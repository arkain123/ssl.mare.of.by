import base64
import logging
import os
import re
import socket
import ssl
import urllib.request
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding

try:
    import certifi
    HAS_CERTIFI = True
except ImportError:
    HAS_CERTIFI = False

logger = logging.getLogger(__name__)


def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
PEM_END = "-----END CERTIFICATE-----"

MAX_CHAIN_DEPTH = _env_int("CHAIN_MAX_DEPTH", 10)
AIA_TIMEOUT = _env_int("AIA_FETCH_TIMEOUT", 10)
USER_AGENT = os.getenv("AIA_USER_AGENT", "SSL-Tools-Chain-Builder/1.0")
CERT_EXPIRY_WARN_DAYS = _env_int("CERT_EXPIRY_WARN_DAYS", 14)
LIVE_CHECK_TIMEOUT = _env_int("LIVE_CHECK_TIMEOUT", 10)

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _cert_item_to_pem(item):
    if isinstance(item, (bytes, bytearray)):
        data = bytes(item)
        if data.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
            return data.decode("utf-8", errors="replace")
        try:
            return ssl.DER_cert_to_PEM_cert(data)
        except Exception as e:
            logger.warning("[live] cannot convert DER to PEM: %s", e)
            return None
    if hasattr(item, "public_bytes"):
        try:
            return item.public_bytes(ssl.ENCODING_PEM).decode()
        except Exception as e:
            logger.warning("[live] public_bytes failed: %s", e)
            return None
    logger.warning("[live] unknown chain item type: %r", type(item))
    return None


def _load_certs(pem_text):
    certs = []
    pos = 0
    while True:
        s = pem_text.find(PEM_BEGIN, pos)
        if s == -1:
            break
        e = pem_text.find(PEM_END, s)
        if e == -1:
            break
        e += len(PEM_END)
        block = pem_text[s:e].encode()
        try:
            certs.append(x509.load_pem_x509_certificate(block))
        except Exception as ex:
            logger.warning("[verify] failed to parse cert block: %s", ex)
        pos = e
    return certs


def _short_name(dn):
    for attr in dn.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        return attr.value
    return dn.rfc4514_string()


def _is_ca(cert):
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bc.value.ca
    except x509.ExtensionNotFound:
        return False


def _find_chain_path(leaf, chain_certs, max_depth=15):
    leaf_fp = leaf.fingerprint(hashes.SHA256())
    unique = []
    seen = {leaf_fp}
    for c in chain_certs:
        fp = c.fingerprint(hashes.SHA256())
        if fp in seen:
            continue
        seen.add(fp)
        unique.append(c)

    def _dfs(current, remaining, path, depth):
        if depth >= max_depth:
            return list(path)
        if current.subject == current.issuer:
            return list(path)

        best = list(path)
        for i, cand in enumerate(remaining):
            if cand.subject != current.issuer:
                continue
            if not _verify_issued_by(current, cand):
                continue
            path.append(cand)
            result = _dfs(cand, remaining[:i] + remaining[i + 1:], path, depth + 1)
            if len(result) > len(best):
                best = result
            path.pop()

        return best

    ordered = _dfs(leaf, unique, [], 0)

    links = []
    prev = leaf
    for curr in ordered:
        links.append({
            "from": _short_name(prev.subject),
            "to": _short_name(curr.subject),
            "verified": _verify_issued_by(prev, curr),
        })
        prev = curr

    ordered_fps = {c.fingerprint(hashes.SHA256()) for c in ordered}
    unused = [c for c in unique if c.fingerprint(hashes.SHA256()) not in ordered_fps]
    complete = bool(ordered) and ordered[-1].subject == ordered[-1].issuer

    return ordered, links, unused, complete


def _is_self_signed(cert):
    """True iff subject == issuer AND the signature verifies with its own key."""
    if cert.subject != cert.issuer:
        return False
    return _verify_issued_by(cert, cert)


def _verify_issued_by(child, issuer):
    if hasattr(child, "verify_directly_issued_by"):
        try:
            child.verify_directly_issued_by(issuer)
            return True
        except Exception:
            return False
    try:
        pub = issuer.public_key()
        sig = child.signature
        data = child.tbs_certificate_bytes
        algo = child.signature_hash_algorithm
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, data, padding.PKCS1v15(), algo)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(algo))
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def _cert_info(cert):
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    domains = set()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san.value.get_values_for_type(x509.DNSName):
            domains.add(name)
    except x509.ExtensionNotFound:
        pass
    for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        domains.add(attr.value)

    return {
        "subject": cert.subject.rfc4514_string(),
        "subject_cn": _short_name(cert.subject),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_cn": _short_name(cert.issuer),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "warn_threshold_days": CERT_EXPIRY_WARN_DAYS,
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "domains": sorted(domains),
        "serial": format(cert.serial_number, "x"),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "is_ca": _is_ca(cert),
        "self_signed": _is_self_signed(cert),
    }


def _key_info(key_obj):
    if isinstance(key_obj, rsa.RSAPrivateKey):
        return f"RSA {key_obj.key_size}"
    if isinstance(key_obj, ec.EllipticCurvePrivateKey):
        return f"ECDSA {key_obj.curve.name}"
    return type(key_obj).__name__


def _key_matches_cert(key_obj, cert):
    try:
        a = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        b = key_obj.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return a == b
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API: verify user-provided bundle
# ---------------------------------------------------------------------------

def verify_inputs(cert_pem, chain_pem, key_pem):
    errors, warnings = [], []
    try:
        leaf = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception as e:
        return {
            "success": False,
            "errors": [f"Cannot parse certificate: {e}"],
            "warnings": [],
        }

    result = {
        "success": True,
        "certificate": _cert_info(leaf),
        "errors": errors,
        "warnings": warnings,
    }

    if result["certificate"]["expired"]:
        errors.append("Certificate is expired")
    if result["certificate"]["not_yet_valid"]:
        errors.append("Certificate is not yet valid")

    # --- Private key ---
    if key_pem and key_pem.strip():
        try:
            key_obj = serialization.load_pem_private_key(key_pem.encode(), password=None)
            matches = _key_matches_cert(key_obj, leaf)
            result["key"] = {
                "type": _key_info(key_obj),
                "matches_certificate": matches,
            }
            if not matches:
                errors.append("Private key does not match the certificate")
        except Exception as e:
            result["key"] = {"error": str(e)}
            errors.append(f"Cannot parse private key: {e}")

    # --- Chain ---
    chain_certs = _load_certs(chain_pem) if chain_pem and chain_pem.strip() else []

    if chain_certs:
        ordered, links, unused, complete = _find_chain_path(leaf, chain_certs)

        if ordered:
            nodes = [{
                "label": "Leaf",
                "name": result["certificate"]["subject_cn"],
                "ok": not (result["certificate"]["expired"] or result["certificate"]["not_yet_valid"]),
            }]
            for i, (c, link) in enumerate(zip(ordered, links)):
                is_last = i == len(ordered) - 1
                is_self = c.subject == c.issuer
                label = "Root" if (is_last and is_self) else "Intermediate"
                nodes.append({
                    "label": label,
                    "name": _short_name(c.subject),
                    "ok": link["verified"],
                })

            result["chain"] = {
                "length": len(ordered),
                "links": links,
                "nodes": nodes,
                "certificates": [
                    {
                        "subject": _short_name(c.subject),
                        "issuer": _short_name(c.issuer),
                        "is_ca": _is_ca(c),
                        "self_signed": c.subject == c.issuer,
                    }
                    for c in ordered
                ],
                "root": {
                    "subject": _short_name(ordered[-1].subject),
                    "self_signed": complete,
                },
                "complete": complete,
                "has_self_signed_root": complete,
                "extra_count": len(unused),
                "provided_count": len(chain_certs),
            }

            for i, link in enumerate(links):
                if not link["verified"]:
                    if i == 0:
                        errors.append(f"Leaf is not signed by {link['to']}")
                    else:
                        errors.append(f"{link['from']} is not signed by {link['to']}")

            if unused:
                warnings.append(
                    f"{len(unused)} extra certificate(s) provided but not part of the "
                    "main chain (normal when including cross-signed variants for "
                    "browser compatibility)"
                )

            if not complete:
                warnings.append(
                    "Chain does not reach a self-signed root - normal for cross-signed "
                    "intermediates; browsers may extend it via the OS trust store"
                )
        else:
            errors.append(
                f"None of the {len(chain_certs)} provided certificate(s) issued the leaf"
            )
            result["chain"] = {
                "length": 0,
                "links": [],
                "nodes": [{
                    "label": "Leaf",
                    "name": result["certificate"]["subject_cn"],
                    "ok": True,
                }],
                "certificates": [],
                "root": None,
                "complete": False,
                "has_self_signed_root": False,
                "extra_count": 0,
                "provided_count": len(chain_certs),
            }
    else:
        warnings.append("No intermediate chain provided - signature chain not verified")
        result["chain"] = {
            "length": 0,
            "links": [],
            "nodes": [{
                "label": "Leaf",
                "name": result["certificate"]["subject_cn"],
                "ok": True,
            }],
            "certificates": [],
            "root": None,
            "complete": False,
            "has_self_signed_root": False,
            "extra_count": 0,
            "provided_count": 0,
        }

    result["chain"]["valid"] = (
        len(result["chain"]["links"]) > 0
        and all(l["verified"] for l in result["chain"]["links"])
    )
    result["success"] = len(errors) == 0
    return result


# ---------------------------------------------------------------------------
# Chain building: AIA chasing + local CA store fallback
# ---------------------------------------------------------------------------

def _aia_ca_issuers_url(cert):
    """Extract the first CA Issuers URL from the AIA extension."""
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        return None

    for access_description in aia.value:
        if access_description.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
            loc = access_description.access_location
            if isinstance(loc, x509.UniformResourceIdentifier):
                return loc.value
    return None


def _fetch_cert_from_url(url):
    """Download a certificate (PEM or DER) from a URL."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=AIA_TIMEOUT) as resp:
        body = resp.read()

    # Try PEM first
    if b"-----BEGIN CERTIFICATE-----" in body:
        certs = _load_certs(body.decode("utf-8", errors="replace"))
        if certs:
            return certs[0]

    # Try DER
    try:
        return x509.load_der_x509_certificate(body)
    except Exception:
        pass

    # Try base64-wrapped DER
    try:
        text = body.decode("ascii", errors="ignore")
        stripped = "".join(text.split())
        der = base64.b64decode(stripped)
        return x509.load_der_x509_certificate(der)
    except Exception:
        pass

    return None


def _load_system_ca_store():
    """Load CA certificates from certifi or the system default store."""
    paths = []

    if HAS_CERTIFI:
        try:
            paths.append(certifi.where())
        except Exception:
            pass

    # Fallback to system openssl default paths
    try:
        defaults = ssl.get_default_verify_paths()
        for p in (defaults.cafile, defaults.openssl_cafile):
            if p:
                paths.append(p)
    except Exception:
        pass

    paths.extend([
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/ca-bundle.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/usr/local/ssl/certs/ca-bundle.crt",
    ])

    certs = []
    seen = set()
    for path in dict.fromkeys(paths):  # deduplicate while preserving order
        if not path:
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            continue
        for cert in _load_certs(content):
            fp = cert.fingerprint(hashes.SHA256())
            if fp in seen:
                continue
            seen.add(fp)
            certs.append(cert)

    logger.info("[chain] loaded %d CA certificate(s) from local store", len(certs))
    return certs


def _find_issuer_in_store(child, store):
    candidates = [c for c in store if c.subject == child.issuer]
    if not candidates:
        return None

    candidates.sort(key=lambda c: 0 if c.subject == c.issuer else 1)

    for candidate in candidates:
        if _verify_issued_by(child, candidate):
            return candidate
    return None


def _cert_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def build_certificate_chain(cert_pem, include_root=False):
    errors = []
    warnings = []

    try:
        leaf = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception as e:
        return {
            "success": False,
            "chain": [],
            "errors": [f"Cannot parse certificate: {e}"],
            "warnings": [],
            "found_root": False,
            "root_included": False,
            "excluded_root": None,
            "complete": False,
        }

    store = _load_system_ca_store()

    chain = [{
        "cert": leaf,
        "pem": cert_pem.strip() + "\n",
        "source": "input",
    }]
    current = leaf
    seen_serials = {leaf.serial_number}

    for _ in range(MAX_CHAIN_DEPTH):
        if current.subject == current.issuer:
            break

        issuer = None
        source = None

        aia_url = _aia_ca_issuers_url(current)
        if aia_url:
            try:
                issuer = _fetch_cert_from_url(aia_url)
                if issuer is not None:
                    source = "aia"
            except Exception as e:
                logger.warning("[chain] AIA fetch failed for %s: %s", aia_url, e)
                warnings.append(f"AIA download failed for {aia_url}: {e}")

        if issuer is None:
            issuer = _find_issuer_in_store(current, store)
            if issuer is not None:
                source = "local_store"

        if issuer is None:
            errors.append(
                f"Could not find issuer for {_short_name(current.subject)} "
                f"({_short_name(current.issuer)})"
            )
            break

        if issuer.serial_number in seen_serials:
            warnings.append(
                f"Loop detected: {_short_name(issuer.subject)} already in chain"
            )
            break
        seen_serials.add(issuer.serial_number)

        chain.append({
            "cert": issuer,
            "pem": _cert_to_pem(issuer),
            "source": source,
        })
        current = issuer
    else:
        errors.append(f"Maximum chain depth ({MAX_CHAIN_DEPTH}) reached")

    found_root = bool(chain) and _is_self_signed(chain[-1]["cert"])

    excluded_root = None
    if found_root and not include_root and len(chain) > 1:
        dropped = chain.pop()
        dropped_info = _cert_info(dropped["cert"])
        excluded_root = {
            "subject": dropped_info["subject_cn"],
            "not_after": dropped_info["not_after"],
        }

    # Assign types on the final list.
    for i, item in enumerate(chain):
        is_self = _is_self_signed(item["cert"])
        if i == 0:
            item["type"] = "leaf"
        elif is_self:
            item["type"] = "root"
        else:
            item["type"] = "intermediate"

    # Warn if the last item is a "root-looking" intermediate.
    if chain:
        last_name = _short_name(chain[-1]["cert"].subject)
        if (chain[-1]["type"] == "intermediate"
                and last_name.lower().startswith(("root ", "root-", "root_"))):
            warnings.append(
                f"'{last_name}' is an intermediate, not a self-signed root "
                f"(its issuer is not in the local CA store). It is kept in the "
                f"chain because it is needed to reach the real root."
            )

    result_chain = []
    for item in chain:
        info = _cert_info(item["cert"])
        result_chain.append({
            "pem": item["pem"],
            "info": info,
            "type": item["type"],
            "source": item["source"],
            "self_signed": info["self_signed"],
        })

    root_included = found_root and include_root

    return {
        "success": len(result_chain) > 0,
        "chain": result_chain,
        "errors": errors,
        "warnings": warnings,
        "found_root": found_root,
        "root_included": root_included,
        "excluded_root": excluded_root,
        "complete": found_root,
    }


# ---------------------------------------------------------------------------
# Live certificate fetching
# ---------------------------------------------------------------------------

def fetch_remote_certificate(hostname, port=443, timeout=LIVE_CHECK_TIMEOUT):
    logger.info("[live] connecting to %s:%d", hostname, port)
    chain_pem_list = []
    tls_version = None
    cipher_info = None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cipher_info = ssock.cipher()
                if hasattr(ssock, "get_unverified_chain"):
                    for item in ssock.get_unverified_chain():
                        pem = _cert_item_to_pem(item)
                        if pem:
                            chain_pem_list.append(pem)
                else:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        chain_pem_list.append(ssl.DER_cert_to_PEM_cert(der))
    except Exception as e:
        logger.warning("[live] fetch failed: %s", e)
        return {
            "ok": False,
            "connect_error": str(e),
            "hostname": hostname,
            "port": port,
        }

    verify_ok = False
    verify_error = None
    try:
        ctx2 = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx2.wrap_socket(sock, server_hostname=hostname):
                pass
        verify_ok = True
        logger.info("[live] chain verified against system CA store")
    except ssl.SSLCertVerificationError as e:
        verify_error = getattr(e, "verify_message", None) or str(e)
        logger.info("[live] verification failed: %s", verify_error)
    except Exception as e:
        verify_error = str(e)
        logger.warning("[live] verification error: %s", e)

    return {
        "ok": True,
        "hostname": hostname,
        "port": port,
        "chain_pem": chain_pem_list,
        "tls_version": tls_version,
        "cipher": {
            "name": cipher_info[0] if cipher_info else None,
            "protocol": cipher_info[1] if cipher_info else None,
            "bits": cipher_info[2] if cipher_info else None,
        } if cipher_info else None,
        "verify_ok": verify_ok,
        "verify_error": verify_error,
    }
