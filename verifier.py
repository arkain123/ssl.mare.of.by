import logging
import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


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
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    pos = 0
    while True:
        s = pem_text.find(begin, pos)
        if s == -1:
            break
        e = pem_text.find(end, s)
        if e == -1:
            break
        e += len(end)
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
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "domains": sorted(domains),
        "serial": format(cert.serial_number, "x"),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "is_ca": _is_ca(cert),
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
    links = []
    nodes = [{
        "label": "Leaf",
        "name": result["certificate"]["subject_cn"],
        "ok": not (result["certificate"]["expired"] or result["certificate"]["not_yet_valid"]),
    }]

    if chain_certs:
        ok = _verify_issued_by(leaf, chain_certs[0])
        links.append({
            "from": _short_name(leaf.subject),
            "to": _short_name(chain_certs[0].subject),
            "verified": ok,
        })
        if not ok:
            errors.append(f"Leaf is not signed by {_short_name(chain_certs[0].subject)}")

        for i in range(len(chain_certs) - 1):
            child = chain_certs[i]
            issuer = chain_certs[i + 1]
            ok = _verify_issued_by(child, issuer)
            links.append({
                "from": _short_name(child.subject),
                "to": _short_name(issuer.subject),
                "verified": ok,
            })
            if not ok:
                errors.append(
                    f"{_short_name(child.subject)} is not signed by {_short_name(issuer.subject)}"
                )

        for i, c in enumerate(chain_certs):
            is_last = i == len(chain_certs) - 1
            is_self = c.subject == c.issuer
            if is_last:
                label = "Root" if is_self else "Intermediate"
            else:
                label = "Intermediate"
            nodes.append({
                "label": label,
                "name": _short_name(c.subject),
                "ok": all(l["verified"] for l in links[:i + 1]),
            })

        last = chain_certs[-1]
        result["chain"] = {
            "length": len(chain_certs),
            "links": links,
            "nodes": nodes,
            "certificates": [
                {
                    "subject": _short_name(c.subject),
                    "issuer": _short_name(c.issuer),
                    "is_ca": _is_ca(c),
                    "self_signed": c.subject == c.issuer,
                }
                for c in chain_certs
            ],
            "root": {
                "subject": _short_name(last.subject),
                "self_signed": last.subject == last.issuer,
            },
            "complete": last.subject == last.issuer,
            "has_self_signed_root": last.subject == last.issuer,
        }
    else:
        warnings.append("No intermediate chain provided - signature chain not verified")
        result["chain"] = {
            "length": 0,
            "links": [],
            "nodes": nodes,
            "certificates": [],
            "root": None,
            "complete": False,
            "has_self_signed_root": False,
        }

    result["chain"]["valid"] = (
        len(result["chain"]["links"]) > 0
        and all(l["verified"] for l in result["chain"]["links"])
    )
    result["success"] = len(errors) == 0
    return result


def fetch_remote_certificate(hostname, port=443, timeout=10):
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
