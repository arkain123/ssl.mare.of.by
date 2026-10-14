"""
Universal certificate format converter.

Parses PEM, DER, PFX/P12, PKCS#7, and base64-encoded inputs into a normalized
Bundle, then serializes the Bundle into any supported output format.
"""

import base64
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.primitives.serialization import pkcs12

try:
    from cryptography.hazmat.primitives.serialization import pkcs7
    HAS_PKCS7 = hasattr(pkcs7, "load_der_pkcs7_certificates")
except ImportError:
    pkcs7 = None
    HAS_PKCS7 = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------

@dataclass
class Bundle:
    private_key: Optional[object] = None
    certificate: Optional[x509.Certificate] = None
    chain: list = field(default_factory=list)
    csr: Optional[x509.CertificateSigningRequest] = None
    public_key: Optional[object] = None
    source_format: str = "unknown"
    warnings: list = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not any([self.private_key, self.certificate, self.chain,
                        self.csr, self.public_key])


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

_PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+?)-----\s*(.*?)\s*-----END \1-----",
    re.DOTALL,
)
_BASE64_RE = re.compile(rb"^[A-Za-z0-9+/=\s]+$")


def _looks_like_der(data: bytes) -> bool:
    return bool(data) and data[0] == 0x30


def _looks_like_base64(data: bytes) -> bool:
    if not data:
        return False
    stripped = b"".join(data.split())
    if not stripped or not _BASE64_RE.match(stripped):
        return False
    try:
        decoded = base64.b64decode(stripped + b"=" * (-len(stripped) % 4))
        return _looks_like_der(decoded)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_pem_into(raw: bytes, password: str, bundle: Bundle) -> bool:
    found_any = False
    for m in _PEM_BLOCK_RE.finditer(raw):
        label = m.group(1).decode("ascii", "replace").strip()
        body = m.group(2)
        block_pem = (
            b"-----BEGIN " + label.encode("ascii", "replace") + b"-----\n"
            + body + b"\n"
            + b"-----END " + label.encode("ascii", "replace") + b"-----\n"
        )
        try:
            _dispatch_pem_block(label, block_pem, body, password, bundle)
            found_any = True
        except Exception as e:
            bundle.warnings.append(f"{label}: {e}")

    if found_any and bundle.source_format == "unknown":
        bundle.source_format = "pem"
    return found_any


def _dispatch_pem_block(label, block_pem, body, password, bundle):
    if label == "CERTIFICATE":
        cert = x509.load_pem_x509_certificate(block_pem)
        if bundle.certificate is None:
            bundle.certificate = cert
        else:
            bundle.chain.append(cert)

    elif label in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"):
        bundle.private_key = serialization.load_pem_private_key(block_pem, password=None)

    elif label == "ENCRYPTED PRIVATE KEY":
        pw = password.encode() if password else None
        bundle.private_key = serialization.load_pem_private_key(block_pem, password=pw)

    elif label in ("PKCS12", "PFX", "ENCRYPTED PFX"):
        der = base64.b64decode(b"".join(body.split()))
        key, cert, extra = pkcs12.load_key_and_certificates(
            der, password.encode() if password else None
        )
        if key:
            bundle.private_key = key
        if cert:
            bundle.certificate = cert
        if extra:
            bundle.chain.extend(extra)
        bundle.source_format = "pkcs12"

    elif label == "PKCS7":
        if not HAS_PKCS7:
            raise ValueError("PKCS#7 parsing requires cryptography >= 42.0")
        certs = pkcs7.load_pem_pkcs7_certificates(block_pem)
        if certs:
            if bundle.certificate is None:
                bundle.certificate = certs[0]
                bundle.chain.extend(certs[1:])
            else:
                bundle.chain.extend(certs)
        bundle.source_format = bundle.source_format if bundle.source_format != "unknown" else "pkcs7"

    elif label == "CERTIFICATE REQUEST":
        bundle.csr = x509.load_pem_x509_csr(block_pem)

    elif label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
        bundle.public_key = serialization.load_pem_public_key(block_pem)

    else:
        raise ValueError(f"Unknown PEM label: {label!r}")


def _parse_der_into(raw: bytes, password: str, bundle: Bundle) -> bool:
    pw = password.encode() if password else None

    # PFX / PKCS#12
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(raw, pw)
        if key or cert:
            bundle.private_key = key
            bundle.certificate = cert
            bundle.chain = list(extra or [])
            bundle.source_format = "pkcs12"
            return True
    except Exception:
        pass

    # PKCS#7 / P7B
    if HAS_PKCS7:
        try:
            certs = pkcs7.load_der_pkcs7_certificates(raw)
            if certs:
                bundle.certificate = certs[0]
                bundle.chain = list(certs[1:])
                bundle.source_format = "pkcs7"
                return True
        except Exception:
            pass

    # Single certificate
    try:
        bundle.certificate = x509.load_der_x509_certificate(raw)
        bundle.source_format = "der-cert"
        return True
    except Exception:
        pass

    # Private key
    try:
        bundle.private_key = serialization.load_der_private_key(raw, password=pw)
        bundle.source_format = "der-key"
        return True
    except Exception:
        pass

    # CSR
    try:
        bundle.csr = x509.load_der_x509_csr(raw)
        bundle.source_format = "der-csr"
        return True
    except Exception:
        pass

    # Public key
    try:
        bundle.public_key = serialization.load_der_public_key(raw)
        bundle.source_format = "der-pubkey"
        return True
    except Exception:
        pass

    return False


def parse_anything(raw, password: str = "") -> Bundle:
    """Auto-detect and parse any supported certificate-like input."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    if not raw:
        raise ValueError("Empty input")

    raw = raw.strip()
    bundle = Bundle()

    # PEM?
    if b"-----BEGIN " in raw:
        _parse_pem_into(raw, password, bundle)
        if bundle.empty and not bundle.warnings:
            raise ValueError("No usable PEM blocks found")
        return bundle

    # Base64-encoded binary?
    if _looks_like_base64(raw):
        try:
            stripped = b"".join(raw.split())
            decoded = base64.b64decode(stripped + b"=" * (-len(stripped) % 4))
            if _parse_der_into(decoded, password, bundle):
                bundle.source_format = "base64:" + bundle.source_format
                return bundle
        except Exception as e:
            logger.warning("base64 decode attempt failed: %s", e)

    # Plain DER?
    if _looks_like_der(raw):
        if _parse_der_into(raw, password, bundle):
            return bundle

    if bundle.empty:
        raise ValueError(
            "Unrecognized format - not PEM, DER, PFX, PKCS#7, or base64"
        )
    return bundle


# ---------------------------------------------------------------------------
# Bundle summary (for /inspect)
# ---------------------------------------------------------------------------

def _key_info(key) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"ECDSA {key.curve.name}"
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PrivateKey):
        return "Ed448"
    return type(key).__name__


def _cert_summary(cert) -> dict:
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before
        na = cert.not_valid_after

    def _cn(name):
        attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else name.rfc4514_string()

    domains = set()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        domains.update(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass

    return {
        "subject": cert.subject.rfc4514_string(),
        "subject_cn": _cn(cert.subject),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_cn": _cn(cert.issuer),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "domains": sorted(domains),
        "serial": format(cert.serial_number, "x"),
    }


def bundle_summary(bundle: Bundle) -> dict:
    s = {
        "source_format": bundle.source_format,
        "warnings": list(bundle.warnings),
        "has_private_key": bundle.private_key is not None,
        "has_certificate": bundle.certificate is not None,
        "has_csr": bundle.csr is not None,
        "has_public_key": bundle.public_key is not None,
        "chain_length": len(bundle.chain),
    }
    if bundle.private_key:
        s["key_type"] = _key_info(bundle.private_key)
    if bundle.certificate:
        s["certificate"] = _cert_summary(bundle.certificate)
    if bundle.chain:
        s["chain"] = [_cert_summary(c) for c in bundle.chain]
    return s


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------

def _pubkey_of(bundle: Bundle):
    if bundle.public_key is not None:
        return bundle.public_key
    if bundle.certificate is not None:
        return bundle.certificate.public_key()
    return None


def _pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key, fmt=serialization.PrivateFormat.PKCS8) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=fmt,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_bundle(bundle: Bundle, target: str,
                     output_password: str = "") -> dict:
    """
    Serialize `bundle` into `target` format.

    Returns a dict {filename: bytes}. Raises ValueError if required
    components are missing.
    """
    outputs = {}

    if target == "pem-separate":
        if bundle.certificate:
            outputs["certificate.crt"] = _pem_cert(bundle.certificate)
        if bundle.chain:
            outputs["chain.crt"] = b"".join(_pem_cert(c) for c in bundle.chain)
        if bundle.private_key:
            outputs["private.key"] = _pem_key(bundle.private_key)

    elif target == "pem-fullchain":
        if not bundle.certificate:
            raise ValueError("fullchain requires a certificate")
        parts = [_pem_cert(bundle.certificate)]
        parts.extend(_pem_cert(c) for c in bundle.chain)
        outputs["fullchain.pem"] = b"".join(parts)
        if bundle.private_key:
            outputs["privkey.pem"] = _pem_key(bundle.private_key)

    elif target == "pem-bundle":
        parts = []
        if bundle.certificate:
            parts.append(_pem_cert(bundle.certificate))
        parts.extend(_pem_cert(c) for c in bundle.chain)
        if bundle.private_key:
            parts.append(_pem_key(bundle.private_key))
        if not parts:
            raise ValueError("Nothing to bundle")
        outputs["bundle.pem"] = b"".join(parts)

    elif target == "pem-cert-chain":
        if not bundle.certificate:
            raise ValueError("cert+chain requires a certificate")
        parts = [_pem_cert(bundle.certificate)]
        parts.extend(_pem_cert(c) for c in bundle.chain)
        outputs["fullchain.pem"] = b"".join(parts)

    elif target == "der":
        if not bundle.certificate:
            raise ValueError("DER output requires a certificate")
        outputs["certificate.der"] = bundle.certificate.public_bytes(
            serialization.Encoding.DER
        )

    elif target == "pkcs7":
        if not HAS_PKCS7:
            raise ValueError("PKCS#7 support requires cryptography >= 42.0")
        if not bundle.certificate:
            raise ValueError("PKCS#7 output requires a certificate")
        certs = [bundle.certificate] + list(bundle.chain)
        outputs["certificate.p7b"] = pkcs7.serialize_certificates(
            certs, serialization.Encoding.DER
        )

    elif target == "pkcs7-pem":
        if not HAS_PKCS7:
            raise ValueError("PKCS#7 support requires cryptography >= 42.0")
        if not bundle.certificate:
            raise ValueError("PKCS#7 output requires a certificate")
        certs = [bundle.certificate] + list(bundle.chain)
        outputs["certificate.p7b.pem"] = pkcs7.serialize_certificates(
            certs, serialization.Encoding.PEM
        )

    elif target == "pfx":
        if not bundle.private_key:
            raise ValueError("PFX requires a private key")
        if not bundle.certificate:
            raise ValueError("PFX requires a certificate")
        pw = output_password.encode() if output_password else None
        enc = (serialization.BestAvailableEncryption(pw)
               if pw else serialization.NoEncryption())
        pfx = pkcs12.serialize_key_and_certificates(
            name=None,
            key=bundle.private_key,
            cert=bundle.certificate,
            cas=list(bundle.chain) if bundle.chain else None,
            encryption_algorithm=enc,
        )
        outputs["certificate.pfx"] = pfx

    elif target == "pfx-b64":
        if not bundle.private_key:
            raise ValueError("PFX requires a private key")
        if not bundle.certificate:
            raise ValueError("PFX requires a certificate")
        pw = output_password.encode() if output_password else None
        enc = (serialization.BestAvailableEncryption(pw)
               if pw else serialization.NoEncryption())
        pfx = pkcs12.serialize_key_and_certificates(
            name=None,
            key=bundle.private_key,
            cert=bundle.certificate,
            cas=list(bundle.chain) if bundle.chain else None,
            encryption_algorithm=enc,
        )
        b64 = base64.b64encode(pfx).decode("ascii")
        wrapped = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
        outputs["certificate.pfx.txt"] = (wrapped + "\n").encode("ascii")

    elif target == "pubkey-pem":
        pub = _pubkey_of(bundle)
        if pub is None:
            raise ValueError("No public key available")
        outputs["public.key"] = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    elif target == "pubkey-openssh":
        pub = _pubkey_of(bundle)
        if pub is None:
            raise ValueError("No public key available")
        try:
            outputs["public.key"] = pub.public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH,
            )
        except Exception as e:
            raise ValueError(f"OpenSSH format not supported for this key type: {e}")

    elif target == "key-pkcs1":
        if not bundle.private_key:
            raise ValueError("No private key available")
        if not isinstance(bundle.private_key, rsa.RSAPrivateKey):
            raise ValueError("PKCS#1 format is only available for RSA keys")
        outputs["private.key"] = _pem_key(
            bundle.private_key, serialization.PrivateFormat.TraditionalOpenSSL
        )

    else:
        raise ValueError(f"Unknown target format: {target!r}")

    if not outputs:
        raise ValueError(
            "Nothing to output - bundle does not contain required components"
        )

    return outputs
