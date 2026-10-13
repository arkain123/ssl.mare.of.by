import base64
import logging
import re
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

logger = logging.getLogger(__name__)

_B64_RE = re.compile(rb"^[A-Za-z0-9+/=\s]+$")
_PEM_PFX_RE = re.compile(
    rb"-----BEGIN\s+(?:PKCS12|PFX|ENCRYPTED\s+PFX)-----(.*?)"
    rb"-----END\s+(?:PKCS12|PFX|ENCRYPTED\s+PFX)-----",
    re.DOTALL | re.IGNORECASE,
)


def _looks_like_der(data: bytes) -> bool:
    # ASN.1 SEQUENCE — 0x30 — обязателен для любого PKCS#12
    return bool(data) and data[0] == 0x30


def _strip_pem_pfx_wrapper(data: bytes) -> bytes | None:
    m = _PEM_PFX_RE.search(data)
    if m:
        return m.group(1)
    return None


def normalize_pfx_bytes(data: bytes) -> bytes:
    """
    Accepts:
      * binary DER PFX (starts with 0x30)
      * raw base64 text (single long line, or with newlines)
      * PEM-like wrapper: -----BEGIN PKCS12----- ... -----END PKCS12-----
    Returns binary DER bytes.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")

    # 1) Already binary DER?
    if _looks_like_der(data):
        return data

    # 2) PEM-style wrapper with PKCS12/PFX header?
    inner = _strip_pem_pfx_wrapper(data)
    if inner is not None:
        data = inner

    # 3) Try base64 (whitespace-tolerant, padding-tolerant)
    stripped = b"".join(data.split())
    if stripped and _B64_RE.match(stripped):
        padded = stripped
        if len(padded) % 4:
            padded += b"=" * (4 - len(padded) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
            if _looks_like_der(decoded):
                logger.info("[pfx] decoded base64 text -> %d DER bytes", len(decoded))
                return decoded
        except Exception as e:
            logger.warning("[pfx] base64 decode attempt failed: %s", e)

    # Give up — return original, let pkcs12 raise a meaningful error
    return data


def pfx_to_pem(pfx_data: bytes, password: str) -> dict:
    """Extract private key, leaf cert and CA chain from a PFX/P12 blob."""
    pfx_data = normalize_pfx_bytes(pfx_data)
    pass_bytes = password.encode("utf-8") if password else b""

    try:
        key, cert, extra_certs = pkcs12.load_key_and_certificates(pfx_data, pass_bytes)
    except Exception as e:
        raise ValueError(f"Cannot decode PFX (wrong password or corrupt file): {e}")

    if key is None and cert is None:
        raise ValueError("PFX contains neither a private key nor a certificate")

    result = {"private_key": "", "certificate": "", "chain": ""}

    if key is not None:
        result["private_key"] = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    if cert is not None:
        result["certificate"] = cert.public_bytes(
            serialization.Encoding.PEM
        ).decode("utf-8")

    if extra_certs:
        result["chain"] = "".join(
            c.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            for c in extra_certs
        )

    return result


def _load_private_key(key_pem: str):
    data = key_pem.encode() if isinstance(key_pem, str) else key_pem
    if not data.strip():
        raise ValueError("Private key is empty")
    try:
        return serialization.load_pem_private_key(data, password=None)
    except Exception as e:
        raise ValueError(
            f"Cannot parse private key (encrypted PKCS#8 is not supported yet): {e}"
        )


def _load_certs(pem_text) -> list:
    if not pem_text:
        return []
    data = pem_text.encode() if isinstance(pem_text, str) else pem_text
    certs = []
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    pos = 0
    while True:
        s = data.find(begin, pos)
        if s == -1:
            break
        e = data.find(end, s)
        if e == -1:
            break
        e += len(end)
        block = data[s:e]
        try:
            certs.append(x509.load_pem_x509_certificate(block))
        except Exception as ex:
            raise ValueError(f"Cannot parse certificate block: {ex}")
        pos = e
    return certs


def pem_to_pfx(key_pem: str, cert_pem: str, chain_pem: str, password: str) -> bytes:
    """Pack PEM key + leaf + optional chain into a PFX/P12 blob."""
    key = _load_private_key(key_pem)

    leaf_certs = _load_certs(cert_pem)
    if not leaf_certs:
        raise ValueError("No certificate found in certificate input")
    leaf = leaf_certs[0]

    cas = leaf_certs[1:]
    cas.extend(_load_certs(chain_pem))

    pass_bytes = password.encode("utf-8") if password else None
    encryption = (
        serialization.BestAvailableEncryption(pass_bytes)
        if pass_bytes is not None
        else serialization.NoEncryption()
    )

    try:
        return pkcs12.serialize_key_and_certificates(
            name=None,
            key=key,
            cert=leaf,
            cas=cas if cas else None,
            encryption_algorithm=encryption,
        )
    except Exception as e:
        raise ValueError(f"Cannot encode PFX: {e}")
