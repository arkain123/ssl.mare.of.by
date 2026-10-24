import base64
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa, ec, ed25519, ed448,
)
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.x509.oid import NameOID

from app import converter as cv


# ==========================================================================
# Crypto material (generated once)
# ==========================================================================
def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _ed25519_key():
    return ed25519.Ed25519PrivateKey.generate()


def _ed448_key():
    return ed448.Ed448PrivateKey.generate()


def _make_cert(key, cn, issuer_key=None, issuer_cn=None,
               san_dns=None, is_ca=False):
    issuer_key = issuer_key or key
    issuer_cn = issuer_cn or cn
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
    )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            critical=False,
        )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
    return builder.sign(issuer_key, hashes.SHA256())


RSA_KEY = _rsa_key()
EC_KEY = _ec_key()
ED25519_KEY = _ed25519_key()
ED448_KEY = _ed448_key()

ROOT_CERT = _make_cert(RSA_KEY, "Root CA", is_ca=True)
LEAF_CERT = _make_cert(
    RSA_KEY, "leaf.example.com",
    issuer_key=RSA_KEY, issuer_cn="Root CA",
    san_dns=["leaf.example.com", "www.example.com"],
)
INT_CERT = _make_cert(
    RSA_KEY, "Intermediate CA",
    issuer_key=RSA_KEY, issuer_cn="Root CA",
    is_ca=True,
)

PEM_LEAF = LEAF_CERT.public_bytes(serialization.Encoding.PEM)
PEM_INT = INT_CERT.public_bytes(serialization.Encoding.PEM)
PEM_ROOT = ROOT_CERT.public_bytes(serialization.Encoding.PEM)
PEM_KEY = RSA_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
DER_CERT = LEAF_CERT.public_bytes(serialization.Encoding.DER)
DER_KEY = RSA_KEY.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)


def _csr(key=RSA_KEY, cn="csr.example.com"):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )


CSR_OBJ = _csr()
PEM_CSR = CSR_OBJ.public_bytes(serialization.Encoding.PEM)
DER_CSR = CSR_OBJ.public_bytes(serialization.Encoding.DER)

PEM_PUBKEY = RSA_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
DER_PUBKEY = RSA_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

PFX_WITH_KEY = pkcs12.serialize_key_and_certificates(
    name=b"test",
    key=RSA_KEY,
    cert=LEAF_CERT,
    cas=[INT_CERT],
    encryption_algorithm=serialization.BestAvailableEncryption(b"secret"),
)
PFX_CERTS_ONLY = pkcs12.serialize_key_and_certificates(
    name=None,
    key=None,
    cert=ROOT_CERT,
    cas=None,
    encryption_algorithm=serialization.NoEncryption(),
)
PEM_P7B = pkcs7.serialize_certificates(
    [LEAF_CERT, INT_CERT], serialization.Encoding.PEM,
)
DER_P7B = pkcs7.serialize_certificates(
    [LEAF_CERT, INT_CERT], serialization.Encoding.DER,
)


# ==========================================================================
# Bundle dataclass
# ==========================================================================
class TestBundle:
    def test_empty_bundle(self):
        assert cv.Bundle().empty is True

    def test_not_empty_with_cert(self):
        b = cv.Bundle(certificate=LEAF_CERT)
        assert b.empty is False

    def test_not_empty_with_key(self):
        b = cv.Bundle(private_key=RSA_KEY)
        assert b.empty is False

    def test_not_empty_with_chain_only(self):
        b = cv.Bundle(chain=[LEAF_CERT])
        assert b.empty is False

    def test_not_empty_with_csr(self):
        b = cv.Bundle(csr=CSR_OBJ)
        assert b.empty is False

    def test_not_empty_with_public_key(self):
        b = cv.Bundle(public_key=RSA_KEY.public_key())
        assert b.empty is False

    def test_defaults(self):
        b = cv.Bundle()
        assert b.chain == []
        assert b.warnings == []
        assert b.source_format == "unknown"


# ==========================================================================
# Detection helpers
# ==========================================================================
class TestLooksLikeDer:
    def test_der_starts_with_0x30(self):
        assert cv._looks_like_der(b"\x30\x82") is True

    def test_not_der(self):
        assert cv._looks_like_der(b"\x00\x01") is False

    def test_empty(self):
        assert cv._looks_like_der(b"") is False


class TestLooksLikeBase64:
    def test_valid_base64_of_der(self):
        b64 = base64.b64encode(DER_CERT)
        assert cv._looks_like_base64(b64) is True

    def test_base64_with_newlines(self):
        b64 = base64.encodebytes(DER_CERT)
        assert cv._looks_like_base64(b64) is True

    def test_empty(self):
        assert cv._looks_like_base64(b"") is False

    def test_garbage(self):
        assert cv._looks_like_base64(b"@@@ not base64 @@@") is False

    def test_valid_base64_not_der(self):
        b64 = base64.b64encode(b"hello world")
        # decodes fine but does not start with 0x30
        assert cv._looks_like_base64(b64) is False

    def test_base64_with_padding_needed(self):
        # length not divisible by 4, padding must be added internally
        raw = DER_CERT
        b64 = base64.b64encode(raw).rstrip(b"=")
        assert cv._looks_like_base64(b64) is True


# ==========================================================================
# PEM parsing
# ==========================================================================
class TestParsePem:
    def test_single_certificate(self):
        b = cv.parse_anything(PEM_LEAF)
        assert b.certificate is not None
        assert b.certificate.subject.rfc4514_string() == LEAF_CERT.subject.rfc4514_string()
        assert b.source_format == "pem"
        assert b.chain == []

    def test_cert_and_chain(self):
        b = cv.parse_anything(PEM_LEAF + PEM_INT)
        assert b.certificate is not None
        assert len(b.chain) == 1
        assert b.chain[0].subject.rfc4514_string() == INT_CERT.subject.rfc4514_string()

    def test_private_key(self):
        b = cv.parse_anything(PEM_KEY)
        assert isinstance(b.private_key, rsa.RSAPrivateKey)
        assert b.source_format == "pem"

    def test_rsa_private_key_label(self):
        # RSA PRIVATE KEY (PKCS#1) label
        pkcs1 = RSA_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        b = cv.parse_anything(pkcs1)
        assert isinstance(b.private_key, rsa.RSAPrivateKey)

    def test_ec_private_key_label(self):
        ec_pem = EC_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        b = cv.parse_anything(ec_pem)
        assert isinstance(b.private_key, ec.EllipticCurvePrivateKey)

    def test_encrypted_private_key_with_password(self):
        enc = RSA_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"pw"),
        )
        b = cv.parse_anything(enc, password="pw")
        assert isinstance(b.private_key, rsa.RSAPrivateKey)

    def test_encrypted_private_key_wrong_password(self):
        enc = RSA_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"pw"),
        )
        b = cv.parse_anything(enc, password="wrong")
        assert b.private_key is None
        assert b.warnings  # warning captured

    def test_csr(self):
        b = cv.parse_anything(PEM_CSR)
        assert b.csr is not None

    def test_public_key(self):
        b = cv.parse_anything(PEM_PUBKEY)
        assert b.public_key is not None

    def test_rsa_public_key_label(self):
        # "RSA PUBLIC KEY" (PKCS#1) label. cryptography rejects PKCS#1
        # public keys on some versions; the parser must capture a warning
        # but not crash.
        pkcs1_pub = RSA_KEY.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )
        b = cv.parse_anything(pkcs1_pub)
        # Either it parsed, or a warning was captured - both are valid
        assert b.public_key is not None or b.warnings

    def test_multiple_certs_no_leaf(self):
        # Two certs: first becomes certificate, second goes to chain
        b = cv.parse_anything(PEM_INT + PEM_LEAF)
        assert b.certificate is not None
        assert len(b.chain) == 1

    def test_unknown_label_captured_as_warning(self):
        raw = (
            b"-----BEGIN FOO-----\nYWJj\n-----END FOO-----\n"
            + PEM_LEAF
        )
        b = cv.parse_anything(raw)
        assert any("FOO" in w for w in b.warnings)
        assert b.certificate is not None

    def test_no_usable_blocks_raises_only_when_no_blocks_at_all(self):
        with pytest.raises(ValueError, match="Unrecognized format"):
            cv.parse_anything(b"----- no markers here -----")

    def test_unknown_label_only_yields_warning(self):
        raw = b"-----BEGIN FOO-----\nYWJj\n-----END FOO-----\n"
        b = cv.parse_anything(raw)
        assert b.empty is True
        assert b.warnings
        assert any("FOO" in w for w in b.warnings)

    def test_no_usable_pem_blocks_branch(self):
        with patch.object(cv, "_parse_pem_into", return_value=False):
            with pytest.raises(ValueError, match="No usable PEM blocks"):
                cv.parse_anything(b"-----BEGIN X-----\nY\n-----END X-----\n")

    def test_pem_block_with_whitespace(self):
        raw = b"  \n" + PEM_LEAF + b"\n  "
        b = cv.parse_anything(raw)
        assert b.certificate is not None

    def test_pkcs12_pem_block(self):
        der_b64 = base64.b64encode(PFX_CERTS_ONLY).decode()
        body = "\n".join(
            der_b64[i:i + 64] for i in range(0, len(der_b64), 64)
        )
        raw = (
            "-----BEGIN PKCS12-----\n"
            + body
            + "\n-----END PKCS12-----\n"
        ).encode()
        b = cv.parse_anything(raw)
        assert b.source_format == "pkcs12"
        # The cert went into the chain
        assert len(b.chain) == 1
        assert b.chain[0].subject.rfc4514_string() == ROOT_CERT.subject.rfc4514_string()

    def test_pkcs12_pem_block_with_key(self):
        der_b64 = base64.b64encode(PFX_WITH_KEY).decode()
        body = "\n".join(
            der_b64[i:i + 64] for i in range(0, len(der_b64), 64)
        )
        raw = (
            "-----BEGIN PKCS12-----\n"
            + body
            + "\n-----END PKCS12-----\n"
        ).encode()
        b = cv.parse_anything(raw, password="secret")
        assert b.source_format == "pkcs12"
        assert b.private_key is not None
        assert b.certificate is not None
        assert len(b.chain) == 1

    def test_pkcs7_pem_block(self):
        b = cv.parse_anything(PEM_P7B)
        assert b.source_format == "pkcs7"
        assert b.certificate is not None
        assert len(b.chain) == 1

    def test_pkcs7_pem_block_with_leading_cert(self):
        raw = PEM_LEAF + PEM_P7B
        b = cv.parse_anything(raw)
        assert b.certificate is not None
        assert b.source_format == "pkcs7"


# ==========================================================================
# DER parsing
# ==========================================================================
class TestParseDer:
    def test_der_certificate(self):
        b = cv.parse_anything(DER_CERT)
        assert b.source_format == "der-cert"
        assert b.certificate is not None

    def test_der_private_key(self):
        b = cv.parse_anything(DER_KEY)
        assert b.source_format == "der-key"
        assert isinstance(b.private_key, rsa.RSAPrivateKey)

    def test_der_csr(self):
        b = cv.parse_anything(DER_CSR)
        assert b.source_format == "der-csr"
        assert b.csr is not None

    def test_der_public_key(self):
        b = cv.parse_anything(DER_PUBKEY)
        assert b.source_format == "der-pubkey"
        assert b.public_key is not None

    def test_der_pkcs12(self):
        b = cv.parse_anything(PFX_WITH_KEY, password="secret")
        assert b.source_format == "pkcs12"
        assert b.private_key is not None
        assert b.certificate is not None
        assert len(b.chain) == 1

    def test_der_pkcs7(self):
        b = cv.parse_anything(DER_P7B)
        assert b.source_format == "pkcs7"
        assert b.certificate is not None
        assert len(b.chain) == 1

    def test_pkcs12_wrong_password(self):
        # Wrong password -> pkcs12 fails, DER cert parse also fails, etc.
        # We expect a ValueError because nothing parses.
        with pytest.raises(ValueError):
            cv.parse_anything(PFX_WITH_KEY, password="wrong")


# ==========================================================================
# Base64 transport parsing
# ==========================================================================
class TestParseBase64:
    def test_base64_der_cert(self):
        raw = base64.b64encode(DER_CERT)
        b = cv.parse_anything(raw)
        assert b.source_format == "base64:der-cert"
        assert b.certificate is not None

    def test_base64_der_key(self):
        raw = base64.b64encode(DER_KEY)
        b = cv.parse_anything(raw)
        assert b.source_format == "base64:der-key"

    def test_base64_with_newlines(self):
        raw = base64.encodebytes(DER_CERT)
        b = cv.parse_anything(raw)
        assert b.certificate is not None

    def test_base64_pkcs12(self):
        raw = base64.b64encode(PFX_WITH_KEY)
        b = cv.parse_anything(raw, password="secret")
        assert b.source_format == "base64:pkcs12"


# ==========================================================================
# parse_anything edge cases
# ==========================================================================
class TestParseAnything:
    def test_empty_input(self):
        with pytest.raises(ValueError, match="Empty input"):
            cv.parse_anything(b"")

    def test_str_input(self):
        b = cv.parse_anything(PEM_LEAF.decode())
        assert b.certificate is not None

    def test_whitespace_only(self):
        with pytest.raises(ValueError):
            cv.parse_anything(b"   \n  ")

    def test_unrecognized(self):
        with pytest.raises(ValueError, match="Unrecognized format"):
            cv.parse_anything(b"this is not a certificate at all!")


# ==========================================================================
# _key_info
# ==========================================================================
class TestKeyInfo:
    def test_rsa(self):
        assert cv._key_info(RSA_KEY).startswith("RSA ")

    def test_ec(self):
        assert cv._key_info(EC_KEY).startswith("ECDSA ")

    def test_ed25519(self):
        assert cv._key_info(ED25519_KEY) == "Ed25519"

    def test_ed448(self):
        assert cv._key_info(ED448_KEY) == "Ed448"

    def test_unknown(self):
        class Weird:
            pass
        assert cv._key_info(Weird()) == "Weird"


# ==========================================================================
# _cert_summary
# ==========================================================================
class TestCertSummary:
    def test_basic_fields(self):
        s = cv._cert_summary(LEAF_CERT)
        assert "CN=leaf.example.com" in s["subject"]
        assert s["subject_cn"] == "leaf.example.com"
        assert "CN=Root CA" in s["issuer"]
        assert s["issuer_cn"] == "Root CA"
        assert isinstance(s["serial"], str)

    def test_domains_from_san(self):
        s = cv._cert_summary(LEAF_CERT)
        assert s["domains"] == ["leaf.example.com", "www.example.com"]

    def test_no_san_returns_empty_list(self):
        s = cv._cert_summary(ROOT_CERT)
        assert s["domains"] == []

    def test_not_before_not_after_iso(self):
        s = cv._cert_summary(LEAF_CERT)
        assert "T" in s["not_before"]
        assert "T" in s["not_after"]

    def test_cn_fallback_to_rfc4514(self):
        # Certificate without CN in subject
        subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org")])
        key = _rsa_key()
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        s = cv._cert_summary(cert)
        # No CN -> falls back to rfc4514_string
        assert "O=Org" in s["subject_cn"]


# ==========================================================================
# bundle_summary
# ==========================================================================
class TestBundleSummary:
    def test_empty_bundle(self):
        s = cv.bundle_summary(cv.Bundle())
        assert s["has_private_key"] is False
        assert s["has_certificate"] is False
        assert s["chain_length"] == 0
        assert s["source_format"] == "unknown"

    def test_with_key(self):
        s = cv.bundle_summary(cv.Bundle(private_key=RSA_KEY))
        assert s["has_private_key"] is True
        assert s["key_type"].startswith("RSA ")

    def test_with_certificate(self):
        s = cv.bundle_summary(cv.Bundle(certificate=LEAF_CERT))
        assert s["has_certificate"] is True
        assert "certificate" in s
        assert s["certificate"]["subject_cn"] == "leaf.example.com"

    def test_with_chain(self):
        s = cv.bundle_summary(cv.Bundle(certificate=LEAF_CERT,
                                        chain=[INT_CERT, ROOT_CERT]))
        assert s["chain_length"] == 2
        assert len(s["chain"]) == 2

    def test_warnings_propagated(self):
        b = cv.Bundle(warnings=["w1", "w2"])
        s = cv.bundle_summary(b)
        assert s["warnings"] == ["w1", "w2"]


# ==========================================================================
# _pubkey_of
# ==========================================================================
class TestPubkeyOf:
    def test_prefers_explicit_public_key(self):
        pub = RSA_KEY.public_key()
        b = cv.Bundle(public_key=pub, certificate=LEAF_CERT)
        assert cv._pubkey_of(b) is pub

    def test_falls_back_to_certificate(self):
        b = cv.Bundle(certificate=LEAF_CERT)
        assert cv._pubkey_of(b) is not None

    def test_none(self):
        assert cv._pubkey_of(cv.Bundle()) is None


# ==========================================================================
# _serialize_pkcs12 and _validate_pkcs12_password
# ==========================================================================
class TestPkcs12Helpers:
    def test_requires_key(self):
        with pytest.raises(ValueError, match="requires a private key"):
            cv._serialize_pkcs12(cv.Bundle(certificate=LEAF_CERT), "pw")

    def test_requires_certificate(self):
        with pytest.raises(ValueError, match="requires a certificate"):
            cv._serialize_pkcs12(cv.Bundle(private_key=RSA_KEY), "pw")

    def test_requires_password(self):
        b = cv.Bundle(private_key=RSA_KEY, certificate=LEAF_CERT)
        with pytest.raises(ValueError, match="requires a password"):
            cv._serialize_pkcs12(b, "")

    def test_produces_bytes(self):
        b = cv.Bundle(private_key=RSA_KEY, certificate=LEAF_CERT)
        out = cv._serialize_pkcs12(b, "pw")
        assert isinstance(out, bytes)
        # PKCS#12 always starts with 0x30
        assert out[0] == 0x30

    def test_validate_empty_password(self):
        with pytest.raises(ValueError, match="requires a password"):
            cv._validate_pkcs12_password("", None)

    def test_validate_mismatch(self):
        with pytest.raises(ValueError, match="does not match"):
            cv._validate_pkcs12_password("a", "b")

    def test_validate_ok_no_confirm(self):
        cv._validate_pkcs12_password("a", None)

    def test_validate_ok_match(self):
        cv._validate_pkcs12_password("a", "a")


# ==========================================================================
# serialize_bundle: PEM targets
# ==========================================================================
class TestSerializePemSeparate:
    def test_cert_only(self):
        out = cv.serialize_bundle(
            cv.Bundle(certificate=LEAF_CERT), "pem-separate")
        assert set(out) == {"certificate.crt"}
        assert b"BEGIN CERTIFICATE" in out["certificate.crt"]

    def test_cert_chain_key(self):
        b = cv.Bundle(private_key=RSA_KEY, certificate=LEAF_CERT,
                      chain=[INT_CERT])
        out = cv.serialize_bundle(b, "pem-separate")
        assert set(out) == {"certificate.crt", "chain.crt", "private.key"}

    def test_chain_only(self):
        out = cv.serialize_bundle(
            cv.Bundle(chain=[INT_CERT]), "pem-separate")
        assert set(out) == {"chain.crt"}

    def test_key_only(self):
        out = cv.serialize_bundle(
            cv.Bundle(private_key=RSA_KEY), "pem-separate")
        assert set(out) == {"private.key"}


class TestSerializePemFullchain:
    def test_requires_certificate(self):
        with pytest.raises(ValueError, match="requires a certificate"):
            cv.serialize_bundle(cv.Bundle(private_key=RSA_KEY), "pem-fullchain")

    def test_fullchain_with_chain(self):
        b = cv.Bundle(certificate=LEAF_CERT, chain=[INT_CERT])
        out = cv.serialize_bundle(b, "pem-fullchain")
        assert set(out) == {"fullchain.pem"}
        assert out["fullchain.pem"].count(b"BEGIN CERTIFICATE") == 2

    def test_fullchain_with_key(self):
        b = cv.Bundle(private_key=RSA_KEY, certificate=LEAF_CERT)
        out = cv.serialize_bundle(b, "pem-fullchain")
        assert set(out) == {"fullchain.pem", "privkey.pem"}


class TestSerializePemBundle:
    def test_empty_raises(self):
        with pytest.raises(ValueError, match="Nothing to bundle"):
            cv.serialize_bundle(cv.Bundle(), "pem-bundle")

    def test_cert_and_key(self):
        b = cv.Bundle(private_key=RSA_KEY, certificate=LEAF_CERT)
        out = cv.serialize_bundle(b, "pem-bundle")
        assert "bundle.pem" in out
        assert b"BEGIN CERTIFICATE" in out["bundle.pem"]
        assert b"BEGIN PRIVATE KEY" in out["bundle.pem"]

    def test_chain_included(self):
        b = cv.Bundle(certificate=LEAF_CERT, chain=[INT_CERT])
        out = cv.serialize_bundle(b, "pem-bundle")
        assert out["bundle.pem"].count(b"BEGIN CERTIFICATE") == 2


class TestSerializePemCertChain:
    def test_requires_certificate(self):
        with pytest.raises(ValueError, match="requires a certificate"):
            cv.serialize_bundle(cv.Bundle(chain=[INT_CERT]), "pem-cert-chain")

    def test_no_key_in_output(self):
        b = cv.Bundle(private_key=RSA_KEY, certificate=LEAF_CERT,
                      chain=[INT_CERT])
        out = cv.serialize_bundle(b, "pem-cert-chain")
        assert "fullchain.pem" in out
        assert b"PRIVATE KEY" not in out["fullchain.pem"]


# ==========================================================================
# serialize_bundle: DER / PKCS#7
# ==========================================================================
class TestSerializeDer:
    def test_requires_certificate(self):
        with pytest.raises(ValueError, match="requires a certificate"):
            cv.serialize_bundle(cv.Bundle(private_key=RSA_KEY), "der")

    def test_produces_der(self):
        out = cv.serialize_bundle(cv.Bundle(certificate=LEAF_CERT), "der")
        assert out["certificate.der"][0] == 0x30


class TestSerializePkcs7:
    def test_requires_certificate(self):
        with pytest.raises(ValueError, match="requires a certificate"):
            cv.serialize_bundle(cv.Bundle(private_key=RSA_KEY), "pkcs7")

    def test_binary(self):
        out = cv.serialize_bundle(cv.Bundle(certificate=LEAF_CERT), "pkcs7")
        assert out["certificate.p7b"][0] == 0x30

    def test_pem(self):
        out = cv.serialize_bundle(cv.Bundle(certificate=LEAF_CERT), "pkcs7-pem")
        assert b"BEGIN PKCS7" in out["certificate.p7b.pem"]

    def test_includes_chain(self):
        b = cv.Bundle(certificate=LEAF_CERT, chain=[INT_CERT])
        out = cv.serialize_bundle(b, "pkcs7")
        # Round-trip to check both certs are there
        certs = pkcs7.load_der_pkcs7_certificates(out["certificate.p7b"])
        assert len(certs) == 2

    def test_no_pkcs7_support(self):
        with __import__("unittest.mock").mock.patch.object(
                cv, "HAS_PKCS7", False):
            with pytest.raises(ValueError, match="PKCS#7 support"):
                cv.serialize_bundle(cv.Bundle(certificate=LEAF_CERT), "pkcs7")
            with pytest.raises(ValueError, match="PKCS#7 support"):
                cv.serialize_bundle(cv.Bundle(certificate=LEAF_CERT), "pkcs7-pem")


# ==========================================================================
# serialize_bundle: PKCS#12 variants
# ==========================================================================
class TestSerializePkcs12:
    def _bundle(self):
        return cv.Bundle(private_key=RSA_KEY, certificate=LEAF_CERT,
                         chain=[INT_CERT])

    def test_pkcs12(self):
        out = cv.serialize_bundle(self._bundle(), "pkcs12",
                                  output_password="pw")
        assert "certificate.pfx" in out
        assert out["certificate.pfx"][0] == 0x30

    def test_pkcs12_p12(self):
        out = cv.serialize_bundle(self._bundle(), "pkcs12-p12",
                                  output_password="pw")
        assert "certificate.p12" in out

    def test_pkcs12_b64(self):
        out = cv.serialize_bundle(self._bundle(), "pkcs12-b64",
                                  output_password="pw")
        assert "certificate.p12.txt" in out
        # Wrapped base64
        lines = out["certificate.p12.txt"].split(b"\n")
        assert len(lines) > 1
        assert all(len(l) <= 64 for l in lines if l)

    def test_legacy_pfx(self):
        out = cv.serialize_bundle(self._bundle(), "pfx",
                                  output_password="pw")
        assert "certificate.pfx" in out

    def test_legacy_pfx_b64(self):
        out = cv.serialize_bundle(self._bundle(), "pfx-b64",
                                  output_password="pw")
        assert "certificate.p12.txt" in out

    def test_missing_password_raises(self):
        with pytest.raises(ValueError, match="requires a password"):
            cv.serialize_bundle(self._bundle(), "pkcs12")

    def test_password_mismatch_raises(self):
        with pytest.raises(ValueError, match="does not match"):
            cv.serialize_bundle(self._bundle(), "pkcs12",
                                output_password="a",
                                output_password_confirm="b")

    def test_roundtrip_with_password(self):
        out = cv.serialize_bundle(self._bundle(), "pkcs12",
                                  output_password="pw")
        key, cert, extra = pkcs12.load_key_and_certificates(
            out["certificate.pfx"], b"pw")
        assert key is not None
        assert cert is not None
        assert extra is not None and len(extra) == 1


# ==========================================================================
# serialize_bundle: public and private keys
# ==========================================================================
class TestSerializePubkey:
    def test_pubkey_pem_from_explicit_public_key(self):
        b = cv.Bundle(public_key=RSA_KEY.public_key())
        out = cv.serialize_bundle(b, "pubkey-pem")
        assert b"BEGIN PUBLIC KEY" in out["public.key"]

    def test_pubkey_pem_from_certificate(self):
        out = cv.serialize_bundle(cv.Bundle(certificate=LEAF_CERT),
                                  "pubkey-pem")
        assert b"BEGIN PUBLIC KEY" in out["public.key"]

    def test_pubkey_pem_missing(self):
        with pytest.raises(ValueError, match="No public key"):
            cv.serialize_bundle(cv.Bundle(private_key=RSA_KEY), "pubkey-pem")

    def test_pubkey_openssh(self):
        b = cv.Bundle(public_key=RSA_KEY.public_key())
        out = cv.serialize_bundle(b, "pubkey-openssh")
        assert out["public.key"].startswith(b"ssh-rsa ")

    def test_pubkey_openssh_unsupported_key_type(self):
        # Ed448 is not supported by OpenSSH encoding in cryptography
        b = cv.Bundle(public_key=ED448_KEY.public_key())
        with pytest.raises(ValueError, match="OpenSSH format not supported"):
            cv.serialize_bundle(b, "pubkey-openssh")

    def test_pubkey_openssh_missing(self):
        with pytest.raises(ValueError, match="No public key"):
            cv.serialize_bundle(cv.Bundle(), "pubkey-openssh")


class TestSerializeKeyPkcs1:
    def test_rsa_key(self):
        out = cv.serialize_bundle(cv.Bundle(private_key=RSA_KEY), "key-pkcs1")
        assert b"BEGIN RSA PRIVATE KEY" in out["private.key"]

    def test_missing_key(self):
        with pytest.raises(ValueError, match="No private key"):
            cv.serialize_bundle(cv.Bundle(), "key-pkcs1")

    def test_non_rsa_key(self):
        with pytest.raises(ValueError, match="only available for RSA"):
            cv.serialize_bundle(cv.Bundle(private_key=EC_KEY), "key-pkcs1")


# ==========================================================================
# serialize_bundle: error paths
# ==========================================================================
class TestSerializeErrors:
    def test_unknown_target(self):
        with pytest.raises(ValueError, match="Unknown target"):
            cv.serialize_bundle(cv.Bundle(certificate=LEAF_CERT), "nonsense")

    def test_no_components_for_target(self):
        # pem-separate with empty bundle yields no outputs
        with pytest.raises(ValueError, match="Nothing to output"):
            cv.serialize_bundle(cv.Bundle(), "pem-separate")

    def test_no_components_chain_only_cert_required(self):
        # pem-cert-chain requires certificate even with chain present
        with pytest.raises(ValueError, match="requires a certificate"):
            cv.serialize_bundle(cv.Bundle(chain=[INT_CERT]), "pem-cert-chain")


# ==========================================================================
# Round-trip integration
# ==========================================================================
class TestRoundTrip:
    def test_pem_to_pkcs12_to_pem(self):
        b1 = cv.parse_anything(PEM_LEAF + PEM_KEY)
        out = cv.serialize_bundle(b1, "pkcs12", output_password="pw")
        b2 = cv.parse_anything(out["certificate.pfx"], password="pw")
        assert b2.certificate is not None
        assert b2.private_key is not None
        assert (b2.certificate.subject.rfc4514_string()
                == b1.certificate.subject.rfc4514_string())

    def test_der_to_pkcs7_to_der(self):
        b1 = cv.parse_anything(DER_CERT)
        out = cv.serialize_bundle(b1, "pkcs7")
        b2 = cv.parse_anything(out["certificate.p7b"])
        assert b2.certificate is not None
        assert b2.source_format == "pkcs7"

    def test_base64_der_roundtrip(self):
        b64 = base64.b64encode(DER_CERT)
        b1 = cv.parse_anything(b64)
        out = cv.serialize_bundle(b1, "der")
        assert out["certificate.der"] == DER_CERT
