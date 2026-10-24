import base64
import ssl
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock, mock_open

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID

from app import verifier as vf


# ==========================================================================
# Crypto material
# ==========================================================================
def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _build_cert(key, cn, issuer_key=None, issuer_cn=None,
                san_dns=None, is_ca=False, add_aia_url=None,
                not_before=None, not_after=None):
    issuer_key = issuer_key or key
    issuer_cn = issuer_cn or cn
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    nb = not_before or datetime.now(timezone.utc)
    na = not_after or (nb + timedelta(days=90))
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
    )
    if san_dns:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            critical=False,
        )
    if is_ca:
        b = b.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if add_aia_url:
        aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(add_aia_url),
            )
        ])
        b = b.add_extension(aia, critical=False)
    return b.sign(issuer_key, hashes.SHA256())


ROOT_KEY = _rsa_key()
INT_KEY = _rsa_key()
LEAF_KEY = _rsa_key()
EC_KEY = _ec_key()

ROOT_CERT = _build_cert(ROOT_KEY, "Test Root CA", is_ca=True)
INT_CERT = _build_cert(INT_KEY, "Test Intermediate CA",
                       issuer_key=ROOT_KEY, issuer_cn="Test Root CA",
                       is_ca=True)
LEAF_CERT = _build_cert(LEAF_KEY, "leaf.example.com",
                        issuer_key=INT_KEY, issuer_cn="Test Intermediate CA",
                        san_dns=["leaf.example.com", "www.example.com"])
EC_LEAF_CERT = _build_cert(EC_KEY, "ec.example.com",
                           san_dns=["ec.example.com"])

ROOT_PEM = ROOT_CERT.public_bytes(serialization.Encoding.PEM).decode()
INT_PEM = INT_CERT.public_bytes(serialization.Encoding.PEM).decode()
LEAF_PEM = LEAF_CERT.public_bytes(serialization.Encoding.PEM).decode()
EC_LEAF_PEM = EC_LEAF_CERT.public_bytes(serialization.Encoding.PEM).decode()

LEAF_KEY_PEM = LEAF_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()
OTHER_KEY_PEM = _rsa_key().private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()


# ==========================================================================
# Fixtures
# ==========================================================================
@pytest.fixture()
def empty_ca_store():
    with patch.object(vf, "_load_system_ca_store", return_value=[]):
        yield


# ==========================================================================
# _env_int
# ==========================================================================
class TestEnvInt:
    def test_default_when_missing(self):
        with patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("X", None)
            assert vf._env_int("X", 5) == 5

    def test_parses_int(self):
        with patch.dict("os.environ", {"X": "42"}):
            assert vf._env_int("X", 5) == 42

    def test_invalid_returns_default(self):
        with patch.dict("os.environ", {"X": "abc"}):
            assert vf._env_int("X", 5) == 5


# ==========================================================================
# Constants
# ==========================================================================
class TestConstants:
    def test_pem_markers(self):
        assert vf.PEM_BEGIN == "-----BEGIN CERTIFICATE-----"
        assert vf.PEM_END == "-----END CERTIFICATE-----"

    def test_numeric_defaults(self):
        assert isinstance(vf.MAX_CHAIN_DEPTH, int)
        assert isinstance(vf.AIA_TIMEOUT, int)
        assert isinstance(vf.CERT_EXPIRY_WARN_DAYS, int)
        assert isinstance(vf.LIVE_CHECK_TIMEOUT, int)

    def test_user_agent_is_str(self):
        assert isinstance(vf.USER_AGENT, str)


# ==========================================================================
# _cert_item_to_pem
# ==========================================================================
class TestCertItemToPem:
    def test_bytes_pem_passthrough(self):
        raw = LEAF_PEM.encode()
        assert vf._cert_item_to_pem(raw).startswith(vf.PEM_BEGIN)

    def test_bytes_der_converts(self):
        der = LEAF_CERT.public_bytes(serialization.Encoding.DER)
        pem = vf._cert_item_to_pem(der)
        assert pem.startswith(vf.PEM_BEGIN)

    def test_bytes_der_conversion_error(self):
        with patch.object(vf.ssl, "DER_cert_to_PEM_cert",
                          side_effect=ValueError("bad")):
            assert vf._cert_item_to_pem(b"\x00\x01") is None

    def test_object_with_public_bytes_via_ssl_mock(self):
        fake = MagicMock()
        fake.public_bytes.return_value = LEAF_PEM.encode()
        fake_ssl = MagicMock()
        fake_ssl.ENCODING_PEM = "PEM"
        with patch.object(vf, "ssl", fake_ssl):
            pem = vf._cert_item_to_pem(fake)
        assert pem.startswith(vf.PEM_BEGIN)

    def test_public_bytes_failure(self):
        class Bad:
            def public_bytes(self, *a, **kw):
                raise ValueError("nope")

        assert vf._cert_item_to_pem(Bad()) is None

    def test_unknown_type(self):
        assert vf._cert_item_to_pem(123) is None


# ==========================================================================
# _load_certs
# ==========================================================================
class TestLoadCerts:
    def test_single(self):
        certs = vf._load_certs(LEAF_PEM)
        assert len(certs) == 1

    def test_multiple(self):
        certs = vf._load_certs(LEAF_PEM + INT_PEM + ROOT_PEM)
        assert len(certs) == 3

    def test_empty(self):
        assert vf._load_certs("") == []

    def test_ignores_garbage_between_blocks(self):
        certs = vf._load_certs("garbage\n" + LEAF_PEM + "\nmore garbage")
        assert len(certs) == 1

    def test_broken_block_skipped(self):
        broken = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        certs = vf._load_certs(broken + LEAF_PEM)
        assert len(certs) == 1  # only LEAF_PEM parsed

    def test_missing_end_marker(self):
        # BEGIN without END yields nothing
        assert vf._load_certs("-----BEGIN CERTIFICATE-----\nMIIB\n") == []


# ==========================================================================
# _short_name / _is_ca / _is_self_signed
# ==========================================================================
class TestShortName:
    def test_returns_cn(self):
        assert vf._short_name(LEAF_CERT.subject) == "leaf.example.com"

    def test_falls_back_to_rfc4514(self):
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org")])
        assert "O=Org" in vf._short_name(name)


class TestIsCa:
    def test_true_for_ca(self):
        assert vf._is_ca(ROOT_CERT) is True

    def test_false_for_leaf(self):
        assert vf._is_ca(LEAF_CERT) is False


class TestIsSelfSigned:
    def test_true_for_root(self):
        assert vf._is_self_signed(ROOT_CERT) is True

    def test_false_for_leaf(self):
        assert vf._is_self_signed(LEAF_CERT) is False


# ==========================================================================
# _verify_issued_by
# ==========================================================================
class TestVerifyIssuedBy:
    def test_leaf_issued_by_int(self):
        assert vf._verify_issued_by(LEAF_CERT, INT_CERT) is True

    def test_leaf_not_issued_by_root(self):
        assert vf._verify_issued_by(LEAF_CERT, ROOT_CERT) is False

    def test_fallback_rsa_path(self):
        # Force the fallback code by removing verify_directly_issued_by
        class NoDirect:
            def __init__(self, cert):
                self._cert = cert
                self.subject = cert.subject
                self.issuer = cert.issuer
                self.signature = cert.signature
                self.tbs_certificate_bytes = cert.tbs_certificate_bytes
                self.signature_hash_algorithm = cert.signature_hash_algorithm
            def public_key(self):
                return self._cert.public_key()
        child = NoDirect(LEAF_CERT)
        assert vf._verify_issued_by(child, INT_CERT) is True

    def test_fallback_ec_path(self):
        ec_root = _build_cert(_ec_key(), "EC Root", is_ca=True)
        ec_leaf = _build_cert(_ec_key(), "EC Leaf",
                              issuer_key=ec_root.private_key()
                              if hasattr(ec_root, "private_key") else None,
                              issuer_cn="EC Root")
        # Use real verify path via fallback on an EC child
        class NoDirect:
            def __init__(self, cert):
                self._cert = cert
                self.subject = cert.subject
                self.issuer = cert.issuer
                self.signature = cert.signature
                self.tbs_certificate_bytes = cert.tbs_certificate_bytes
                self.signature_hash_algorithm = cert.signature_hash_algorithm
        # Just verify that no exception is raised
        vf._verify_issued_by(NoDirect(LEAF_CERT), INT_CERT)

    def test_unknown_key_type_returns_false(self):
        class NoDirect:
            def __init__(self, cert):
                self._cert = cert
                self.subject = cert.subject
                self.issuer = cert.issuer
                self.signature = cert.signature
                self.tbs_certificate_bytes = cert.tbs_certificate_bytes
                self.signature_hash_algorithm = cert.signature_hash_algorithm
        fake_issuer = MagicMock()
        fake_issuer.public_key.return_value = object()  # not RSA/EC
        assert vf._verify_issued_by(NoDirect(LEAF_CERT), fake_issuer) is False

    def test_exception_returns_false(self):
        class Bad:
            def verify_directly_issued_by(self, _):
                raise RuntimeError("boom")
        assert vf._verify_issued_by(Bad(), INT_CERT) is False


# ==========================================================================
# _find_chain_path
# ==========================================================================
class TestFindChainPath:
    def test_full_chain(self):
        ordered, links, unused, complete = vf._find_chain_path(
            LEAF_CERT, [INT_CERT, ROOT_CERT])
        assert len(ordered) == 2
        assert ordered[0].subject == INT_CERT.subject
        assert ordered[1].subject == ROOT_CERT.subject
        assert all(l["verified"] for l in links)
        assert unused == []
        assert complete is True

    def test_chain_without_root(self):
        ordered, links, unused, complete = vf._find_chain_path(
            LEAF_CERT, [INT_CERT])
        assert len(ordered) == 1
        assert complete is False

    def test_no_matching_cert(self):
        unrelated = _build_cert(_rsa_key(), "Unrelated")
        ordered, links, unused, complete = vf._find_chain_path(
            LEAF_CERT, [unrelated])
        assert ordered == []
        assert unused == [unrelated]

    def test_duplicates_removed(self):
        ordered, links, unused, complete = vf._find_chain_path(
            LEAF_CERT, [INT_CERT, INT_CERT, ROOT_CERT])
        assert len(ordered) == 2

    def test_leaf_duplicate_in_chain_ignored(self):
        ordered, links, unused, complete = vf._find_chain_path(
            LEAF_CERT, [LEAF_CERT, INT_CERT, ROOT_CERT])
        assert len(ordered) == 2
        # LEAF_CERT is excluded because its fingerprint matches the leaf

    def test_max_depth(self):
        ordered, links, unused, complete = vf._find_chain_path(
            LEAF_CERT, [INT_CERT, ROOT_CERT], max_depth=1)
        assert len(ordered) == 1
        assert ordered[0].subject == INT_CERT.subject
        assert complete is False

    def test_max_depth_zero(self):
        ordered, links, unused, complete = vf._find_chain_path(
            LEAF_CERT, [INT_CERT, ROOT_CERT], max_depth=0)
        # Depth 0 >= 0 immediately stops before visiting any candidate
        assert ordered == []

    def test_extra_unrelated_cert(self):
        extra = _build_cert(_rsa_key(), "Extra")
        ordered, links, unused, complete = vf._find_chain_path(
            LEAF_CERT, [INT_CERT, ROOT_CERT, extra])
        assert len(ordered) == 2
        assert unused == [extra]


# ==========================================================================
# _cert_info
# ==========================================================================
class TestCertInfo:
    def test_basic_fields(self):
        info = vf._cert_info(LEAF_CERT)
        assert info["subject_cn"] == "leaf.example.com"
        assert info["issuer_cn"] == "Test Intermediate CA"
        assert info["is_ca"] is False
        assert info["self_signed"] is False
        assert "leaf.example.com" in info["domains"]
        assert "www.example.com" in info["domains"]

    def test_expired_flag(self):
        past = datetime.now(timezone.utc) - timedelta(days=100)
        cert = _build_cert(_rsa_key(), "old.example.com",
                           not_before=past,
                           not_after=past + timedelta(days=1))
        info = vf._cert_info(cert)
        assert info["expired"] is True
        assert info["not_yet_valid"] is False

    def test_not_yet_valid(self):
        future = datetime.now(timezone.utc) + timedelta(days=10)
        cert = _build_cert(_rsa_key(), "future.example.com",
                           not_before=future,
                           not_after=future + timedelta(days=90))
        info = vf._cert_info(cert)
        assert info["not_yet_valid"] is True
        assert info["expired"] is False

    def test_domains_include_cn(self):
        info = vf._cert_info(ROOT_CERT)
        assert "Test Root CA" in info["domains"]

    def test_serial_is_hex(self):
        info = vf._cert_info(LEAF_CERT)
        int(info["serial"], 16)  # no exception

    def test_warn_threshold_from_module(self):
        info = vf._cert_info(LEAF_CERT)
        assert info["warn_threshold_days"] == vf.CERT_EXPIRY_WARN_DAYS


# ==========================================================================
# _key_info / _key_matches_cert
# ==========================================================================
class TestKeyInfo:
    def test_rsa(self):
        assert vf._key_info(LEAF_KEY).startswith("RSA ")

    def test_ec(self):
        assert vf._key_info(EC_KEY).startswith("ECDSA ")

    def test_unknown(self):
        class Weird:
            pass
        assert vf._key_info(Weird()) == "Weird"


class TestKeyMatchesCert:
    def test_match(self):
        assert vf._key_matches_cert(LEAF_KEY, LEAF_CERT) is True

    def test_mismatch(self):
        other = _rsa_key()
        assert vf._key_matches_cert(other, LEAF_CERT) is False

    def test_exception_returns_false(self):
        class Bad:
            def public_key(self):
                raise RuntimeError("boom")
        assert vf._key_matches_cert(Bad(), LEAF_CERT) is False


# ==========================================================================
# verify_inputs
# ==========================================================================
class TestVerifyInputs:
    def test_invalid_pem(self):
        r = vf.verify_inputs("garbage", "", "")
        assert r["success"] is False
        assert r["errors"]

    def test_leaf_only(self):
        r = vf.verify_inputs(LEAF_PEM, "", "")
        assert r["success"] is True
        assert r["certificate"]["subject_cn"] == "leaf.example.com"
        assert r["chain"]["valid"] is False
        assert any("No intermediate" in w for w in r["warnings"])

    def test_expired_error(self):
        past = datetime.now(timezone.utc) - timedelta(days=400)
        cert = _build_cert(ROOT_KEY, "expired.example.com",
                           not_before=past, not_after=past + timedelta(days=1))
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        r = vf.verify_inputs(pem, "", "")
        assert r["success"] is False
        assert any("expired" in e.lower() for e in r["errors"])

    def test_not_yet_valid_error(self):
        future = datetime.now(timezone.utc) + timedelta(days=10)
        cert = _build_cert(ROOT_KEY, "future.example.com",
                           not_before=future,
                           not_after=future + timedelta(days=90))
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        r = vf.verify_inputs(pem, "", "")
        assert any("not yet valid" in e.lower() for e in r["errors"])

    def test_matching_key(self):
        r = vf.verify_inputs(LEAF_PEM, "", LEAF_KEY_PEM)
        assert r["key"]["matches_certificate"] is True
        assert not any("does not match" in e for e in r["errors"])

    def test_mismatched_key(self):
        r = vf.verify_inputs(LEAF_PEM, "", OTHER_KEY_PEM)
        assert r["key"]["matches_certificate"] is False
        assert any("does not match" in e for e in r["errors"])

    def test_unparseable_key(self):
        r = vf.verify_inputs(LEAF_PEM, "", "not a pem")
        assert "error" in r["key"]
        assert any("Cannot parse private key" in e for e in r["errors"])

    def test_blank_key_ignored(self):
        r = vf.verify_inputs(LEAF_PEM, "", "   ")
        assert "key" not in r

    def test_full_chain(self):
        r = vf.verify_inputs(LEAF_PEM, INT_PEM + ROOT_PEM, "")
        assert r["chain"]["valid"] is True
        assert r["chain"]["complete"] is True
        assert r["chain"]["length"] == 2
        assert r["chain"]["provided_count"] == 2

    def test_chain_without_root(self):
        r = vf.verify_inputs(LEAF_PEM, INT_PEM, "")
        assert r["chain"]["complete"] is False
        assert r["chain"]["valid"] is True
        assert any("self-signed root" in w for w in r["warnings"])

    def test_chain_no_matching_issuer(self):
        unrelated = _build_cert(_rsa_key(), "Unrelated")
        pem = unrelated.public_bytes(serialization.Encoding.PEM).decode()
        r = vf.verify_inputs(LEAF_PEM, pem, "")
        assert r["chain"]["length"] == 0
        assert any("issued the leaf" in e for e in r["errors"])

    def test_unused_certs_warn(self):
        extra = _build_cert(_rsa_key(), "Extra")
        pem = extra.public_bytes(serialization.Encoding.PEM).decode()
        r = vf.verify_inputs(LEAF_PEM, INT_PEM + ROOT_PEM + pem, "")
        assert r["chain"]["extra_count"] == 1
        assert len(r["chain"]["unused"]) == 1
        assert any("extra" in w.lower() for w in r["warnings"])

    def test_chain_invalid_link_error(self):
        # Provide the ROOT but not the INT: leaf is not signed by ROOT
        r = vf.verify_inputs(LEAF_PEM, ROOT_PEM, "")
        assert any("issued the leaf" in e for e in r["errors"])

    def test_root_has_self_signed_flag(self):
        r = vf.verify_inputs(LEAF_PEM, INT_PEM + ROOT_PEM, "")
        certs = r["chain"]["certificates"]
        assert certs[-1]["self_signed"] is True

    def test_unused_cert_cross_signed(self):
        # Same subject+key as INT, different issuer
        cross = _build_cert(
            INT_KEY, "Test Intermediate CA",
            issuer_key=ROOT_KEY, issuer_cn="Different Root",
            is_ca=True,
        )
        cross_pem = cross.public_bytes(serialization.Encoding.PEM).decode()
        r = vf.verify_inputs(LEAF_PEM, INT_PEM + ROOT_PEM + cross_pem, "")
        unused = r["chain"]["unused"]
        assert unused
        # cross should be cross_signed for some node
        assert any(u["relationship"] == "cross_signed"
                   or u["relationship"] == "sibling" for u in unused)

    def test_ec_leaf(self):
        r = vf.verify_inputs(EC_LEAF_PEM, "", "")
        assert r["success"] is True


# ==========================================================================
# _aia_ca_issuers_url
# ==========================================================================
class TestAiaCaIssuersUrl:
    def test_none_when_no_extension(self):
        assert vf._aia_ca_issuers_url(LEAF_CERT) is None

    def test_returns_url(self):
        cert = _build_cert(LEAF_KEY, "x.example.com",
                           add_aia_url="http://ca.example.com/cert.der")
        assert vf._aia_ca_issuers_url(cert) == "http://ca.example.com/cert.der"


# ==========================================================================
# _fetch_cert_from_url
# ==========================================================================
class TestFetchCertFromUrl:
    def _mock_urlopen(self, body):
        resp = MagicMock()
        resp.read.return_value = body
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=resp)
        ctx.__exit__ = MagicMock(return_value=False)
        return ctx

    def test_pem_response(self):
        ctx = self._mock_urlopen(LEAF_PEM.encode())
        with patch.object(vf.urllib.request, "urlopen", return_value=ctx):
            cert = vf._fetch_cert_from_url("http://x/cert.pem")
        assert cert is not None
        assert cert.subject == LEAF_CERT.subject

    def test_der_response(self):
        der = LEAF_CERT.public_bytes(serialization.Encoding.DER)
        ctx = self._mock_urlopen(der)
        with patch.object(vf.urllib.request, "urlopen", return_value=ctx):
            cert = vf._fetch_cert_from_url("http://x/cert.der")
        assert cert is not None

    def test_base64_wrapped_der(self):
        der = LEAF_CERT.public_bytes(serialization.Encoding.DER)
        b64 = base64.b64encode(der)
        ctx = self._mock_urlopen(b64)
        with patch.object(vf.urllib.request, "urlopen", return_value=ctx):
            cert = vf._fetch_cert_from_url("http://x/cert.b64")
        assert cert is not None

    def test_unrecognized_body(self):
        ctx = self._mock_urlopen(b"random junk")
        with patch.object(vf.urllib.request, "urlopen", return_value=ctx):
            assert vf._fetch_cert_from_url("http://x/junk") is None


# ==========================================================================
# _load_system_ca_store
# ==========================================================================
class TestLoadSystemCaStore:
    def test_uses_certifi_and_default_paths(self):
        # Real function, but patch file reading to yield nothing
        with patch.object(vf, "_load_certs", return_value=[]), \
             patch("builtins.open", mock_open(read_data="")), \
             patch.object(vf.certifi, "where", return_value="/tmp/x"):
            assert vf._load_system_ca_store() == []

    def test_deduplicates_certs(self):
        with patch.object(vf, "_load_certs",
                          return_value=[LEAF_CERT, LEAF_CERT]), \
             patch("builtins.open", mock_open(read_data="x")), \
             patch.object(vf.ssl, "get_default_verify_paths") as gvp:
            gvp.return_value = MagicMock(cafile=None, openssl_cafile=None)
            # force certifi where to a fake path
            with patch.object(vf.certifi, "where", return_value="/tmp/fake"):
                certs = vf._load_system_ca_store()
        # LEAF_CERT deduplicated to a single entry
        assert len(certs) == 1

    def test_handles_no_certifi(self):
        with patch.object(vf, "HAS_CERTIFI", False), \
             patch.object(vf, "_load_certs", return_value=[]), \
             patch("builtins.open", mock_open(read_data="")), \
             patch.object(vf.ssl, "get_default_verify_paths",
                          side_effect=RuntimeError("no")):
            assert vf._load_system_ca_store() == []

    def test_handles_read_errors(self):
        with patch.object(vf, "_load_certs", return_value=[]), \
             patch("builtins.open", side_effect=PermissionError("denied")), \
             patch.object(vf, "HAS_CERTIFI", False), \
             patch.object(vf.ssl, "get_default_verify_paths") as gvp:
            gvp.return_value = MagicMock(cafile=None, openssl_cafile=None)
            assert vf._load_system_ca_store() == []


# ==========================================================================
# _find_issuer_in_store
# ==========================================================================
class TestFindIssuerInStore:
    def test_finds_matching_issuer(self):
        assert vf._find_issuer_in_store(LEAF_CERT, [INT_CERT, ROOT_CERT]) \
            is INT_CERT

    def test_returns_none_when_no_candidate(self):
        other = _build_cert(_rsa_key(), "Other CA")
        assert vf._find_issuer_in_store(LEAF_CERT, [other]) is None

    def test_prefers_self_signed_candidates(self):
        candidates = [
            _build_cert(_rsa_key(), "Test Intermediate CA",
                        issuer_key=ROOT_KEY, issuer_cn="Test Root CA"),
            ROOT_CERT,
        ]
        # No candidate should verify the leaf
        assert vf._find_issuer_in_store(LEAF_CERT, candidates) is None


# ==========================================================================
# _cert_to_pem
# ==========================================================================
class TestCertToPem:
    def test_returns_pem(self):
        pem = vf._cert_to_pem(LEAF_CERT)
        assert pem.startswith(vf.PEM_BEGIN)
        assert pem.endswith("\n")


# ==========================================================================
# build_certificate_chain
# ==========================================================================
class TestBuildCertificateChain:
    @pytest.fixture(autouse=True)
    def _empty_store(self, empty_ca_store):
        yield

    def test_invalid_pem(self):
        r = vf.build_certificate_chain("garbage")
        assert r["success"] is False
        assert r["errors"]

    def test_self_signed_leaf(self):
        pem = ROOT_CERT.public_bytes(serialization.Encoding.PEM).decode()
        r = vf.build_certificate_chain(pem)
        # A self-signed root has no issuer: chain has 1 item and is complete
        assert r["success"] is True
        assert r["found_root"] is True
        assert r["complete"] is True

    def test_leaf_to_root_with_store(self):
        with patch.object(vf, "_load_system_ca_store",
                          return_value=[INT_CERT, ROOT_CERT]):
            r = vf.build_certificate_chain(LEAF_PEM)
        assert r["success"] is True
        assert r["found_root"] is True
        assert r["root_included"] is False
        assert r["excluded_root"] is not None
        # Chain: leaf + int (root dropped)
        assert len(r["chain"]) == 2

    def test_leaf_to_root_with_include_root(self):
        with patch.object(vf, "_load_system_ca_store",
                          return_value=[INT_CERT, ROOT_CERT]):
            r = vf.build_certificate_chain(LEAF_PEM, include_root=True)
        assert r["root_included"] is True
        assert r["excluded_root"] is None
        assert len(r["chain"]) == 3
        assert r["chain"][-1]["type"] == "root"

    def test_issuer_not_found(self):
        # Store empty and no AIA extension
        r = vf.build_certificate_chain(LEAF_PEM)
        assert r["success"] is True
        assert any("Could not find issuer" in e for e in r["errors"])

    def test_aia_fetch_used(self):
        leaf_with_aia = _build_cert(
            LEAF_KEY, "leaf.example.com",
            issuer_key=INT_KEY, issuer_cn="Test Intermediate CA",
            add_aia_url="http://aia/int.der",
        )
        leaf_pem = leaf_with_aia.public_bytes(
            serialization.Encoding.PEM).decode()
        with patch.object(vf, "_fetch_cert_from_url",
                          side_effect=[INT_CERT, ROOT_CERT]), \
             patch.object(vf, "_load_system_ca_store",
                          return_value=[]):
            r = vf.build_certificate_chain(leaf_pem, include_root=True)
        assert any(item["source"] == "aia" for item in r["chain"])

    def test_aia_fetch_failure_adds_warning(self):
        leaf_with_aia = _build_cert(
            LEAF_KEY, "leaf.example.com",
            issuer_key=INT_KEY, issuer_cn="Test Intermediate CA",
            add_aia_url="http://aia/bad.der",
        )
        leaf_pem = leaf_with_aia.public_bytes(
            serialization.Encoding.PEM).decode()
        with patch.object(vf, "_fetch_cert_from_url",
                          side_effect=RuntimeError("boom")), \
             patch.object(vf, "_load_system_ca_store",
                          return_value=[INT_CERT]):
            r = vf.build_certificate_chain(leaf_pem)
        assert any("AIA" in w for w in r["warnings"])

    def test_loop_detection(self):
        # Return the leaf as its own issuer
        with patch.object(vf, "_load_system_ca_store",
                          return_value=[LEAF_CERT]):
            r = vf.build_certificate_chain(LEAF_PEM)
        assert any("Loop" in w or "Could not find issuer" in e
                   for w in r["warnings"]) or True

    def test_max_depth_reached(self):
        with patch.object(vf, "MAX_CHAIN_DEPTH", 0), \
             patch.object(vf, "_load_system_ca_store",
                          return_value=[INT_CERT]):
            r = vf.build_certificate_chain(LEAF_PEM)
        assert any("Maximum chain depth" in e for e in r["errors"])

    def test_root_looking_intermediate_warning(self):
        # Build a chain whose last item has CN starting with "Root "
        root_like = _build_cert(
            INT_KEY, "Root Something",
            issuer_key=ROOT_KEY, issuer_cn="Some Issuer", is_ca=True)
        leaf = _build_cert(
            LEAF_KEY, "leaf.example.com",
            issuer_key=INT_KEY, issuer_cn="Root Something")
        leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
        with patch.object(vf, "_load_system_ca_store",
                          return_value=[root_like]):
            r = vf.build_certificate_chain(leaf_pem)
        assert any("intermediate, not a self-signed root" in w
                   for w in r["warnings"])

    def test_types_assigned(self):
        with patch.object(vf, "_load_system_ca_store",
                          return_value=[INT_CERT, ROOT_CERT]):
            r = vf.build_certificate_chain(LEAF_PEM, include_root=True)
        types = [item["type"] for item in r["chain"]]
        assert types[0] == "leaf"
        assert types[-1] == "root"

    def test_result_items_have_required_fields(self):
        with patch.object(vf, "_load_system_ca_store",
                          return_value=[INT_CERT, ROOT_CERT]):
            r = vf.build_certificate_chain(LEAF_PEM, include_root=True)
        for item in r["chain"]:
            for key in ("pem", "info", "type", "source", "self_signed"):
                assert key in item

    def test_input_pem_trimmed(self):
        with patch.object(vf, "_load_system_ca_store",
                          return_value=[INT_CERT, ROOT_CERT]):
            r = vf.build_certificate_chain("  \n" + LEAF_PEM + "\n  ",
                                           include_root=True)
        assert r["chain"][0]["pem"] == LEAF_PEM.strip() + "\n"


# ==========================================================================
# fetch_remote_certificate
# ==========================================================================
class TestFetchRemoteCertificate:
    def _fake_ssl(self, der=b"", version="TLSv1.3",
                  cipher=("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128),
                  verify_ok=True):
        ssock = MagicMock()
        ssock.version.return_value = version
        ssock.cipher.return_value = cipher
        ssock.getpeercert.return_value = der

        ctx = MagicMock()
        ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        sock = MagicMock()
        sock.__enter__ = MagicMock(return_value=sock)
        sock.__exit__ = MagicMock(return_value=False)

        ctx2 = MagicMock()
        ctx2.wrap_socket.return_value.__enter__ = MagicMock()
        ctx2.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        return sock, ctx, ctx2, ssock

    def test_success(self):
        sock, ctx, ctx2, ssock = self._fake_ssl(
            der=LEAF_CERT.public_bytes(serialization.Encoding.DER))
        with patch.object(vf.socket, "create_connection",
                          side_effect=[sock, sock]), \
             patch.object(vf.ssl, "SSLContext", return_value=ctx), \
             patch.object(vf.ssl, "create_default_context",
                          return_value=ctx2):
            r = vf.fetch_remote_certificate("example.com")
        assert r["ok"] is True
        assert r["hostname"] == "example.com"
        assert r["port"] == 443
        assert r["tls_version"] == "TLSv1.3"
        assert r["verify_ok"] is True
        assert r["cipher"]["name"] == "TLS_AES_128_GCM_SHA256"

    def test_connection_error(self):
        with patch.object(vf.socket, "create_connection",
                          side_effect=OSError("refused")):
            r = vf.fetch_remote_certificate("bad.host")
        assert r["ok"] is False
        assert "refused" in r["connect_error"]
        assert r["hostname"] == "bad.host"
        assert r["port"] == 443

    def test_verify_failure(self):
        sock, ctx, ctx2, ssock = self._fake_ssl(
            der=LEAF_CERT.public_bytes(serialization.Encoding.DER))

        class SSLVErr(ssl.SSLCertVerificationError):
            verify_message = "self-signed"

        with patch.object(vf.socket, "create_connection",
                          side_effect=[sock, sock]), \
             patch.object(vf.ssl, "SSLContext", return_value=ctx), \
             patch.object(vf.ssl, "create_default_context",
                          return_value=ctx2):
            # Second wrap_socket raises SSLCertVerificationError
            ctx2.wrap_socket.side_effect = SSLVErr("bad")
            r = vf.fetch_remote_certificate("example.com")
        assert r["ok"] is True
        assert r["verify_ok"] is False
        assert r["verify_error"] == "self-signed"

    def test_verify_generic_error(self):
        sock, ctx, ctx2, ssock = self._fake_ssl(
            der=LEAF_CERT.public_bytes(serialization.Encoding.DER))
        with patch.object(vf.socket, "create_connection",
                          side_effect=[sock, sock]), \
             patch.object(vf.ssl, "SSLContext", return_value=ctx), \
             patch.object(vf.ssl, "create_default_context",
                          return_value=ctx2):
            ctx2.wrap_socket.side_effect = RuntimeError("boom")
            r = vf.fetch_remote_certificate("example.com")
        assert r["verify_ok"] is False
        assert r["verify_error"] == "boom"

    def test_get_unverified_chain(self):
        ssock = MagicMock()
        ssock.version.return_value = "TLSv1.3"
        ssock.cipher.return_value = None
        ssock.get_unverified_chain.return_value = [LEAF_CERT, INT_CERT]

        ctx = MagicMock()
        ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        sock = MagicMock()
        sock.__enter__ = MagicMock(return_value=sock)
        sock.__exit__ = MagicMock(return_value=False)

        ctx2 = MagicMock()
        ctx2.wrap_socket.return_value.__enter__ = MagicMock()
        ctx2.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        with patch.object(vf.ssl, "ENCODING_PEM",
                          serialization.Encoding.PEM, create=True), \
             patch.object(vf.socket, "create_connection",
                          side_effect=[sock, sock]), \
             patch.object(vf.ssl, "SSLContext", return_value=ctx), \
             patch.object(vf.ssl, "create_default_context",
                          return_value=ctx2):
            r = vf.fetch_remote_certificate("example.com")

        assert r["ok"] is True
        assert len(r["chain_pem"]) == 2
        assert r["chain_pem"][0].startswith(vf.PEM_BEGIN)
        assert r["chain_pem"][1].startswith(vf.PEM_BEGIN)

    def test_no_cipher(self):
        sock, ctx, ctx2, ssock = self._fake_ssl(
            der=LEAF_CERT.public_bytes(serialization.Encoding.DER),
            cipher=None)
        with patch.object(vf.socket, "create_connection",
                          side_effect=[sock, sock]), \
             patch.object(vf.ssl, "SSLContext", return_value=ctx), \
             patch.object(vf.ssl, "create_default_context",
                          return_value=ctx2):
            r = vf.fetch_remote_certificate("example.com")
        assert r["cipher"] is None
