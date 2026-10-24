import base64
import uuid
from datetime import datetime, timezone

import pytest
from unittest.mock import MagicMock, patch


# --------------------------------------------------------------------------
# Import application
# --------------------------------------------------------------------------
from app.app import app as flask_app
from app import app as app_module


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
CHAIN_PEM = CERT_PEM + CERT_PEM
SESSION_ID = "11111111-1111-1111-1111-111111111111"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture()
def app():
    flask_app.config.update(TESTING=True, MAX_CONTENT_LENGTH=None)
    yield flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def clean_manager_sessions():
    """Every test starts with an empty manager.sessions mapping."""
    with patch.object(app_module.manager, "sessions", {}):
        yield


@pytest.fixture()
def fake_session():
    """A session as held in memory by ACMEManager."""
    return {
        "session_id": SESSION_ID,
        "domains": ["test.com"],
        "tokens": {"test.com": ["abc"]},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "pending",
        "client": MagicMock(name="acme_client"),
        "client_state": {"some": "state"},
    }


@pytest.fixture()
def fake_persisted_session():
    """A session as returned by session_store.load_session."""
    return {
        "domains": ["test.com"],
        "tokens": {"test.com": ["abc"]},
        "auto_check_status": "pending",
        "auto_check_attempts": 0,
        "auto_check_started_at": None,
        "auto_check_last_at": None,
        "auto_check_last_message": "",
        "client_state": {"some": "state"},
    }


# ==========================================================================
# Helpers: _is_text_content
# ==========================================================================
class TestIsTextContent:
    def _fn(self):
        from app.app import _is_text_content
        return _is_text_content

    @pytest.mark.parametrize("name", ["a.der", "a.pfx", "a.p12",
                                      "a.jks", "a.keystore"])
    def test_binary_extensions_are_not_text(self, name):
        assert self._fn()(name, b"\x00\x01\x02") is False

    @pytest.mark.parametrize("name", ["a.pem", "a.crt", "a.key",
                                      "a.txt", "a.csr", "a.pub"])
    def test_text_extensions_are_text(self, name):
        assert self._fn()(name, b"\x00") is True

    def test_utf8_decodable_content(self):
        assert self._fn()("a.bin", "hello world".encode()) is True

    def test_non_utf8_is_not_text(self):
        assert self._fn()("a.bin", b"\xff\xfe\x00\x01") is False

    def test_mostly_printable(self):
        # 95 of 100 bytes are printable, ratio above 0.9
        content = b"a" * 95 + b"\x00" * 5
        assert self._fn()("a.bin", content) is True

    def test_borderline_not_printable(self):
        # 80 of 100 printable, ratio below 0.9
        content = b"a" * 80 + b"\x00" * 20
        assert self._fn()("a.bin", content) is False

    def test_empty_content(self):
        assert self._fn()("a.bin", b"") is False

    def test_whitespace_only_content(self):
        # Tabs and newlines are allowed as printable control characters
        assert self._fn()("a.bin", b"\r\n\t") is True


# ==========================================================================
# Helpers: _read_convert_payload
# ==========================================================================
class TestReadConvertPayload:
    def _fn(self):
        from app.app import _read_convert_payload
        return _read_convert_payload

    def test_prefers_b64(self):
        fn = self._fn()
        data = {"input_b64": _b64(b"binary"), "input_text": "text"}
        assert fn(data) == b"binary"

    def test_text_fallback(self):
        fn = self._fn()
        assert fn({"input_text": "hello"}) == b"hello"

    def test_empty_raises(self):
        fn = self._fn()
        with pytest.raises(ValueError, match="Provide a file or paste text"):
            fn({})

    def test_bad_base64_raises(self):
        fn = self._fn()
        with pytest.raises(ValueError, match="Invalid base64"):
            fn({"input_b64": "!!!not-base64!!!"})


# ==========================================================================
# UI routes
# ==========================================================================
class TestUI:
    def test_index(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_favicon_served(self, client):
        r = client.get("/favicon.ico")
        # 200 if the file exists, 404 if not, but never 500
        assert r.status_code in (200, 404)


# ==========================================================================
# /api/config
# ==========================================================================
class TestConfig:
    def test_config(self, client):
        r = client.get("/api/config")
        assert r.status_code == 200
        body = r.get_json()
        assert "dns_auto_interval_ms" in body
        assert "dns_auto_max_attempts" in body
        assert "dns_auto_start_delay_ms" in body
        assert "cert_expiry_warn_days" in body
        assert "convert_max_inline_text_bytes" in body
        # No secret leakage
        raw = r.get_data(as_text=True).lower()
        assert "account_email" not in raw
        assert "-----begin" not in raw

    def test_config_env_override(self, client):
        with patch.dict("os.environ", {"DNS_AUTO_INTERVAL_MS": "1234",
                                       "CERT_EXPIRY_WARN_DAYS": "7"}):
            body = client.get("/api/config").get_json()
            assert body["dns_auto_interval_ms"] == 1234
            assert body["cert_expiry_warn_days"] == 7


# ==========================================================================
# /api/create
# ==========================================================================
class TestCreate:
    def test_not_json(self, client):
        r = client.post("/api/create", data="x", content_type="text/plain")
        # request.get_json(silent=True) or {} yields an empty dict
        assert r.status_code == 400
        assert "domain" in r.get_json()["error"].lower()

    def test_no_domains(self, client):
        r = client.post("/api/create", json={})
        assert r.status_code == 400
        assert "domain" in r.get_json()["error"].lower()

    def test_empty_string(self, client):
        r = client.post("/api/create", json={"domains": ""})
        assert r.status_code == 400

    def test_only_commas_and_spaces(self, client):
        r = client.post("/api/create", json={"domains": " , ,, "})
        assert r.status_code == 400

    def test_single_domain(self, client):
        with patch.object(app_module.manager, "create_request",
                          return_value={"test.com": ["tok1"]}) as m:
            r = client.post("/api/create", json={"domains": "test.com"})
            body = r.get_json()
            assert r.status_code == 200
            assert "session_id" in body
            assert body["tokens"] == [{"fqdn": "test.com", "value": "tok1"}]
            args, _ = m.call_args
            assert isinstance(args[0], str)
            assert args[1] == ["test.com"]

    def test_multiple_domains(self, client):
        with patch.object(app_module.manager, "create_request",
                          return_value={"a.com": ["1"], "b.com": ["2"]}):
            body = client.post("/api/create",
                               json={"domains": "a.com,b.com"}).get_json()
            assert len(body["tokens"]) == 2

    def test_trims_whitespace(self, client):
        with patch.object(app_module.manager, "create_request",
                          return_value={}) as m:
            client.post("/api/create",
                        json={"domains": "  a.com , b.com  "})
            assert m.call_args[0][1] == ["a.com", "b.com"]

    def test_wildcard(self, client):
        with patch.object(app_module.manager, "create_request",
                          return_value={"*.test.com": ["v"]}):
            r = client.post("/api/create", json={"domains": "*.test.com"})
            assert r.status_code == 200

    def test_multiple_tokens_per_domain(self, client):
        with patch.object(app_module.manager, "create_request",
                          return_value={"test.com": ["a", "b"]}):
            body = client.post("/api/create",
                               json={"domains": "test.com"}).get_json()
            assert len(body["tokens"]) == 2
            assert {t["value"] for t in body["tokens"]} == {"a", "b"}

    def test_manager_exception(self, client):
        with patch.object(app_module.manager, "create_request",
                          side_effect=RuntimeError("acme down")):
            r = client.post("/api/create", json={"domains": "test.com"})
            assert r.status_code == 500
            assert "acme down" in r.get_json()["error"]

    def test_session_id_is_uuid(self, client):
        with patch.object(app_module.manager, "create_request",
                          return_value={}):
            body = client.post("/api/create",
                               json={"domains": "test.com"}).get_json()
            uuid.UUID(body["session_id"])


# ==========================================================================
# /api/check
# ==========================================================================
class TestCheck:
    def test_missing_session_id(self, client):
        r = client.post("/api/check", json={})
        assert r.status_code == 400
        assert "session_id" in r.get_json()["error"]

    def test_session_not_in_memory(self, client):
        r = client.post("/api/check", json={"session_id": "nope"})
        body = r.get_json()
        # Not an HTTP error, but 200 with success=False
        assert r.status_code == 200
        assert body["success"] is False
        assert "not found" in body["message"].lower()

    def test_client_not_restored(self, client):
        with patch.dict(app_module.manager.sessions, {
            SESSION_ID: {"client": None, "domains": ["test.com"]}
        }):
            r = client.post("/api/check", json={"session_id": SESSION_ID})
            body = r.get_json()
            assert r.status_code == 200
            assert body["success"] is False
            assert "not restored" in body["message"].lower()

    def test_check_success_pending_flipped_to_verified(
            self, client, fake_session, fake_persisted_session):
        with patch.dict(app_module.manager.sessions,
                        {SESSION_ID: fake_session}), \
             patch.object(app_module.manager, "check_dns",
                          return_value=(True, "all resolved")), \
             patch("app.session_store.load_session",
                   return_value=fake_persisted_session), \
             patch("app.session_store.save_session") as save:
            r = client.post("/api/check", json={"session_id": SESSION_ID})
            body = r.get_json()
            assert body["success"] is True
            assert body["message"] == "all resolved"
            saved = save.call_args[0][1]
            assert saved["auto_check_status"] == "verified"
            assert saved["auto_check_last_message"] == "all resolved"

    def test_check_success_but_not_pending_does_not_flip(
            self, client, fake_session, fake_persisted_session):
        fake_persisted_session["auto_check_status"] = "stopped"
        with patch.dict(app_module.manager.sessions,
                        {SESSION_ID: fake_session}), \
             patch.object(app_module.manager, "check_dns",
                          return_value=(True, "ok")), \
             patch("app.session_store.load_session",
                   return_value=fake_persisted_session), \
             patch("app.session_store.save_session") as save:
            client.post("/api/check", json={"session_id": SESSION_ID})
            save.assert_not_called()

    def test_check_failure(self, client, fake_session):
        with patch.dict(app_module.manager.sessions,
                        {SESSION_ID: fake_session}), \
             patch.object(app_module.manager, "check_dns",
                          return_value=(False, "not yet")):
            body = client.post("/api/check",
                               json={"session_id": SESSION_ID}).get_json()
            assert body["success"] is False
            assert body["message"] == "not yet"

    def test_check_success_persisted_session_missing(self, client,
                                                     fake_session):
        # check_dns succeeded but load_session returned None, must not crash
        with patch.dict(app_module.manager.sessions,
                        {SESSION_ID: fake_session}), \
             patch.object(app_module.manager, "check_dns",
                          return_value=(True, "ok")), \
             patch("app.session_store.load_session", return_value=None):
            r = client.post("/api/check", json={"session_id": SESSION_ID})
            assert r.status_code == 200
            assert r.get_json()["success"] is True


# ==========================================================================
# /api/issue
# ==========================================================================
class TestIssue:
    def test_missing_session_id(self, client):
        r = client.post("/api/issue", json={})
        assert r.status_code == 400
        assert "session_id" in r.get_json()["error"]

    def test_session_not_found(self, client):
        r = client.post("/api/issue", json={"session_id": "nope"})
        assert r.status_code == 404
        assert "not found" in r.get_json()["error"].lower()

    def test_client_not_restored(self, client):
        with patch.dict(app_module.manager.sessions, {
            SESSION_ID: {"client": None, "domains": ["test.com"]}
        }):
            r = client.post("/api/issue", json={"session_id": SESSION_ID})
            assert r.status_code == 400
            assert "not restored" in r.get_json()["error"].lower()

    def test_issue_success(self, client, fake_session):
        result = {
            "certificate": CERT_PEM,
            "chain": CHAIN_PEM,
            "private_key": KEY_PEM,
            "cert_path": "/certs/a.crt",
            "chain_path": "/certs/a.chain",
            "key_path": "/certs/a.key",
        }
        with patch.dict(app_module.manager.sessions,
                        {SESSION_ID: fake_session}), \
             patch.object(app_module.manager, "issue_certificate",
                          return_value=result):
            body = client.post("/api/issue",
                               json={"session_id": SESSION_ID}).get_json()
            assert body["success"] is True
            assert body["certificate"] == CERT_PEM
            assert body["chain"] == CHAIN_PEM
            assert body["private_key"] == KEY_PEM
            assert body["paths"]["cert"] == "/certs/a.crt"
            assert body["paths"]["chain"] == "/certs/a.chain"
            assert body["paths"]["key"] == "/certs/a.key"

    def test_issue_value_error_returns_400(self, client, fake_session):
        with patch.dict(app_module.manager.sessions,
                        {SESSION_ID: fake_session}), \
             patch.object(app_module.manager, "issue_certificate",
                          side_effect=ValueError("dns not verified")):
            r = client.post("/api/issue", json={"session_id": SESSION_ID})
            assert r.status_code == 400
            assert "dns not verified" in r.get_json()["error"]

    def test_issue_generic_error_returns_500(self, client, fake_session):
        with patch.dict(app_module.manager.sessions,
                        {SESSION_ID: fake_session}), \
             patch.object(app_module.manager, "issue_certificate",
                          side_effect=RuntimeError("boom")):
            r = client.post("/api/issue", json={"session_id": SESSION_ID})
            assert r.status_code == 500
            assert "boom" in r.get_json()["error"]


# ==========================================================================
# /api/check_status
# ==========================================================================
class TestCheckStatus:
    def test_missing_session_id(self, client):
        r = client.post("/api/check_status", json={})
        assert r.status_code == 400

    def test_not_found(self, client):
        with patch("app.session_store.load_session", return_value=None):
            r = client.post("/api/check_status",
                            json={"session_id": SESSION_ID})
            assert r.status_code == 404
            assert r.get_json()["success"] is False

    def test_pending(self, client, fake_persisted_session):
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session):
            body = client.post("/api/check_status",
                               json={"session_id": SESSION_ID}).get_json()
            assert body["success"] is True
            assert body["status"] == "pending"
            assert body["attempts"] == 0
            assert body["max_attempts"] == 240
            assert body["interval_ms"] == 30000

    @pytest.mark.parametrize("status", ["verified", "failed",
                                        "stopped", "expired"])
    def test_all_statuses(self, client, fake_persisted_session, status):
        fake_persisted_session["auto_check_status"] = status
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session):
            body = client.post("/api/check_status",
                               json={"session_id": SESSION_ID}).get_json()
            assert body["status"] == status

    def test_legacy_unknown(self, client, fake_persisted_session):
        fake_persisted_session.pop("auto_check_status")
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session):
            body = client.post("/api/check_status",
                               json={"session_id": SESSION_ID}).get_json()
            assert body["status"] == "unknown"

    def test_attempts_and_message(self, client, fake_persisted_session):
        fake_persisted_session["auto_check_attempts"] = 12
        fake_persisted_session["auto_check_last_message"] = "not yet"
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session):
            body = client.post("/api/check_status",
                               json={"session_id": SESSION_ID}).get_json()
            assert body["attempts"] == 12
            assert body["last_message"] == "not yet"


# ==========================================================================
# /api/check_auto_toggle
# ==========================================================================
class TestAutoToggle:
    def test_missing_session_id(self, client):
        r = client.post("/api/check_auto_toggle", json={"enabled": True})
        assert r.status_code == 400

    def test_not_found(self, client):
        with patch("app.session_store.load_session", return_value=None):
            r = client.post("/api/check_auto_toggle",
                            json={"session_id": SESSION_ID, "enabled": True})
            assert r.status_code == 404

    def test_pause_pending(self, client, fake_persisted_session):
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session), \
             patch("app.session_store.save_session") as save:
            body = client.post("/api/check_auto_toggle", json={
                "session_id": SESSION_ID, "enabled": False}).get_json()
            assert body["success"] is True
            assert body["status"] == "stopped"
            saved = save.call_args[0][1]
            assert saved["auto_check_status"] == "stopped"

    def test_pause_from_verified_keeps_verified(self, client,
                                                fake_persisted_session):
        fake_persisted_session["auto_check_status"] = "verified"
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session), \
             patch("app.session_store.save_session"):
            body = client.post("/api/check_auto_toggle", json={
                "session_id": SESSION_ID, "enabled": False}).get_json()
            # pause only flips pending to stopped, verified stays verified
            assert body["status"] == "verified"

    @pytest.mark.parametrize("prev", ["failed", "stopped", "expired"])
    def test_resume_resets_attempts(self, client, fake_persisted_session,
                                     prev):
        fake_persisted_session["auto_check_status"] = prev
        fake_persisted_session["auto_check_attempts"] = 99
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session), \
             patch("app.session_store.save_session") as save:
            body = client.post("/api/check_auto_toggle", json={
                "session_id": SESSION_ID, "enabled": True}).get_json()
            assert body["status"] == "pending"
            assert body["attempts"] == 0
            saved = save.call_args[0][1]
            assert saved["auto_check_attempts"] == 0
            assert saved["auto_check_started_at"] is not None
            assert saved["auto_check_last_at"] is None

    def test_enable_after_verified_rejected(self, client,
                                            fake_persisted_session):
        fake_persisted_session["auto_check_status"] = "verified"
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session):
            r = client.post("/api/check_auto_toggle", json={
                "session_id": SESSION_ID, "enabled": True})
            assert r.status_code == 400
            assert r.get_json()["success"] is False

    def test_enable_pending_keeps_attempts(self, client,
                                           fake_persisted_session):
        fake_persisted_session["auto_check_status"] = "pending"
        fake_persisted_session["auto_check_attempts"] = 7
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session), \
             patch("app.session_store.save_session"):
            body = client.post("/api/check_auto_toggle", json={
                "session_id": SESSION_ID, "enabled": True}).get_json()
            assert body["status"] == "pending"
            assert body["attempts"] == 7

    def test_enabled_default_true_when_missing(self, client,
                                               fake_persisted_session):
        fake_persisted_session["auto_check_status"] = "stopped"
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session), \
             patch("app.session_store.save_session"):
            # Missing enabled flag defaults to True
            body = client.post("/api/check_auto_toggle",
                               json={"session_id": SESSION_ID}).get_json()
            assert body["status"] == "pending"


# ==========================================================================
# /api/sessions
# ==========================================================================
class TestSessions:
    def test_list(self, client):
        with patch("app.session_store.list_metadata",
                   return_value=[{"session_id": "a"},
                                 {"session_id": "b"}]):
            body = client.get("/api/sessions").get_json()
            assert body["success"] is True
            assert len(body["sessions"]) == 2

    def test_get_from_memory(self, client, fake_session):
        with patch.dict(app_module.manager.sessions,
                        {SESSION_ID: fake_session}):
            body = client.get(f"/api/sessions/{SESSION_ID}").get_json()
            assert body["success"] is True
            assert body["session_id"] == SESSION_ID
            assert body["has_client"] is True

    def test_get_not_found(self, client):
        with patch("app.session_store.load_session", return_value=None):
            r = client.get(f"/api/sessions/{SESSION_ID}")
            assert r.status_code == 404

    def test_get_restored_from_disk(self, client, fake_persisted_session):
        fake_persisted_session["client"] = None
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session), \
             patch("app.acme_manager._client_from_state",
                   return_value=MagicMock()):
            body = client.get(f"/api/sessions/{SESSION_ID}").get_json()
            assert body["success"] is True
            assert body["has_client"] is True

    def test_get_restored_but_rebuild_fails(self, client,
                                            fake_persisted_session):
        fake_persisted_session["client"] = None
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session), \
             patch("app.acme_manager._client_from_state",
                   side_effect=RuntimeError("no key")):
            r = client.get(f"/api/sessions/{SESSION_ID}")
            # Rebuild failed, but the session is still returned
            assert r.status_code == 200
            assert r.get_json()["has_client"] is False

    def test_get_without_client_state(self, client, fake_persisted_session):
        fake_persisted_session.pop("client_state")
        with patch("app.session_store.load_session",
                   return_value=fake_persisted_session):
            body = client.get(f"/api/sessions/{SESSION_ID}").get_json()
            assert body["success"] is True
            assert body["has_client"] is False

    def test_delete(self, client):
        with patch.object(app_module.manager, "sessions",
                          {SESSION_ID: {}}), \
             patch("app.session_store.delete_session") as delete:
            r = client.delete(f"/api/sessions/{SESSION_ID}")
            assert r.get_json()["success"] is True
            delete.assert_called_once_with(SESSION_ID)

    def test_session_public_fields(self, client, fake_session):
        with patch.dict(app_module.manager.sessions,
                        {SESSION_ID: fake_session}):
            body = client.get(f"/api/sessions/{SESSION_ID}").get_json()
            for key in ("session_id", "domains", "tokens",
                        "created_at", "status", "has_client"):
                assert key in body
            # The client object must not be serialized
            assert "client" not in body


# ==========================================================================
# /api/build_chain
# ==========================================================================
class TestBuildChain:
    def test_missing_certificate(self, client):
        r = client.post("/api/build_chain", json={})
        assert r.status_code == 400
        body = r.get_json()
        assert body["success"] is False
        for key in ("errors", "chain", "warnings", "found_root",
                    "root_included", "excluded_root", "complete"):
            assert key in body

    def test_default_include_root_false(self, client):
        fake = {"success": True, "chain": [], "errors": [],
                "warnings": [], "found_root": False,
                "root_included": False, "complete": False}
        with patch("app.app.build_certificate_chain",
                   return_value=fake) as m:
            r = client.post("/api/build_chain",
                            json={"certificate": CERT_PEM})
            assert r.status_code == 200
            assert r.get_json() == fake
            _, kwargs = m.call_args
            assert kwargs.get("include_root") is False

    def test_include_root_true(self, client):
        with patch("app.app.build_certificate_chain",
                   return_value={"success": True}) as m:
            client.post("/api/build_chain",
                        json={"certificate": CERT_PEM,
                              "include_root": True})
            _, kwargs = m.call_args
            assert kwargs.get("include_root") is True

    def test_build_exception(self, client):
        with patch("app.app.build_certificate_chain",
                   side_effect=RuntimeError("aia down")):
            r = client.post("/api/build_chain",
                            json={"certificate": CERT_PEM})
            assert r.status_code == 500
            body = r.get_json()
            assert body["success"] is False
            assert "aia down" in body["errors"][0]

    def test_strips_whitespace(self, client):
        with patch("app.app.build_certificate_chain",
                   return_value={"success": True}) as m:
            client.post("/api/build_chain",
                        json={"certificate": "  \n" + CERT_PEM + "\n  "})
            assert m.call_args[0][0] == CERT_PEM.strip()

    def test_whitespace_only_certificate(self, client):
        r = client.post("/api/build_chain",
                        json={"certificate": "   \n  "})
        assert r.status_code == 400


# ==========================================================================
# /api/verify
# ==========================================================================
class TestVerify:
    def test_missing_certificate(self, client):
        r = client.post("/api/verify", json={})
        assert r.status_code == 400
        assert r.get_json()["success"] is False

    def test_cert_only(self, client):
        fake = {"success": True, "certificate": {}, "chain": {},
                "errors": [], "warnings": []}
        with patch("app.app.verify_inputs", return_value=fake) as m:
            body = client.post("/api/verify",
                               json={"certificate": CERT_PEM}).get_json()
            assert body["success"] is True
            args = m.call_args[0]
            assert args[0] == CERT_PEM
            assert args[1] == ""
            assert args[2] == ""

    def test_cert_chain_key(self, client):
        with patch("app.app.verify_inputs",
                   return_value={"success": True}) as m:
            client.post("/api/verify", json={
                "certificate": CERT_PEM,
                "chain": CHAIN_PEM,
                "private_key": KEY_PEM,
            })
            args = m.call_args[0]
            assert args == (CERT_PEM, CHAIN_PEM, KEY_PEM)

    def test_verify_exception(self, client):
        with patch("app.app.verify_inputs",
                   side_effect=ValueError("bad pem")):
            r = client.post("/api/verify", json={"certificate": CERT_PEM})
            assert r.status_code == 500
            body = r.get_json()
            assert body["success"] is False
            assert "bad pem" in body["errors"][0]


# ==========================================================================
# /api/globalsign-intermediates
# ==========================================================================
class TestGlobalsign:
    def test_groups(self, client):
        groups = [{"name": "g1", "items": [{"name": "a"},
                                            {"name": "b"}]}]
        with patch("app.app.grouped_catalog", return_value=groups):
            body = client.get("/api/globalsign-intermediates").get_json()
            assert body["success"] is True
            assert body["groups"] == groups

    def test_empty(self, client):
        with patch("app.app.grouped_catalog", return_value=[]):
            body = client.get("/api/globalsign-intermediates").get_json()
            assert body["groups"] == []


# ==========================================================================
# /api/check_live
# ==========================================================================
class TestCheckLive:
    def test_missing_hostname(self, client):
        r = client.post("/api/check_live", json={})
        assert r.status_code == 400
        assert r.get_json()["success"] is False

    def _fetch_ok(self, hostname="example.com", port=443):
        return {
            "ok": True,
            "hostname": hostname,
            "port": port,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "verify_ok": True,
            "verify_error": None,
            "chain_pem": [CERT_PEM, CERT_PEM],
        }

    def test_ok(self, client):
        with patch("app.app.fetch_remote_certificate",
                   return_value=self._fetch_ok()), \
             patch("app.app.verify_inputs",
                   return_value={"success": True, "errors": []}):
            body = client.post("/api/check_live",
                               json={"hostname": "example.com"}).get_json()
            assert body["success"] is True
            assert body["connection"]["tls_version"] == "TLSv1.3"
            assert body["connection"]["verify_ok"] is True
            assert body["chain_pem"] == [CERT_PEM, CERT_PEM]

    def test_default_port_443(self, client):
        with patch("app.app.fetch_remote_certificate",
                   return_value=self._fetch_ok()) as m, \
             patch("app.app.verify_inputs",
                   return_value={"success": True}):
            client.post("/api/check_live", json={"hostname": "example.com"})
            _, kwargs = m.call_args
            assert kwargs.get("port") == 443

    def test_custom_port(self, client):
        with patch("app.app.fetch_remote_certificate",
                   return_value=self._fetch_ok(port=8443)) as m, \
             patch("app.app.verify_inputs",
                   return_value={"success": True}):
            client.post("/api/check_live",
                        json={"hostname": "example.com:8443"})
            _, kwargs = m.call_args
            assert kwargs.get("port") == 8443

    def test_non_numeric_port_kept_as_part_of_hostname(self, client):
        with patch("app.app.fetch_remote_certificate",
                   return_value=self._fetch_ok()) as m, \
             patch("app.app.verify_inputs",
                   return_value={"success": True}):
            client.post("/api/check_live",
                        json={"hostname": "example.com:abc"})
            args, kwargs = m.call_args
            # Non-numeric suffix stays in the hostname, default port used
            assert args[0] == "example.com:abc"
            assert kwargs.get("port") == 443

    def test_strips_scheme_and_path(self, client):
        with patch("app.app.fetch_remote_certificate",
                   return_value=self._fetch_ok()) as m, \
             patch("app.app.verify_inputs",
                   return_value={"success": True}):
            client.post("/api/check_live",
                        json={"hostname": "https://example.com/foo/bar"})
            args, _ = m.call_args
            assert args[0] == "example.com"

    def test_strips_trailing_whitespace(self, client):
        with patch("app.app.fetch_remote_certificate",
                   return_value=self._fetch_ok()) as m, \
             patch("app.app.verify_inputs",
                   return_value={"success": True}):
            client.post("/api/check_live",
                        json={"hostname": "  example.com  "})
            args, _ = m.call_args
            assert args[0] == "example.com"

    def test_fetch_exception(self, client):
        with patch("app.app.fetch_remote_certificate",
                   side_effect=OSError("connect timeout")):
            r = client.post("/api/check_live",
                            json={"hostname": "example.com"})
            assert r.status_code == 500
            assert r.get_json()["success"] is False
            assert "connect timeout" in r.get_json()["errors"][0]

    def test_fetch_returns_not_ok(self, client):
        with patch("app.app.fetch_remote_certificate",
                   return_value={"ok": False,
                                 "connect_error": "refused"}):
            r = client.post("/api/check_live",
                            json={"hostname": "example.com"})
            assert r.status_code == 200
            body = r.get_json()
            assert body["success"] is False
            assert "refused" in body["errors"][0]

    def test_fetch_returns_empty_chain(self, client):
        fetched = self._fetch_ok()
        fetched["chain_pem"] = []
        with patch("app.app.fetch_remote_certificate",
                   return_value=fetched):
            r = client.post("/api/check_live",
                            json={"hostname": "example.com"})
            body = r.get_json()
            assert body["success"] is False
            assert "did not present" in body["errors"][0]

    def test_leaf_and_chain_split(self, client):
        with patch("app.app.fetch_remote_certificate",
                   return_value=self._fetch_ok()), \
             patch("app.app.verify_inputs",
                   return_value={"success": True}) as m:
            client.post("/api/check_live", json={"hostname": "example.com"})
            args = m.call_args[0]
            # leaf is the first item, chain is everything after joined
            assert args[0] == CERT_PEM
            assert args[1] == CERT_PEM
            assert args[2] == ""


# ==========================================================================
# /api/convert/inspect
# ==========================================================================
class TestConvertInspect:
    def test_no_input_returns_400(self, client):
        r = client.post("/api/convert/inspect", json={})
        assert r.status_code == 400
        assert r.get_json()["success"] is False

    def test_invalid_base64_returns_400(self, client):
        r = client.post("/api/convert/inspect",
                        json={"input_b64": "!!!bad!!!"})
        assert r.status_code == 400
        assert "base64" in r.get_json()["error"].lower()

    def test_ok_from_text(self, client):
        summary = {"source_format": "pem", "items": []}
        with patch("app.app.parse_anything",
                   return_value=MagicMock()) as parse, \
             patch("app.app.bundle_summary", return_value=summary):
            body = client.post("/api/convert/inspect",
                               json={"input_text": "hello"}).get_json()
            assert body["success"] is True
            assert body["source_format"] == "pem"
            assert parse.call_args[0][0] == b"hello"

    def test_ok_from_b64(self, client):
        summary = {"source_format": "pem", "items": []}
        with patch("app.app.parse_anything",
                   return_value=MagicMock()) as parse, \
             patch("app.app.bundle_summary", return_value=summary):
            client.post("/api/convert/inspect",
                        json={"input_b64": _b64(b"raw")})
            assert parse.call_args[0][0] == b"raw"

    def test_password_forwarded(self, client):
        with patch("app.app.parse_anything",
                   return_value=MagicMock()) as parse, \
             patch("app.app.bundle_summary", return_value={}):
            client.post("/api/convert/inspect",
                        json={"input_text": "x", "password": "s3cret"})
            assert parse.call_args[0][1] == "s3cret"

    def test_parse_exception_returns_500(self, client):
        with patch("app.app.parse_anything",
                   side_effect=ValueError("cannot parse")):
            r = client.post("/api/convert/inspect",
                            json={"input_text": "x"})
            assert r.status_code == 500
            assert r.get_json()["success"] is False
            assert "cannot parse" in r.get_json()["error"]


# ==========================================================================
# /api/convert/output
# ==========================================================================
class TestConvertOutput:
    def test_missing_target(self, client):
        r = client.post("/api/convert/output",
                        json={"input_text": "x"})
        assert r.status_code == 400
        assert "target" in r.get_json()["error"].lower()

    def test_missing_input(self, client):
        r = client.post("/api/convert/output",
                        json={"target": "pem-separate"})
        assert r.status_code == 400

    @pytest.mark.parametrize("target", ["pkcs12", "pkcs12-p12",
                                        "pkcs12-b64"])
    def test_pkcs12_requires_password(self, client, target):
        r = client.post("/api/convert/output",
                        json={"input_text": "x", "target": target})
        assert r.status_code == 400
        assert "password" in r.get_json()["error"].lower()

    @pytest.mark.parametrize("target", ["pkcs12", "pkcs12-p12",
                                        "pkcs12-b64"])
    def test_pkcs12_password_mismatch(self, client, target):
        r = client.post("/api/convert/output", json={
            "input_text": "x", "target": target,
            "output_password": "a", "output_password_confirm": "b",
        })
        assert r.status_code == 400
        assert "match" in r.get_json()["error"].lower()

    def test_non_pkcs12_ignores_password_fields(self, client):
        with patch("app.app.parse_anything",
                   return_value=MagicMock()), \
             patch("app.app.serialize_bundle",
                   return_value={"certificate.crt": b"PEM"}) as ser:
            client.post("/api/convert/output", json={
                "input_text": "x", "target": "pem-separate",
                "output_password": "leak",
                "output_password_confirm": "leak",
                "friendly_name": "leak",
            })
            kwargs = ser.call_args.kwargs
            assert kwargs["output_password"] == ""
            assert kwargs["friendly_name"] == ""

    def test_pkcs12_passes_password(self, client):
        with patch("app.app.parse_anything",
                   return_value=MagicMock()), \
             patch("app.app.serialize_bundle",
                   return_value={"certificate.pfx": b"bin"}) as ser:
            client.post("/api/convert/output", json={
                "input_text": "x", "target": "pkcs12",
                "output_password": "pw",
                "output_password_confirm": "pw",
                "friendly_name": "my-cert",
            })
            kwargs = ser.call_args.kwargs
            assert kwargs["output_password"] == "pw"
            assert kwargs["friendly_name"] == "my-cert"

    def test_parse_error_returns_500(self, client):
        with patch("app.app.parse_anything",
                   side_effect=RuntimeError("bad input")):
            r = client.post("/api/convert/output",
                            json={"input_text": "x",
                                  "target": "pem-separate"})
            assert r.status_code == 500
            assert "bad input" in r.get_json()["error"]

    def test_serialize_value_error_returns_400(self, client):
        with patch("app.app.parse_anything",
                   return_value=MagicMock()), \
             patch("app.app.serialize_bundle",
                   side_effect=ValueError("cannot serialize")):
            r = client.post("/api/convert/output",
                            json={"input_text": "x",
                                  "target": "der"})
            assert r.status_code == 400
            assert "cannot serialize" in r.get_json()["error"]

    def test_serialize_generic_error_returns_500(self, client):
        with patch("app.app.parse_anything",
                   return_value=MagicMock()), \
             patch("app.app.serialize_bundle",
                   side_effect=RuntimeError("crash")):
            r = client.post("/api/convert/output",
                            json={"input_text": "x",
                                  "target": "der"})
            assert r.status_code == 500

    def test_output_includes_text_for_small_text_files(self, client):
        payload = b"-----BEGIN CERTIFICATE-----\nPEM\n"
        with patch("app.app.parse_anything",
                   return_value=MagicMock()), \
             patch("app.app.serialize_bundle",
                   return_value={"certificate.crt": payload}):
            body = client.post("/api/convert/output",
                               json={"input_text": "x",
                                     "target": "pem-separate"}).get_json()
            f = body["files"][0]
            assert f["text"] == payload.decode()
            assert f["b64"] == _b64(payload)
            assert f["size"] == len(payload)

    def test_output_omits_text_for_binary_files(self, client):
        payload = b"\x00\x01\x02"
        with patch("app.app.parse_anything",
                   return_value=MagicMock()), \
             patch("app.app.serialize_bundle",
                   return_value={"certificate.der": payload}):
            body = client.post("/api/convert/output",
                               json={"input_text": "x",
                                     "target": "der"}).get_json()
            assert body["files"][0]["text"] is None

    def test_output_omits_text_for_large_text_files(self, client):
        payload = b"a" * (app_module.CONVERT_MAX_INLINE_TEXT_BYTES + 1)
        with patch("app.app.parse_anything",
                   return_value=MagicMock()), \
             patch("app.app.serialize_bundle",
                   return_value={"certificate.pem": payload}):
            body = client.post("/api/convert/output",
                               json={"input_text": "x",
                                     "target": "pem-bundle"}).get_json()
            assert body["files"][0]["text"] is None

    def test_output_handles_multiple_files(self, client):
        with patch("app.app.parse_anything",
                   return_value=MagicMock()), \
             patch("app.app.serialize_bundle",
                   return_value={
                       "certificate.crt": b"CERT",
                       "chain.crt": b"CHAIN",
                       "private.key": b"KEY",
                   }):
            body = client.post("/api/convert/output",
                               json={"input_text": "x",
                                     "target": "pem-separate"}).get_json()
            names = {f["name"] for f in body["files"]}
            assert names == {"certificate.crt", "chain.crt", "private.key"}
            for f in body["files"]:
                assert f["b64"]
                assert "size" in f


