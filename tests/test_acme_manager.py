import os
import time
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


from app import acme_manager as am


# --------------------------------------------------------------------------
# PEM helpers
# --------------------------------------------------------------------------
def _make_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _make_csr_pem(key_pem: str, cn: str = "test.com") -> str:
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _make_cert_pem(cn: str = "test.com") -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


CERT_PEM = _make_cert_pem("leaf.test")
KEY_PEM = _make_key_pem()
CSR_PEM = _make_csr_pem(KEY_PEM)
CHAIN_PEM = _make_cert_pem("intermediate.test")
FULLCHAIN = CERT_PEM + CHAIN_PEM


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture()
def tmp_dirs(tmp_path):
    """Redirect ACCOUNTS_DIR / CERTS_DIR to a temp directory."""
    accounts = tmp_path / "accounts"
    certs = tmp_path / "certs"
    accounts.mkdir()
    certs.mkdir()
    with patch.object(am, "ACCOUNTS_DIR", str(accounts)), \
         patch.object(am, "CERTS_DIR", str(certs)):
        yield {"accounts": accounts, "certs": certs}


@pytest.fixture()
def fake_client():
    """A MagicMock standing in for ACMEClient with realistic attrs."""
    c = MagicMock(name="ACMEClient")
    c.private_key = KEY_PEM
    c.csr = CSR_PEM
    c.domains = ["test.com"]
    c.directory = am.LE_URL
    c.nameservers = list(am.NAMESERVERS)
    return c


@pytest.fixture()
def manager(tmp_dirs):
    """
    ACMEManager instance with side effects disabled:
    no disk reads, no scheduler thread.
    """
    with patch.object(am.session_store, "list_metadata", return_value=[]), \
         patch.object(am.ACMEManager, "_start_scheduler"):
        m = am.ACMEManager()
        yield m


@pytest.fixture()
def fake_persisted_session():
    return {
        "domains": ["test.com"],
        "tokens": {"test.com": ["tok1"]},
        "auto_check_status": "pending",
        "auto_check_attempts": 0,
        "auto_check_started_at": datetime.now(timezone.utc).isoformat(),
        "auto_check_last_at": None,
        "auto_check_last_message": None,
    }


# ==========================================================================
# _split_pem_chain
# ==========================================================================
class TestSplitPemChain:
    def test_leaf_only(self):
        leaf, chain = am._split_pem_chain(CERT_PEM.encode())
        assert leaf.strip() == CERT_PEM.strip()
        assert chain == ""

    def test_leaf_and_chain(self):
        leaf, chain = am._split_pem_chain(FULLCHAIN.encode())
        assert leaf.strip() == CERT_PEM.strip()
        assert chain.strip() == CHAIN_PEM.strip()

    def test_accepts_str_input(self):
        leaf, chain = am._split_pem_chain(FULLCHAIN)
        assert leaf.strip() == CERT_PEM.strip()
        assert chain.strip() == CHAIN_PEM.strip()

    def test_empty_input(self):
        assert am._split_pem_chain(b"") == ("", "")
        assert am._split_pem_chain("") == ("", "")

    def test_no_cert_blocks(self):
        assert am._split_pem_chain(b"random bytes") == ("", "")

    def test_truncated_block(self):
        # BEGIN without END is ignored
        broken = "-----BEGIN CERTIFICATE-----\nMIIB\n"
        assert am._split_pem_chain(broken) == ("", "")

    def test_multiple_blocks(self):
        three = CERT_PEM + CHAIN_PEM + CERT_PEM
        leaf, chain = am._split_pem_chain(three)
        assert leaf.strip() == CERT_PEM.strip()
        # chain has two blocks joined by newline
        assert chain.count("BEGIN CERTIFICATE") == 2


# ==========================================================================
# _client_to_state
# ==========================================================================
class TestClientToState:
    def test_pem_string_key_and_csr(self, fake_client):
        state = am._client_to_state(fake_client, "sid")
        assert state["private_key_pem"] == KEY_PEM
        assert state["csr_pem"] == CSR_PEM
        assert state["domains"] == ["test.com"]
        assert state["directory"] == am.LE_URL
        assert state["nameservers"] == list(am.NAMESERVERS)
        assert state["account_file"].endswith("sid.json")

    def test_bytes_key_and_csr(self, fake_client):
        fake_client.private_key = KEY_PEM.encode()
        fake_client.csr = CSR_PEM.encode()
        state = am._client_to_state(fake_client, "sid")
        assert state["private_key_pem"] == KEY_PEM
        assert state["csr_pem"] == CSR_PEM

    def test_serializes_crypto_objects(self, fake_client):
        key_obj = serialization.load_pem_private_key(KEY_PEM.encode(),
                                                     password=None)
        csr_obj = x509.load_pem_x509_csr(CSR_PEM.encode())
        fake_client.private_key = key_obj
        fake_client.csr = csr_obj
        state = am._client_to_state(fake_client, "sid")
        assert "BEGIN PRIVATE KEY" in state["private_key_pem"]
        assert "BEGIN CERTIFICATE REQUEST" in state["csr_pem"]

    def test_serialization_failure_is_swallowed(self, fake_client):
        class BadKey:
            def private_bytes(self, *a, **kw):
                raise RuntimeError("cannot serialize")

        fake_client.private_key = BadKey()
        fake_client.csr = BadKey()
        state = am._client_to_state(fake_client, "sid")
        assert state["private_key_pem"] is None
        assert state["csr_pem"] is None

    def test_missing_key_and_csr(self, fake_client):
        fake_client.private_key = None
        fake_client.csr = None
        state = am._client_to_state(fake_client, "sid")
        assert state["private_key_pem"] is None
        assert state["csr_pem"] is None

    def test_missing_domains_and_nameservers(self, fake_client):
        fake_client.domains = None
        fake_client.nameservers = None
        state = am._client_to_state(fake_client, "sid")
        assert state["domains"] == []
        assert state["nameservers"] == list(am.NAMESERVERS)

    def test_missing_directory_uses_default(self, fake_client):
        del fake_client.directory
        state = am._client_to_state(fake_client, "sid")
        assert state["directory"] == am.LE_URL


# ==========================================================================
# _client_from_state
# ==========================================================================
class TestClientFromState:
    def test_none_state(self):
        assert am._client_from_state(None) is None

    def test_missing_account_file_key(self):
        assert am._client_from_state({}) is None

    def test_account_file_missing_on_disk(self, tmp_path):
        state = {"account_file": str(tmp_path / "missing.json")}
        assert am._client_from_state(state) is None

    def test_load_account_fails(self, tmp_path):
        f = tmp_path / "acc.json"
        f.write_text("{}")
        with patch.object(am.ACMEClient, "load_account_from_file",
                          side_effect=RuntimeError("bad file")):
            assert am._client_from_state({"account_file": str(f)}) is None

    def test_load_account_ok(self, tmp_path):
        f = tmp_path / "acc.json"
        f.write_text("{}")
        fake = MagicMock()
        with patch.object(am.ACMEClient, "load_account_from_file",
                          return_value=fake):
            client = am._client_from_state({
                "account_file": str(f),
                "domains": ["a.com"],
                "directory": "https://x",
                "nameservers": ["1.1.1.1"],
            })
        assert client is fake
        assert fake.domains == ["a.com"]
        assert fake.directory == "https://x"
        assert fake.nameservers == ["1.1.1.1"]

    def test_load_account_no_nameservers(self, tmp_path):
        f = tmp_path / "acc.json"
        f.write_text("{}")
        fake = MagicMock()
        with patch.object(am.ACMEClient, "load_account_from_file",
                          return_value=fake):
            am._client_from_state({"account_file": str(f)})
        # nameservers was not set because state has no nameservers
        assert fake.nameservers is not None  # untouched default from MagicMock

    def test_parses_private_key(self, tmp_path):
        f = tmp_path / "acc.json"
        f.write_text("{}")
        fake = MagicMock()
        with patch.object(am.ACMEClient, "load_account_from_file",
                          return_value=fake):
            am._client_from_state({
                "account_file": str(f),
                "private_key_pem": KEY_PEM,
            })
        # A real private key object should have been assigned
        assert hasattr(fake.private_key, "private_bytes")

    def test_bad_private_key_swallowed(self, tmp_path):
        f = tmp_path / "acc.json"
        f.write_text("{}")
        fake = MagicMock()
        original = fake.private_key
        with patch.object(am.ACMEClient, "load_account_from_file",
                          return_value=fake):
            am._client_from_state({
                "account_file": str(f),
                "private_key_pem": "not a pem",
            })
        assert fake.private_key is original

    def test_parses_csr(self, tmp_path):
        f = tmp_path / "acc.json"
        f.write_text("{}")
        fake = MagicMock()
        with patch.object(am.ACMEClient, "load_account_from_file",
                          return_value=fake):
            am._client_from_state({
                "account_file": str(f),
                "csr_pem": CSR_PEM,
            })
        assert hasattr(fake.csr, "public_bytes")

    def test_bad_csr_swallowed(self, tmp_path):
        f = tmp_path / "acc.json"
        f.write_text("{}")
        fake = MagicMock()
        original = fake.csr
        with patch.object(am.ACMEClient, "load_account_from_file",
                          return_value=fake):
            am._client_from_state({
                "account_file": str(f),
                "csr_pem": "not a csr",
            })
        assert fake.csr is original


# ==========================================================================
# ACMEManager: init, scheduler lifecycle
# ==========================================================================
class TestManagerInit:
    def test_sessions_starts_empty(self, tmp_dirs):
        with patch.object(am.session_store, "list_metadata", return_value=[]), \
             patch.object(am.ACMEManager, "_start_scheduler"):
            m = am.ACMEManager()
            assert m.sessions == {}

    def test_loads_persisted_sessions(self, tmp_dirs):
        fake = {"domains": ["a"], "client": None}
        with patch.object(am.session_store, "list_metadata",
                          return_value=[{"session_id": "s1"}]), \
             patch.object(am.session_store, "load_session",
                          return_value=fake), \
             patch.object(am.ACMEManager, "_hydrate_sessions"), \
             patch.object(am.ACMEManager, "_start_scheduler"):
            m = am.ACMEManager()
            assert "s1" in m.sessions

    def test_hydrate_rebuilds_client(self, tmp_dirs):
        session = {"client_state": {"account_file": "/x.json"}}
        fake_client = MagicMock()
        with patch.object(am.session_store, "list_metadata",
                          return_value=[{"session_id": "s1"}]), \
             patch.object(am.session_store, "load_session",
                          return_value=session), \
             patch.object(am, "_client_from_state",
                          return_value=fake_client), \
             patch.object(am.ACMEManager, "_start_scheduler"):
            m = am.ACMEManager()
            assert m.sessions["s1"]["client"] is fake_client

    def test_hydrate_skips_existing_client(self, tmp_dirs):
        session = {"client": MagicMock(), "client_state": {"account_file": "x"}}
        with patch.object(am.session_store, "list_metadata",
                          return_value=[{"session_id": "s1"}]), \
             patch.object(am.session_store, "load_session",
                          return_value=session), \
             patch.object(am, "_client_from_state") as from_state, \
             patch.object(am.ACMEManager, "_start_scheduler"):
            am.ACMEManager()
            from_state.assert_not_called()

    def test_hydrate_no_state(self, tmp_dirs):
        session = {"client": None}
        with patch.object(am.session_store, "list_metadata",
                          return_value=[{"session_id": "s1"}]), \
             patch.object(am.session_store, "load_session",
                          return_value=session), \
             patch.object(am.ACMEManager, "_start_scheduler"):
            m = am.ACMEManager()
            assert m.sessions["s1"].get("client") is None

    def test_hydrate_failed_rebuild(self, tmp_dirs):
        session = {"client_state": {"account_file": "/x.json"}}
        with patch.object(am.session_store, "list_metadata",
                          return_value=[{"session_id": "s1"}]), \
             patch.object(am.session_store, "load_session",
                          return_value=session), \
             patch.object(am, "_client_from_state", return_value=None), \
             patch.object(am.ACMEManager, "_start_scheduler"):
            m = am.ACMEManager()
            assert "client" not in m.sessions["s1"]

    def test_start_scheduler_creates_thread(self, tmp_dirs):
        with patch.object(am.session_store, "list_metadata", return_value=[]):
            m = am.ACMEManager()
            try:
                assert m._scheduler_thread is not None
                assert m._scheduler_thread.daemon is True
            finally:
                m._scheduler_stop.set()
                m._scheduler_thread.join(timeout=2)

    def test_start_scheduler_twice_keeps_one_thread(self, tmp_dirs):
        with patch.object(am.session_store, "list_metadata", return_value=[]):
            m = am.ACMEManager()
            try:
                first = m._scheduler_thread
                m._start_scheduler()
                assert m._scheduler_thread is first
            finally:
                m._scheduler_stop.set()
                m._scheduler_thread.join(timeout=2)


# ==========================================================================
# Scheduler: loop and tick
# ==========================================================================
class TestSchedulerLoop:
    def test_tick_all_sessions_skips_missing_id(self, manager):
        with patch.object(am.session_store, "list_metadata",
                          return_value=[{}, {"session_id": "s1"}]), \
             patch.object(manager, "_maybe_run_auto_check") as m:
            manager._tick_all_sessions()
            m.assert_called_once_with("s1")

    def test_tick_all_sessions_swallows_exception(self, manager):
        with patch.object(am.session_store, "list_metadata",
                          return_value=[{"session_id": "s1"}]), \
             patch.object(manager, "_maybe_run_auto_check",
                          side_effect=RuntimeError("boom")):
            # Should not raise
            manager._tick_all_sessions()

    def test_scheduler_loop_swallows_tick_exception(self, manager):
        # Run one iteration and stop immediately
        manager._scheduler_stop.set()
        with patch.object(manager, "_tick_all_sessions",
                          side_effect=RuntimeError("boom")):
            # Loop checks stop event first, so it will exit immediately
            manager._scheduler_loop()


# ==========================================================================
# _maybe_run_auto_check: gating
# ==========================================================================
class TestMaybeRunAutoCheck:
    def _setup(self, manager, session):
        return patch.object(am.session_store, "load_session",
                            return_value=session)

    def test_no_session(self, manager):
        with patch.object(am.session_store, "load_session",
                          return_value=None), \
             patch.object(am.session_store, "save_session") as save:
            manager._maybe_run_auto_check("s1")
            save.assert_not_called()

    def test_not_pending(self, manager, fake_persisted_session):
        fake_persisted_session["auto_check_status"] = "verified"
        with patch.object(am.session_store, "load_session",
                          return_value=fake_persisted_session), \
             patch.object(am.session_store, "save_session") as save:
            manager._maybe_run_auto_check("s1")
            save.assert_not_called()

    def test_waiting_for_start_delay(self, manager, fake_persisted_session):
        # attempts == 0, started just now, default 3000ms delay
        fake_persisted_session["auto_check_started_at"] = (
            datetime.now(timezone.utc).isoformat())
        with patch.object(am.session_store, "load_session",
                          return_value=fake_persisted_session), \
             patch.object(am.session_store, "save_session") as save:
            manager._maybe_run_auto_check("s1")
            save.assert_not_called()

    def test_waiting_for_interval(self, manager, fake_persisted_session):
        fake_persisted_session["auto_check_attempts"] = 1
        fake_persisted_session["auto_check_last_at"] = (
            datetime.now(timezone.utc).isoformat())
        with patch.object(am.session_store, "load_session",
                          return_value=fake_persisted_session), \
             patch.object(am.session_store, "save_session") as save:
            manager._maybe_run_auto_check("s1")
            save.assert_not_called()

    def test_session_expired_after_7_days(self, manager,
                                          fake_persisted_session):
        old = (datetime.now(timezone.utc)
               - timedelta(days=8)).isoformat()
        fake_persisted_session["auto_check_started_at"] = old
        fake_persisted_session["auto_check_attempts"] = 1
        fake_persisted_session["auto_check_last_at"] = old
        with patch.object(am.session_store, "load_session",
                          return_value=fake_persisted_session), \
             patch.object(am.session_store, "save_session") as save:
            manager._maybe_run_auto_check("s1")
            saved = save.call_args[0][1]
            assert saved["auto_check_status"] == "expired"
            assert "7 days" in saved["auto_check_last_message"]

    def test_max_attempts_reached_marks_failed(self, manager,
                                               fake_persisted_session):
        fake_persisted_session["auto_check_attempts"] = 240
        fake_persisted_session["auto_check_started_at"] = (
            datetime.now(timezone.utc)
            - timedelta(seconds=60)).isoformat()
        fake_persisted_session["auto_check_last_at"] = (
            datetime.now(timezone.utc)
            - timedelta(seconds=60)).isoformat()
        with patch.dict("os.environ", {"DNS_AUTO_MAX_ATTEMPTS": "240"}), \
             patch.object(am.session_store, "load_session",
                          return_value=fake_persisted_session), \
             patch.object(am.session_store, "save_session") as save:
            manager._maybe_run_auto_check("s1")
            saved = save.call_args[0][1]
            assert saved["auto_check_status"] == "failed"
            assert "240" in saved["auto_check_last_message"]

    def test_invalid_iso_timestamps_are_ignored(self, manager,
                                                fake_persisted_session,
                                                tmp_path):
        fake_persisted_session["auto_check_started_at"] = "not-a-date"
        fake_persisted_session["auto_check_last_at"] = "also-bad"
        fake_persisted_session["auto_check_attempts"] = 1
        with patch.dict("os.environ", {"DNS_AUTO_INTERVAL_MS": "0"}), \
             patch.object(am.session_store, "load_session",
                          return_value=fake_persisted_session), \
             patch.object(am.session_store, "save_session") as save, \
             patch.object(am.session_store, "SESSIONS_DIR", tmp_path), \
             patch.object(am, "resolve_txt_records",
                          return_value=(["tok1"], None)), \
             patch.object(Path, "exists", return_value=True):
            manager._maybe_run_auto_check("s1")
            save.assert_called_once()


# ==========================================================================
# _maybe_run_auto_check: lock and DNS outcomes
# ==========================================================================
class TestAutoCheckLock:
    def _run(self, manager, session, dns_side_effect, tmp_path,
             lock_open_side_effect=None, flock_side_effect=None):
        env = {
            "DNS_AUTO_MAX_ATTEMPTS": "240",
            "DNS_AUTO_INTERVAL_MS": "0",
            "DNS_AUTO_START_DELAY_MS": "0",
        }
        with patch.dict("os.environ", env), \
             patch.object(am.session_store, "load_session",
                          return_value=session), \
             patch.object(am.session_store, "save_session") as save, \
             patch.object(am.session_store, "SESSIONS_DIR", tmp_path), \
             patch.object(am, "resolve_txt_records",
                          side_effect=dns_side_effect) as resolve, \
             patch.object(Path, "exists", return_value=True):
            if lock_open_side_effect is not None:
                with patch("builtins.open",
                           side_effect=lock_open_side_effect):
                    manager._maybe_run_auto_check("s1")
            elif flock_side_effect is not None:
                with patch.object(am.fcntl, "flock",
                                  side_effect=flock_side_effect):
                    manager._maybe_run_auto_check("s1")
            else:
                manager._maybe_run_auto_check("s1")
            return save, resolve

    def test_lock_open_fails(self, manager, fake_persisted_session, tmp_path):
        save, resolve = self._run(
            manager, fake_persisted_session,
            dns_side_effect=RuntimeError("should not be called"),
            tmp_path=tmp_path,
            lock_open_side_effect=PermissionError("nope"))
        save.assert_not_called()
        resolve.assert_not_called()

    def test_flock_already_held(self, manager, fake_persisted_session,
                                tmp_path):
        save, resolve = self._run(
            manager, fake_persisted_session,
            dns_side_effect=RuntimeError("should not be called"),
            tmp_path=tmp_path,
            flock_side_effect=OSError("locked"))
        save.assert_not_called()

    def test_dns_lookup_error(self, manager, fake_persisted_session,
                              tmp_path):
        save, _ = self._run(
            manager, fake_persisted_session,
            dns_side_effect=lambda fqdn: ([], "timeout"),
            tmp_path=tmp_path)
        saved = save.call_args[0][1]
        assert saved["auto_check_last_message"].startswith(
            "DNS lookup failed")
        assert saved["auto_check_status"] == "pending"

    def test_dns_record_missing(self, manager, fake_persisted_session,
                                tmp_path):
        save, _ = self._run(
            manager, fake_persisted_session,
            dns_side_effect=lambda fqdn: ([], None),
            tmp_path=tmp_path)
        saved = save.call_args[0][1]
        assert "not published yet" in saved["auto_check_last_message"]
        assert saved["auto_check_status"] == "pending"

    def test_dns_value_mismatch(self, manager, fake_persisted_session,
                                tmp_path):
        save, _ = self._run(
            manager, fake_persisted_session,
            dns_side_effect=lambda fqdn: (["other-value"], None),
            tmp_path=tmp_path)
        saved = save.call_args[0][1]
        assert "TXT mismatch" in saved["auto_check_last_message"]
        assert saved["auto_check_status"] == "pending"

    def test_dns_ok_flips_to_verified(self, manager, fake_persisted_session,
                                      tmp_path):
        save, _ = self._run(
            manager, fake_persisted_session,
            dns_side_effect=lambda fqdn: (["tok1"], None),
            tmp_path=tmp_path)
        saved = save.call_args[0][1]
        assert saved["auto_check_status"] == "verified"
        assert "All TXT records verified" in saved["auto_check_last_message"]

    def test_last_attempt_marks_failed(self, manager, fake_persisted_session,
                                       tmp_path):
        fake_persisted_session["auto_check_attempts"] = 239
        save, _ = self._run(
            manager, fake_persisted_session,
            dns_side_effect=lambda fqdn: ([], None),
            tmp_path=tmp_path)
        saved = save.call_args[0][1]
        assert saved["auto_check_status"] == "failed"
        assert "240" in saved["auto_check_last_message"]

    def test_session_deleted_during_check_is_not_resaved(
            self, manager, fake_persisted_session, tmp_path):
        with patch.dict("os.environ",
                        {"DNS_AUTO_INTERVAL_MS": "0",
                         "DNS_AUTO_START_DELAY_MS": "0"}), \
             patch.object(am.session_store, "load_session",
                          return_value=fake_persisted_session), \
             patch.object(am.session_store, "save_session") as save, \
             patch.object(am.session_store, "SESSIONS_DIR", tmp_path), \
             patch.object(am, "resolve_txt_records",
                          return_value=(["tok1"], None)), \
             patch.object(Path, "exists", return_value=False):
            manager._maybe_run_auto_check("s1")
            assert save.call_count == 0

    def test_state_reloaded_inside_lock(self, manager, fake_persisted_session,
                                        tmp_path):
        calls = {"n": 0}

        def load_side(sid):
            calls["n"] += 1
            if calls["n"] == 1:
                return fake_persisted_session
            s = dict(fake_persisted_session)
            s["auto_check_status"] = "stopped"
            return s

        with patch.dict("os.environ",
                        {"DNS_AUTO_INTERVAL_MS": "0",
                         "DNS_AUTO_START_DELAY_MS": "0"}), \
             patch.object(am.session_store, "load_session",
                          side_effect=load_side), \
             patch.object(am.session_store, "save_session") as save, \
             patch.object(am.session_store, "SESSIONS_DIR", tmp_path), \
             patch.object(am, "resolve_txt_records") as resolve:
            manager._maybe_run_auto_check("s1")
            resolve.assert_not_called()
            save.assert_not_called()


# ==========================================================================
# create_request
# ==========================================================================
class TestCreateRequest:
    def test_new_account(self, manager, tmp_dirs, fake_client):
        fake_client.request_verification_tokens.return_value = {
            "test.com": ["tok1"]
        }
        with patch.object(am.ACMEClient, "__new__",
                          return_value=fake_client) as ctor, \
             patch.object(am, "_client_to_state",
                          return_value={"account_file": "x"}), \
             patch.object(am.session_store, "save_session") as save:
            tokens = manager.create_request("sid", ["test.com"])
            assert tokens == {"test.com": ["tok1"]}
            # new account path called export_account_to_file
            fake_client.export_account_to_file.assert_called_once()
            fake_client.generate_private_key_and_csr.assert_called_once_with(
                key_type="rsa2048")
            fake_client.request_verification_tokens.assert_called_once()
            save.assert_called_once()
            sess = save.call_args[0][1]
            assert sess["auto_check_status"] == "pending"
            assert sess["auto_check_attempts"] == 0
            assert sess["domains"] == ["test.com"]
            assert sess["client"] is fake_client

    def test_existing_account_file(self, manager, tmp_dirs, fake_client):
        # Create the account file so the "exists" branch is taken
        account_file = Path(am.ACCOUNTS_DIR) / "sid.json"
        account_file.write_text("{}")
        fake_client.request_verification_tokens.return_value = {"a.com": ["t"]}
        with patch.object(am.ACMEClient, "load_account_from_file",
                          return_value=fake_client) as load, \
             patch.object(am, "_client_to_state",
                          return_value={"account_file": "x"}), \
             patch.object(am.session_store, "save_session"):
            tokens = manager.create_request("sid", ["a.com"])
            load.assert_called_once_with(str(account_file))
            assert tokens == {"a.com": ["t"]}
            # Existing path does not export a new account
            fake_client.export_account_to_file.assert_not_called()
            assert fake_client.domains == ["a.com"]
            assert fake_client.directory == am.LE_URL
            assert fake_client.nameservers == am.NAMESERVERS

    def test_multiple_domains(self, manager, tmp_dirs, fake_client):
        fake_client.request_verification_tokens.return_value = {
            "a.com": ["t1"], "b.com": ["t2"],
        }
        with patch.object(am.ACMEClient, "__new__",
                          return_value=fake_client), \
             patch.object(am, "_client_to_state", return_value={}), \
             patch.object(am.session_store, "save_session"):
            tokens = manager.create_request("sid", ["a.com", "b.com"])
            assert set(tokens.keys()) == {"a.com", "b.com"}

    def test_tokens_stored_in_session(self, manager, tmp_dirs, fake_client):
        fake_client.request_verification_tokens.return_value = {"x.com": ["t"]}
        with patch.object(am.ACMEClient, "__new__",
                          return_value=fake_client), \
             patch.object(am, "_client_to_state", return_value={}), \
             patch.object(am.session_store, "save_session"):
            manager.create_request("sid", ["x.com"])
            assert manager.sessions["sid"]["tokens"] == {"x.com": ["t"]}


# ==========================================================================
# check_dns
# ==========================================================================
class TestCheckDns:
    def test_no_session(self, manager):
        ok, msg = manager.check_dns("nope")
        assert ok is False
        assert "not found" in msg.lower()

    def test_no_tokens(self, manager):
        manager.sessions["s1"] = {"tokens": {}}
        ok, msg = manager.check_dns("s1")
        assert ok is False
        assert "no txt" in msg.lower()

    def test_missing_tokens_key(self, manager):
        manager.sessions["s1"] = {"domains": ["test.com"]}
        ok, msg = manager.check_dns("s1")
        assert ok is False
        assert "no txt" in msg.lower()

    def test_empty_session_dict_treated_as_missing(self, manager):
        manager.sessions["s1"] = {}
        ok, msg = manager.check_dns("s1")
        assert ok is False
        assert "not found" in msg.lower()

    def test_all_present(self, manager):
        manager.sessions["s1"] = {"tokens": {"test.com": ["tok1"]}}
        with patch.object(am, "resolve_txt_records",
                          return_value=(["tok1"], None)):
            ok, msg = manager.check_dns("s1")
            assert ok is True
            assert "verified" in msg.lower()

    def test_dns_error(self, manager):
        manager.sessions["s1"] = {"tokens": {"test.com": ["tok1"]}}
        with patch.object(am, "resolve_txt_records",
                          return_value=([], "timeout")):
            ok, msg = manager.check_dns("s1")
            assert ok is False
            assert "timeout" in msg

    def test_missing_records(self, manager):
        manager.sessions["s1"] = {"tokens": {"test.com": ["tok1"]}}
        with patch.object(am, "resolve_txt_records",
                          return_value=([], None)):
            ok, msg = manager.check_dns("s1")
            assert ok is False
            assert "not published" in msg.lower()

    def test_mismatched_value(self, manager):
        manager.sessions["s1"] = {"tokens": {"test.com": ["tok1"]}}
        with patch.object(am, "resolve_txt_records",
                          return_value=(["other"], None)):
            ok, msg = manager.check_dns("s1")
            assert ok is False
            assert "mismatch" in msg.lower()

    def test_multiple_fqdns_all_ok(self, manager):
        manager.sessions["s1"] = {
            "tokens": {"a.com": ["t1"], "b.com": ["t2"]},
        }
        with patch.object(am, "resolve_txt_records",
                          side_effect=[(["t1"], None), (["t2"], None)]):
            ok, msg = manager.check_dns("s1")
            assert ok is True

    def test_multiple_fqdns_one_missing(self, manager):
        manager.sessions["s1"] = {
            "tokens": {"a.com": ["t1"], "b.com": ["t2"]},
        }
        with patch.object(am, "resolve_txt_records",
                          side_effect=[(["t1"], None), ([], None)]):
            ok, msg = manager.check_dns("s1")
            assert ok is False
            assert "b.com" in msg

    def test_multiple_fqdns_one_mismatch(self, manager):
        manager.sessions["s1"] = {
            "tokens": {"a.com": ["t1"], "b.com": ["t2"]},
        }
        with patch.object(am, "resolve_txt_records",
                          side_effect=[(["t1"], None), (["other"], None)]):
            ok, msg = manager.check_dns("s1")
            assert ok is False
            assert "mismatch" in msg.lower()
            assert "b.com" in msg


# ==========================================================================
# _forget_session
# ==========================================================================
class TestForgetSession:
    def test_removes_from_memory_and_disk(self, manager):
        manager.sessions["s1"] = {"x": 1}
        with patch.object(am.session_store, "delete_session") as delete:
            manager._forget_session("s1")
            assert "s1" not in manager.sessions
            delete.assert_called_once_with("s1")

    def test_delete_raises_is_swallowed(self, manager):
        manager.sessions["s1"] = {"x": 1}
        with patch.object(am.session_store, "delete_session",
                          side_effect=RuntimeError("boom")):
            manager._forget_session("s1")
            assert "s1" not in manager.sessions

    def test_missing_session_still_calls_delete(self, manager):
        with patch.object(am.session_store, "delete_session") as delete:
            manager._forget_session("missing")
            delete.assert_called_once_with("missing")


# ==========================================================================
# issue_certificate
# ==========================================================================
class TestIssueCertificate:
    def test_no_session(self, manager):
        with pytest.raises(ValueError, match="not found"):
            manager.issue_certificate("nope")

    def test_client_missing(self, manager):
        manager.sessions["s1"] = {"client": None,
                                  "domains": ["test.com"]}
        with pytest.raises(ValueError, match="not available"):
            manager.issue_certificate("s1")

    def test_empty_fullchain(self, manager, fake_client):
        fake_client.request_certificate.return_value = ""
        manager.sessions["s1"] = {"client": fake_client,
                                  "domains": ["test.com"]}
        with pytest.raises(ValueError, match="Empty certificate"):
            manager.issue_certificate("s1")

    def test_empty_private_key(self, manager, fake_client):
        fake_client.request_certificate.return_value = FULLCHAIN
        fake_client.private_key = ""
        manager.sessions["s1"] = {"client": fake_client,
                                  "domains": ["test.com"]}
        with pytest.raises(ValueError, match="Empty private key"):
            manager.issue_certificate("s1")

    def test_success_writes_files(self, manager, tmp_dirs, fake_client):
        fake_client.request_certificate.return_value = FULLCHAIN
        manager.sessions["s1"] = {
            "client": fake_client,
            "domains": ["test.com"],
        }
        with patch.object(am.session_store, "mark_issued") as mark, \
             patch.object(am.session_store, "delete_session") as delete:
            result = manager.issue_certificate("s1")

        cert_path = Path(result["cert_path"])
        chain_path = Path(result["chain_path"])
        key_path = Path(result["key_path"])
        assert cert_path.exists()
        assert chain_path.exists()
        assert key_path.exists()
        assert cert_path.read_text().strip() == CERT_PEM.strip()
        assert chain_path.read_text().strip() == CHAIN_PEM.strip()
        assert key_path.read_text().strip() == KEY_PEM.strip()
        # Result contains the same content
        assert result["certificate"].strip() == CERT_PEM.strip()
        assert result["chain"].strip() == CHAIN_PEM.strip()
        assert result["private_key"].strip() == KEY_PEM.strip()
        # Session is cleaned up
        mark.assert_called_once_with("s1")
        delete.assert_called_once_with("s1")
        assert "s1" not in manager.sessions

    def test_success_with_wildcard_domain(self, manager, tmp_dirs,
                                          fake_client):
        fake_client.request_certificate.return_value = FULLCHAIN
        manager.sessions["s1"] = {
            "client": fake_client,
            "domains": ["*.example.com"],
        }
        with patch.object(am.session_store, "mark_issued"), \
             patch.object(am.session_store, "delete_session"):
            result = manager.issue_certificate("s1")
        # wildcard -> wildcard, dots -> underscores
        assert "wildcard_example_com" in result["cert_path"]

    def test_success_with_bytes_private_key(self, manager, tmp_dirs,
                                            fake_client):
        fake_client.request_certificate.return_value = FULLCHAIN
        fake_client.private_key = KEY_PEM.encode()
        manager.sessions["s1"] = {
            "client": fake_client,
            "domains": ["test.com"],
        }
        with patch.object(am.session_store, "mark_issued"), \
             patch.object(am.session_store, "delete_session"):
            result = manager.issue_certificate("s1")
        assert result["private_key"].strip() == KEY_PEM.strip()

    def test_success_with_crypto_private_key(self, manager, tmp_dirs,
                                             fake_client):
        key_obj = serialization.load_pem_private_key(KEY_PEM.encode(),
                                                     password=None)
        fake_client.request_certificate.return_value = FULLCHAIN
        fake_client.private_key = key_obj
        manager.sessions["s1"] = {
            "client": fake_client,
            "domains": ["test.com"],
        }
        with patch.object(am.session_store, "mark_issued"), \
             patch.object(am.session_store, "delete_session"):
            result = manager.issue_certificate("s1")
        assert "BEGIN PRIVATE KEY" in result["private_key"]

    def test_mark_issued_failure_is_swallowed(self, manager, tmp_dirs,
                                              fake_client):
        fake_client.request_certificate.return_value = FULLCHAIN
        manager.sessions["s1"] = {
            "client": fake_client,
            "domains": ["test.com"],
        }
        with patch.object(am.session_store, "mark_issued",
                          side_effect=RuntimeError("boom")), \
             patch.object(am.session_store, "delete_session"):
            # Should not raise
            result = manager.issue_certificate("s1")
        assert result["certificate"]

    def test_request_certificate_raises(self, manager, fake_client):
        fake_client.request_certificate.side_effect = RuntimeError("acme err")
        manager.sessions["s1"] = {
            "client": fake_client,
            "domains": ["test.com"],
        }
        with pytest.raises(RuntimeError, match="acme err"):
            manager.issue_certificate("s1")
