import os
import logging
import time
import threading
from datetime import datetime, timezone
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from simple_acme_dns import ACMEClient
from dns_check import resolve_txt_records
import session_store

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

load_dotenv()

logger = logging.getLogger(__name__)

LE_URL = os.getenv("LE_URL", "https://acme-v02.api.letsencrypt.org/directory")
ACCOUNT_EMAIL = os.getenv("ACCOUNT_EMAIL")
NAMESERVERS = [x.strip() for x in os.getenv("NAMESERVERS", "8.8.8.8,1.1.1.1").split(",") if x.strip()]

BASE_DIR = os.getenv("BASE_DIR") or os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_DIR = os.path.join(BASE_DIR, os.getenv("ACCOUNTS_DIR", "accounts"))
CERTS_DIR    = os.path.join(BASE_DIR, os.getenv("CERTS_DIR", "certs"))
os.makedirs(ACCOUNTS_DIR, exist_ok=True)
os.makedirs(CERTS_DIR, exist_ok=True)


def _split_pem_chain(pem_bytes):
    if isinstance(pem_bytes, bytes):
        text = pem_bytes.decode("utf-8")
    else:
        text = pem_bytes

    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"

    blocks = []
    pos = 0
    while True:
        s = text.find(begin, pos)
        if s == -1:
            break
        e = text.find(end, s)
        if e == -1:
            break
        e += len(end)
        blocks.append(text[s:e].strip() + "\n")
        pos = e

    if not blocks:
        return "", ""

    leaf = blocks[0]
    chain = "\n".join(blocks[1:])
    return leaf, chain


# ---------------------------------------------------------------------------
# ACMEClient <-> JSON state
# ---------------------------------------------------------------------------

def _client_to_state(client, session_id):
    """Serialize ACMEClient into JSON-friendly dict."""
    private_key_pem = None
    pk = getattr(client, "private_key", None)
    if pk is not None:
        if isinstance(pk, bytes):
            private_key_pem = pk.decode("utf-8")
        elif isinstance(pk, str):
            private_key_pem = pk
        else:
            try:
                private_key_pem = pk.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("ascii")
            except Exception as e:
                logger.warning("[state] cannot serialize private key: %s", e)

    csr_pem = None
    csr = getattr(client, "csr", None)
    if csr is not None:
        if isinstance(csr, bytes):
            csr_pem = csr.decode("utf-8")
        elif isinstance(csr, str):
            csr_pem = csr
        else:
            try:
                csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
            except Exception as e:
                logger.warning("[state] cannot serialize CSR: %s", e)

    return {
        "account_file": os.path.join(ACCOUNTS_DIR, f"{session_id}.json"),
        "private_key_pem": private_key_pem,
        "csr_pem": csr_pem,
        "domains": list(getattr(client, "domains", []) or []),
        "directory": getattr(client, "directory", LE_URL),
        "nameservers": list(getattr(client, "nameservers", []) or NAMESERVERS),
    }


def _client_from_state(state):
    """Rebuild ACMEClient from persisted state. Returns None on failure."""
    if not state or not state.get("account_file"):
        return None

    if not os.path.exists(state["account_file"]):
        logger.warning("[restore] account file missing: %s", state["account_file"])
        return None

    try:
        client = ACMEClient.load_account_from_file(state["account_file"])
    except Exception as e:
        logger.warning("[restore] load_account_from_file failed: %s", e)
        return None

    client.domains = state.get("domains") or []
    client.directory = state.get("directory") or LE_URL
    if state.get("nameservers"):
        client.nameservers = state["nameservers"]

    key_pem = state.get("private_key_pem")
    if key_pem:
        try:
            client.private_key = serialization.load_pem_private_key(
                key_pem.encode(), password=None
            )
        except Exception as e:
            logger.warning("[restore] private key parse failed: %s", e)

    csr_pem = state.get("csr_pem")
    if csr_pem:
        try:
            client.csr = x509.load_pem_x509_csr(csr_pem.encode())
        except Exception as e:
            logger.warning("[restore] CSR parse failed: %s", e)

    return client


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class ACMEManager:
    def __init__(self):
        self.sessions = {}
        self._scheduler_stop = threading.Event()
        self._scheduler_thread = None
        self._load_persisted_sessions()
        self._hydrate_sessions()
        logger.info("[init] loaded %d persisted session(s)", len(self.sessions))
        self._start_scheduler()

    def _start_scheduler(self):
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            return
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True,
            name="dns-autocheck-scheduler",
        )
        self._scheduler_thread.start()
        logger.info("[scheduler] started")

    def _scheduler_loop(self):
        while not self._scheduler_stop.is_set():
            try:
                self._tick_all_sessions()
            except Exception as e:
                logger.exception("[scheduler] tick failed: %s", e)
            self._scheduler_stop.wait(3)  # 3 seconds

    def _tick_all_sessions(self):
        for meta in session_store.list_metadata():
            sid = meta.get("session_id")
            if not sid:
                continue
            try:
                self._maybe_run_auto_check(sid)
            except Exception as e:
                logger.warning("[scheduler] %s: %s", sid, e)

    def _maybe_run_auto_check(self, session_id):
        session = session_store.load_session(session_id)
        if not session:
            return
        if session.get("auto_check_status") != "pending":
            return

        now = time.time()

        def _parse(iso):
            if not iso:
                return None
            try:
                return datetime.fromisoformat(iso).timestamp()
            except Exception:
                return None

        attempts = int(session.get("auto_check_attempts", 0))
        max_attempts = int(os.getenv("DNS_AUTO_MAX_ATTEMPTS", "240"))
        interval_ms = int(os.getenv("DNS_AUTO_INTERVAL_MS", "30000"))
        start_delay_ms = int(os.getenv("DNS_AUTO_START_DELAY_MS", "3000"))

        started_ts = _parse(session.get("auto_check_started_at")) or now
        last_ts = _parse(session.get("auto_check_last_at")) or 0

        if attempts == 0:
            next_at = started_ts + start_delay_ms / 1000.0
        else:
            next_at = last_ts + interval_ms / 1000.0

        if now < next_at:
            return

        # Hard timeout: don't keep checking zombie sessions forever
        if now - started_ts > 7 * 86400:
            session["auto_check_status"] = "expired"
            session["auto_check_last_message"] = "Session older than 7 days"
            session_store.save_session(session_id, session)
            return

        if attempts >= max_attempts:
            session["auto_check_status"] = "failed"
            session["auto_check_last_message"] = (
                f"Max attempts ({max_attempts}) reached"
            )
            session_store.save_session(session_id, session)
            return

        lock_path = session_store.SESSIONS_DIR / f"{session_id}.lock"
        try:
            lock_fd = open(lock_path, "w")
        except Exception as e:
            logger.warning("[autocheck] cannot open lock for %s: %s", session_id, e)
            return

        try:
            if HAS_FCNTL:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (IOError, OSError):
                    return

            try:
                # Re-read inside lock - state may have changed
                session = session_store.load_session(session_id)
                if not session or session.get("auto_check_status") != "pending":
                    return

                attempts = int(session.get("auto_check_attempts", 0)) + 1
                session["auto_check_attempts"] = attempts
                session["auto_check_last_at"] = datetime.now(timezone.utc).isoformat()

                tokens = session.get("tokens") or {}
                ok = True
                message = "All TXT records verified via public DNS"
                for fqdn, expected_values in tokens.items():
                    found, err = resolve_txt_records(fqdn)
                    if err:
                        ok, message = False, f"DNS lookup failed for {fqdn}: {err}"
                        break
                    if not found:
                        ok, message = False, f"TXT record not published yet: {fqdn}"
                        break
                    for expected in expected_values:
                        if expected not in found:
                            ok, message = False, f"TXT mismatch for {fqdn}"
                            break
                    if not ok:
                        break

                session["auto_check_last_message"] = message

                if ok:
                    session["auto_check_status"] = "verified"
                elif attempts >= max_attempts:
                    session["auto_check_status"] = "failed"
                    session["auto_check_last_message"] = (
                        f"Max attempts ({max_attempts}) reached. Last: {message}"
                    )

                # Don't resurrect a session that was deleted during our check
                if (session_store.SESSIONS_DIR / f"{session_id}.json").exists():
                    session_store.save_session(session_id, session)

                logger.info(
                    "[autocheck] %s attempt %d/%d ok=%s msg=%s",
                    session_id, attempts, max_attempts, ok, message,
                )
            finally:
                if HAS_FCNTL:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except Exception:
                        pass
        finally:
            try:
                lock_fd.close()
            except Exception:
                pass

    def _load_persisted_sessions(self):
        for meta in session_store.list_metadata():
            sid = meta["session_id"]
            if sid in self.sessions:
                continue
            session = session_store.load_session(sid)
            if session:
                self.sessions[sid] = session

    def _hydrate_sessions(self):
        """Rebuild missing ACME clients from client_state."""
        for sid, session in list(self.sessions.items()):
            if session.get("client"):
                continue
            state = session.get("client_state")
            if not state:
                continue
            client = _client_from_state(state)
            if client:
                session["client"] = client
                logger.info("[hydrate] client restored for session %s", sid)
            else:
                logger.warning("[hydrate] could not rebuild client for %s", sid)

    def _forget_session(self, session_id):
        self.sessions.pop(session_id, None)
        try:
            session_store.delete_session(session_id)
            logger.info("[cleanup] removed session %s after successful issuance",
                        session_id)
        except Exception as e:
            logger.warning("[cleanup] failed to remove session %s from disk: %s",
                           session_id, e)

    def create_request(self, session_id, domains):
        logger.info("[create] session=%s domains=%s", session_id, domains)
        account_file = os.path.join(ACCOUNTS_DIR, f"{session_id}.json")

        if os.path.exists(account_file):
            logger.info("[create] loading existing account from %s", account_file)
            client = ACMEClient.load_account_from_file(account_file)
            client.domains = domains
            client.directory = LE_URL
            client.nameservers = NAMESERVERS
        else:
            logger.info("[create] registering new ACME account (email=%s)", ACCOUNT_EMAIL)
            client = ACMEClient(
                domains=domains,
                email=ACCOUNT_EMAIL,
                directory=LE_URL,
                nameservers=NAMESERVERS,
                new_account=True,
                generate_csr=False,
            )
            logger.info("[create] saving account to %s", account_file)
            client.export_account_to_file(
                path=ACCOUNTS_DIR,
                name=f"{session_id}.json",
                save_certificate=False,
            )

        logger.info("[create] generating RSA-2048 key and CSR")
        client.generate_private_key_and_csr(key_type="rsa2048")

        logger.info("[create] requesting verification tokens")
        tokens = client.request_verification_tokens()
        logger.info("[create] got tokens: %s", tokens)
        now_iso = datetime.now(timezone.utc).isoformat()

        session = {
            "client": client,
            "tokens": tokens,
            "domains": domains,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
            "client_state": _client_to_state(client, session_id),
            "auto_check_status": "pending",
            "auto_check_attempts": 0,
            "auto_check_started_at": now_iso,
            "auto_check_last_at": None,
            "auto_check_last_message": None,
        }
        self.sessions[session_id] = session
        session_store.save_session(session_id, session)
        return tokens

    def check_dns(self, session_id):
        session = self.sessions.get(session_id)
        if not session:
            return False, "Session not found"

        tokens = session.get("tokens") or {}
        if not tokens:
            return False, "No TXT tokens in this session"

        missing = []
        mismatched = []

        for fqdn, expected_values in tokens.items():
            found, err = resolve_txt_records(fqdn)
            if err:
                return False, f"DNS lookup failed for {fqdn}: {err}"

            if not found:
                missing.append(fqdn)
                continue

            for expected in expected_values:
                if expected not in found:
                    mismatched.append(
                        f"{fqdn}: expected {expected!r}, got {found!r}"
                    )

        if missing:
            return False, "TXT record not published yet: " + ", ".join(missing)
        if mismatched:
            return False, "TXT mismatch: " + "; ".join(mismatched)

        return True, "All TXT records verified via public DNS"

    def issue_certificate(self, session_id):
        logger.info("[issue] session=%s", session_id)
        session = self.sessions.get(session_id)
        if not session:
            logger.warning("[issue] session %s not found", session_id)
            raise ValueError("Session not found")

        client = session.get("client")
        if client is None:
            msg = ("Session client is not available. The server was restarted "
                   "and the session state could not be fully restored. Please "
                   "start a new request.")
            logger.error("[issue] %s (session=%s)", msg, session_id)
            raise ValueError(msg)

        logger.info("[issue] requesting certificate from Let's Encrypt")
        fullchain = client.request_certificate()

        leaf_pem, chain_pem = _split_pem_chain(fullchain)
        logger.info("[issue] leaf=%d bytes, chain=%d bytes",
                    len(leaf_pem), len(chain_pem))

        if not leaf_pem:
            raise ValueError("Empty certificate received")

        key_pem = client.private_key
        if isinstance(key_pem, bytes):
            key_pem = key_pem.decode("utf-8")
        if hasattr(key_pem, "private_bytes"):
            key_pem = key_pem.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("ascii")
        if not key_pem:
            raise ValueError("Empty private key received")

        domain_slug = session["domains"][0].replace("*", "wildcard").replace(".", "_")
        cert_path = os.path.join(CERTS_DIR, f"{domain_slug}.crt")
        chain_path = os.path.join(CERTS_DIR, f"{domain_slug}.chain.pem")
        key_path = os.path.join(CERTS_DIR, f"{domain_slug}.key")

        with open(cert_path, "w") as f:
            f.write(leaf_pem)
        logger.info("[issue] leaf certificate written to %s", cert_path)

        with open(chain_path, "w") as f:
            f.write(chain_pem)
        logger.info("[issue] intermediate chain written to %s", chain_path)

        with open(key_path, "w") as f:
            f.write(key_pem)
        logger.info("[issue] private key written to %s", key_path)

        try:
            session_store.mark_issued(session_id)
        except Exception:
            pass

        self._forget_session(session_id)

        return {
            "certificate": leaf_pem,
            "chain": chain_pem,
            "private_key": key_pem,
            "cert_path": cert_path,
            "chain_path": chain_path,
            "key_path": key_path,
        }
