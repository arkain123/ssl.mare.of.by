import os
import logging
import dns.resolver
import session_store
from datetime import datetime, timezone
from dotenv import load_dotenv
from simple_acme_dns import ACMEClient

load_dotenv()

logger = logging.getLogger(__name__)

LE_URL = os.getenv("LE_URL", "https://acme-v02.api.letsencrypt.org/directory")
ACCOUNT_EMAIL = os.getenv("ACCOUNT_EMAIL")
NAMESERVERS = os.getenv("NAMESERVERS", "1.1.1.1,8.8.8.8").split(",")

BASE_DIR = os.getenv("BASE_DIR")
ACCOUNTS_DIR = os.path.join(BASE_DIR, "accounts")
CERTS_DIR = os.path.join(BASE_DIR, "certs")
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


class ACMEManager:
    def __init__(self):
        self.sessions = session_store.load_all()
        logger.info("[init] loaded %d persisted session(s)", len(self.sessions))

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

        session = {
            "client": client,
            "tokens": tokens,
            "domains": domains,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
        }
        self.sessions[session_id] = session
        session_store.save_session(session_id, session)
        return tokens

    def check_dns(self, session_id):
        session = self.sessions.get(session_id)
        if not session:
            logger.warning("[check] session %s not found", session_id)
            return False, "Session not found"

        tokens = session["tokens"]
        logger.info("[check] session=%s, checking %d FQDN(s)", session_id, len(tokens))

        resolver = dns.resolver.Resolver()
        resolver.nameservers = NAMESERVERS
        resolver.timeout = 5
        resolver.lifetime = 5

        missing = []
        for fqdn, expected_list in tokens.items():
            logger.info("[check] querying TXT %s via %s", fqdn, NAMESERVERS)
            found = []
            try:
                answers = resolver.resolve(fqdn, "TXT")
                for rdata in answers:
                    txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    found.append(txt)
                logger.info("[check]   found %d TXT value(s):", len(found))
                for v in found:
                    logger.info("[check]     %s", v)
            except dns.resolver.NXDOMAIN:
                logger.warning("[check]   NXDOMAIN for %s", fqdn)
            except dns.resolver.NoAnswer:
                logger.warning("[check]   no TXT answer for %s", fqdn)
            except dns.resolver.NoNameservers:
                logger.warning("[check]   no nameservers responded for %s", fqdn)
            except Exception as e:
                logger.exception("[check]   query failed for %s: %s", fqdn, e)

            for token in expected_list:
                if token in found:
                    logger.info("[check]   OK: token %s present", token)
                else:
                    logger.warning("[check]   MISSING: token %s", token)
                    missing.append((fqdn, token))

        if missing:
            logger.warning("[check] result: %d token(s) missing", len(missing))
            return False, f"{len(missing)} TXT value(s) missing. Verify DNS and try again."

        logger.info("[check] result: all records found")
        return True, "All records found"

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

        session_store.mark_issued(session_id)
        self.sessions.pop(session_id, None)

        return {
            "certificate": leaf_pem,
            "chain": chain_pem,
            "private_key": key_pem,
            "cert_path": cert_path,
            "chain_path": chain_path,
            "key_path": key_path,
        }
