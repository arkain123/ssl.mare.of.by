"""
DNS TXT resolution for ACME challenges.

Queries public resolvers over TCP (like `dig +tcp @8.8.8.8 name TXT`) and
returns the TXT payload(s). Uses dnspython, so no external `dig` binary
is required. Resolver list and timeouts are configurable via .env.
"""

import logging
import os

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

logger = logging.getLogger(__name__)


def _env_list(name, default):
    raw = os.getenv(name, "")
    if not raw.strip():
        return list(default)
    return [x.strip() for x in raw.split(",") if x.strip()]


def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


ACME_DNS_SERVERS = _env_list("NAMESERVERS", ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
QUERY_TIMEOUT = _env_int("DNS_QUERY_TIMEOUT", 3)


def resolve_txt_records(fqdn, nameservers=None, timeout=None):
    """
    Resolve TXT records for `fqdn` via TCP against public resolvers.

    Returns (values, error):
      - values: list[str] of TXT payloads (empty list if none found)
      - error:  None on success, or a string describing the last fatal error
    """
    nameservers = nameservers or ACME_DNS_SERVERS
    timeout = timeout if timeout is not None else QUERY_TIMEOUT
    last_error = None

    for ns in nameservers:
        try:
            values = _query_txt_tcp(fqdn, ns, timeout)
        except Exception as e:
            logger.warning("[dns] query %s via %s failed: %s", fqdn, ns, e)
            last_error = str(e)
            continue

        if values is None:
            continue

        if values:
            logger.info("[dns] %s -> %d TXT value(s) via %s", fqdn, len(values), ns)
            return values, None

        logger.info("[dns] no TXT for %s via %s, trying next", fqdn, ns)

    return [], last_error


def _query_txt_tcp(fqdn, ns, timeout):
    query = dns.message.make_query(fqdn, dns.rdatatype.TXT, use_edns=0)
    try:
        response = dns.query.tcp(query, ns, timeout=timeout)
    except (dns.exception.Timeout, dns.exception.DNSException, OSError):
        raise

    if response.rcode() != dns.rcode.NOERROR:
        logger.info(
            "[dns] %s via %s: rcode=%s",
            fqdn, ns, dns.rcode.to_text(response.rcode()),
        )
        return None

    values = []
    for rrset in response.answer:
        if rrset.rdtype != dns.rdatatype.TXT:
            continue
        for rdata in rrset:
            text = b"".join(rdata.strings).decode("utf-8", errors="replace")
            values.append(text)

    return values or None
