import logging

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

logger = logging.getLogger(__name__)

ACME_DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
QUERY_TIMEOUT = 3  # seconds per nameserver


def resolve_txt_records(fqdn, nameservers=None, timeout=QUERY_TIMEOUT):
    nameservers = nameservers or ACME_DNS_SERVERS
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
            # RFC 7208: a single TXT value may be split into multiple
            # character-strings; concatenate them.
            text = b"".join(rdata.strings).decode("utf-8", errors="replace")
            values.append(text)

    return values or None
