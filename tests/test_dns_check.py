import os
from unittest.mock import MagicMock, patch

import pytest

import dns.exception
import dns.message
import dns.rcode
import dns.rdatatype

from app import dns_check as dc


# --------------------------------------------------------------------------
# Helpers to build fake DNS responses
# --------------------------------------------------------------------------
def _make_rrset(rdtype, values):
    rrset = MagicMock(name=f"rrset-{rdtype}")
    rrset.rdtype = rdtype
    rdatas = []
    for v in values:
        rdata = MagicMock(name=f"rdata-{v}")
        if isinstance(v, bytes):
            rdata.strings = [v]
        elif isinstance(v, (list, tuple)):
            rdata.strings = [
                (x if isinstance(x, bytes) else x.encode()) for x in v
            ]
        else:
            rdata.strings = [v.encode()]
        rdatas.append(rdata)
    rrset.__iter__ = MagicMock(return_value=iter(rdatas))
    return rrset


def _make_response(rcode_value=dns.rcode.NOERROR, answer=None):
    resp = MagicMock(name="dns-response")
    resp.rcode.return_value = rcode_value
    resp.answer = answer if answer is not None else []
    return resp


# ==========================================================================
# _env_list
# ==========================================================================
class TestEnvList:
    def test_uses_default_when_missing(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NAMESERVERS", None)
            assert dc._env_list("NAMESERVERS", ["a", "b"]) == ["a", "b"]

    def test_uses_default_when_empty_string(self):
        with patch.dict(os.environ, {"NAMESERVERS": ""}):
            assert dc._env_list("NAMESERVERS", ["a"]) == ["a"]

    def test_uses_default_when_whitespace_only(self):
        with patch.dict(os.environ, {"NAMESERVERS": "   "}):
            assert dc._env_list("NAMESERVERS", ["a"]) == ["a"]

    def test_parses_comma_separated(self):
        with patch.dict(os.environ, {"NAMESERVERS": "1.1.1.1,8.8.8.8"}):
            assert dc._env_list("NAMESERVERS", []) == ["1.1.1.1", "8.8.8.8"]

    def test_strips_whitespace_around_entries(self):
        with patch.dict(os.environ, {"NAMESERVERS": " 1.1.1.1 , 8.8.8.8 "}):
            assert dc._env_list("NAMESERVERS", []) == ["1.1.1.1", "8.8.8.8"]

    def test_skips_empty_entries(self):
        with patch.dict(os.environ, {"NAMESERVERS": "1.1.1.1,,8.8.8.8,"}):
            assert dc._env_list("NAMESERVERS", []) == ["1.1.1.1", "8.8.8.8"]


# ==========================================================================
# _env_int
# ==========================================================================
class TestEnvInt:
    def test_uses_default_when_missing(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DNS_QUERY_TIMEOUT", None)
            assert dc._env_int("DNS_QUERY_TIMEOUT", 3) == 3

    def test_parses_integer(self):
        with patch.dict(os.environ, {"DNS_QUERY_TIMEOUT": "10"}):
            assert dc._env_int("DNS_QUERY_TIMEOUT", 3) == 10

    def test_parses_negative_integer(self):
        with patch.dict(os.environ, {"DNS_QUERY_TIMEOUT": "-1"}):
            assert dc._env_int("DNS_QUERY_TIMEOUT", 3) == -1

    def test_invalid_value_falls_back_to_default(self):
        with patch.dict(os.environ, {"DNS_QUERY_TIMEOUT": "abc"}):
            assert dc._env_int("DNS_QUERY_TIMEOUT", 3) == 3

    def test_none_like_value_falls_back_to_default(self):
        # int("None") raises ValueError -> default returned
        with patch.dict(os.environ, {"DNS_QUERY_TIMEOUT": "None"}):
            assert dc._env_int("DNS_QUERY_TIMEOUT", 3) == 3


# ==========================================================================
# Module-level constants
# ==========================================================================
class TestModuleConstants:
    def test_acme_dns_servers_is_list(self):
        assert isinstance(dc.ACME_DNS_SERVERS, list)
        assert dc.ACME_DNS_SERVERS  # non-empty

    def test_query_timeout_is_int(self):
        assert isinstance(dc.QUERY_TIMEOUT, int)


# ==========================================================================
# _query_txt_tcp
# ==========================================================================
class TestQueryTxtTcp:
    def test_builds_query_and_returns_values(self):
        rrset = _make_rrset(dns.rdatatype.TXT, ["v1", "v2"])
        response = _make_response(answer=[rrset])
        with patch.object(dc.dns.message, "make_query") as mq, \
             patch.object(dc.dns.query, "tcp", return_value=response) as tcp:
            values = dc._query_txt_tcp("test.com", "8.8.8.8", 3)
        mq.assert_called_once_with("test.com", dns.rdatatype.TXT, use_edns=0)
        tcp.assert_called_once()
        assert values == ["v1", "v2"]

    def test_passes_timeout(self):
        response = _make_response()
        with patch.object(dc.dns.message, "make_query"), \
             patch.object(dc.dns.query, "tcp",
                          return_value=response) as tcp:
            dc._query_txt_tcp("test.com", "8.8.8.8", 7)
            _, kwargs = tcp.call_args
            assert kwargs["timeout"] == 7

    def test_passes_nameserver_positionally(self):
        response = _make_response()
        with patch.object(dc.dns.message, "make_query"), \
             patch.object(dc.dns.query, "tcp",
                          return_value=response) as tcp:
            dc._query_txt_tcp("test.com", "9.9.9.9", 3)
            args = tcp.call_args[0]
            assert args[1] == "9.9.9.9"

    def test_returns_none_for_non_noerror_rcode(self):
        response = _make_response(rcode_value=dns.rcode.NXDOMAIN)
        with patch.object(dc.dns.message, "make_query"), \
             patch.object(dc.dns.query, "tcp", return_value=response):
            assert dc._query_txt_tcp("test.com", "8.8.8.8", 3) is None

    def test_returns_none_when_no_txt_rrset(self):
        # Answer contains only A record
        a_rrset = _make_rrset(dns.rdatatype.A, ["1.2.3.4"])
        response = _make_response(answer=[a_rrset])
        with patch.object(dc.dns.message, "make_query"), \
             patch.object(dc.dns.query, "tcp", return_value=response):
            assert dc._query_txt_tcp("test.com", "8.8.8.8", 3) is None

    def test_returns_none_when_answer_empty(self):
        response = _make_response(answer=[])
        with patch.object(dc.dns.message, "make_query"), \
             patch.object(dc.dns.query, "tcp", return_value=response):
            assert dc._query_txt_tcp("test.com", "8.8.8.8", 3) is None

    def test_concatenates_multiple_strings_in_one_txt(self):
        rrset = _make_rrset(dns.rdatatype.TXT, [["part1-", "part2"]])
        response = _make_response(answer=[rrset])
        with patch.object(dc.dns.message, "make_query"), \
             patch.object(dc.dns.query, "tcp", return_value=response):
            values = dc._query_txt_tcp("test.com", "8.8.8.8", 3)
        assert values == ["part1-part2"]

    def test_decodes_non_utf8_with_replace(self):
        rrset = _make_rrset(dns.rdatatype.TXT, [b"\xff\xfe"])
        response = _make_response(answer=[rrset])
        with patch.object(dc.dns.message, "make_query"), \
             patch.object(dc.dns.query, "tcp", return_value=response):
            values = dc._query_txt_tcp("test.com", "8.8.8.8", 3)
        # Non-UTF-8 bytes replaced with U+FFFD
        assert values == ["\ufffd\ufffd"]

    def test_skips_non_txt_rrsets(self):
        a_rrset = _make_rrset(dns.rdatatype.A, ["1.2.3.4"])
        txt_rrset = _make_rrset(dns.rdatatype.TXT, ["ok"])
        response = _make_response(answer=[a_rrset, txt_rrset])
        with patch.object(dc.dns.message, "make_query"), \
             patch.object(dc.dns.query, "tcp", return_value=response):
            values = dc._query_txt_tcp("test.com", "8.8.8.8", 3)
        assert values == ["ok"]

    def test_multiple_txt_rrsets(self):
        rr1 = _make_rrset(dns.rdatatype.TXT, ["a"])
        rr2 = _make_rrset(dns.rdatatype.TXT, ["b"])
        response = _make_response(answer=[rr1, rr2])
        with patch.object(dc.dns.message, "make_query"), \
             patch.object(dc.dns.query, "tcp", return_value=response):
            values = dc._query_txt_tcp("test.com", "8.8.8.8", 3)
        assert values == ["a", "b"]

    @pytest.mark.parametrize("exc", [
        dns.exception.Timeout(),
        dns.exception.DNSException("boom"),
        OSError("net down"),
    ])
    def test_propagates_known_exceptions(self, exc):
        with patch.object(dc.dns.message, "make_query"), \
             patch.object(dc.dns.query, "tcp", side_effect=exc):
            with pytest.raises(type(exc)):
                dc._query_txt_tcp("test.com", "8.8.8.8", 3)


# ==========================================================================
# resolve_txt_records
# ==========================================================================
class TestResolveTxtRecords:
    def test_returns_values_from_first_nameserver(self):
        with patch.object(dc, "_query_txt_tcp",
                          return_value=["v1"]) as q:
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=["1.1.1.1", "8.8.8.8"])
        assert values == ["v1"]
        assert err is None
        q.assert_called_once()
        assert q.call_args[0][1] == "1.1.1.1"

    def test_skips_nameserver_returning_none(self):
        # First NS returns None, second returns values
        side = [None, ["v"]]
        with patch.object(dc, "_query_txt_tcp", side_effect=side) as q:
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=["1.1.1.1", "8.8.8.8"])
        assert values == ["v"]
        assert err is None
        assert q.call_count == 2

    def test_skips_nameserver_returning_empty_list(self):
        # Empty list means "no TXT found here", try next NS
        side = [[], ["v"]]
        with patch.object(dc, "_query_txt_tcp", side_effect=side):
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=["1.1.1.1", "8.8.8.8"])
        assert values == ["v"]
        assert err is None

    def test_all_nameservers_return_none(self):
        with patch.object(dc, "_query_txt_tcp", return_value=None):
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=["1.1.1.1", "8.8.8.8"])
        assert values == []
        assert err is None

    def test_all_nameservers_return_empty(self):
        with patch.object(dc, "_query_txt_tcp", return_value=[]):
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=["1.1.1.1", "8.8.8.8"])
        assert values == []
        assert err is None

    def test_exception_recorded_as_last_error(self):
        with patch.object(dc, "_query_txt_tcp",
                          side_effect=RuntimeError("boom")):
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=["1.1.1.1"])
        assert values == []
        assert err == "boom"

    def test_last_error_is_from_last_failing_nameserver(self):
        # First fails with "e1", second fails with "e2"
        side = [RuntimeError("e1"), RuntimeError("e2")]
        with patch.object(dc, "_query_txt_tcp", side_effect=side):
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=["1.1.1.1", "8.8.8.8"])
        assert values == []
        assert err == "e2"

    def test_error_then_none_then_values(self):
        # First NS fails, second returns None, third returns values
        side = [RuntimeError("boom"), None, ["v"]]
        with patch.object(dc, "_query_txt_tcp", side_effect=side):
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=["a", "b", "c"])
        assert values == ["v"]
        assert err is None

    def test_error_then_none(self):
        # First fails, second returns None -> last_error still from first
        side = [RuntimeError("boom"), None]
        with patch.object(dc, "_query_txt_tcp", side_effect=side):
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=["a", "b"])
        assert values == []
        assert err == "boom"

    def test_uses_defaults_when_arguments_missing(self):
        with patch.object(dc, "_query_txt_tcp", return_value=["v"]) as q, \
             patch.object(dc, "ACME_DNS_SERVERS", ["x", "y"]), \
             patch.object(dc, "QUERY_TIMEOUT", 5):
            dc.resolve_txt_records("test.com")
            args = q.call_args[0]
            assert args[1] == "x"
            assert args[2] == 5

    def test_timeout_override(self):
        with patch.object(dc, "_query_txt_tcp", return_value=["v"]) as q:
            dc.resolve_txt_records("test.com",
                                   nameservers=["1.1.1.1"],
                                   timeout=42)
            args = q.call_args[0]
            assert args[2] == 42

    def test_empty_nameservers_list(self):
        # Empty list falls back to ACME_DNS_SERVERS via `nameservers or default`
        with patch.object(dc, "_query_txt_tcp", return_value=["v"]) as q, \
             patch.object(dc, "ACME_DNS_SERVERS", ["ns1"]):
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=[])
            assert values == ["v"]
            args = q.call_args[0]
            assert args[1] == "ns1"

    def test_default_nameservers_used_when_none(self):
        with patch.object(dc, "_query_txt_tcp", return_value=["v"]) as q, \
             patch.object(dc, "ACME_DNS_SERVERS", ["ns1", "ns2"]):
            dc.resolve_txt_records("test.com", nameservers=None)
            args = q.call_args[0]
            assert args[1] == "ns1"

    def test_timeout_zero_is_respected(self):
        # timeout=0 is falsy but not None, so must be used
        with patch.object(dc, "_query_txt_tcp", return_value=["v"]) as q:
            dc.resolve_txt_records("test.com",
                                   nameservers=["1.1.1.1"],
                                   timeout=0)
            args = q.call_args[0]
            assert args[2] == 0

    def test_all_ns_raise_success_returns_last_error(self):
        side = [dns.exception.Timeout(),
                OSError("net down")]
        with patch.object(dc, "_query_txt_tcp", side_effect=side):
            values, err = dc.resolve_txt_records(
                "test.com", nameservers=["a", "b"])
        assert values == []
        assert err == "net down"
