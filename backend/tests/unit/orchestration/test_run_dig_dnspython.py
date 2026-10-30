"""`_run_dig` resolves DNS via dnspython, not the unreliable `dig ANY`.

Regression: `dig ANY` returns an RFC-8482 minimal answer (no NS/MX/SOA) and the
sandbox dig binary core-dumps on an OpenSSL init mismatch, so Target Intelligence
DNS (ns/mx/soa) was always empty. The dnspython path must produce dig-compatible
answer text that `_parse_dig_any` can read.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from src.orchestration.handlers import (
    _dig_answer_via_dnspython,
    _parse_dig_any,
    _run_dig,
)


class _Rd:
    def __init__(self, text: str) -> None:
        self._t = text

    def to_text(self) -> str:
        return self._t


class _Rrset:
    ttl = 3600


class _Answer:
    def __init__(self, rdatas: list[_Rd]) -> None:
        self._rdatas = rdatas
        self.rrset = _Rrset()

    def __iter__(self):
        return iter(self._rdatas)


_BY_TYPE = {
    "NS": _Answer([_Rd("ns1.vercel-dns.com."), _Rd("ns2.vercel-dns.com.")]),
    "MX": _Answer([_Rd("0 svalbard-ca.mail.protection.outlook.com.")]),
    "SOA": _Answer([_Rd("ns1.vercel-dns.com. hostmaster.nsone.net. 1721422316 43200 7200 1209600 600")]),
    "A": _Answer([_Rd("216.198.79.1")]),
}


def _fake_resolve(name, rtype, lifetime=8):  # noqa: ANN001, ARG001
    ans = _BY_TYPE.get(rtype)
    if ans is None:
        raise RuntimeError("NoAnswer")
    return ans


def test_dnspython_answer_parses_to_ns_mx_soa() -> None:
    with patch("dns.resolver.resolve", side_effect=_fake_resolve):
        text = _dig_answer_via_dnspython("svalbard.ca")
    ns, mx, soa = _parse_dig_any(text)
    assert ns == ["ns1.vercel-dns.com", "ns2.vercel-dns.com"]
    assert mx == ["svalbard-ca.mail.protection.outlook.com"]
    assert soa == "ns1.vercel-dns.com"


def test_run_dig_uses_dnspython_and_never_core_dumping_binary() -> None:
    # execute_command must NOT be reached when dnspython yields an answer.
    with (
        patch("dns.resolver.resolve", side_effect=_fake_resolve),
        patch(
            "src.orchestration.handlers.execute_command",
            side_effect=AssertionError("legacy dig ANY must not run when dnspython resolves"),
        ),
    ):
        res = asyncio.run(_run_dig("svalbard.ca"))
    assert res["success"] is True
    ns, mx, soa = _parse_dig_any(res["stdout"])
    assert ns and mx and soa


def test_run_dig_falls_back_when_dnspython_empty() -> None:
    fallback = {"success": False, "stdout": "", "stderr": "", "return_code": 1}
    with (
        patch("src.orchestration.handlers._dig_answer_via_dnspython", return_value=""),
        patch("src.orchestration.handlers.execute_command", return_value=fallback) as ec,
    ):
        res = asyncio.run(_run_dig("svalbard.ca"))
    ec.assert_called_once()
    assert res == fallback
