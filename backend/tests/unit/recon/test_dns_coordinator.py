"""Block 2 wiring — DNS-security coordinator with a fake command runner.

The fake runner models probe semantics: a *matched* command "ran" (success
True, output may be empty = genuinely-absent record); an *unmatched* command
"failed" (success False = network/timeout), which the coordinator treats as
unknown rather than absent.
"""

from __future__ import annotations

import pytest
from src.recon.dns_security.coordinator import collect_dns_security_findings

D = "alleksy.com"


def _make_runner(responses: dict[str, str]):
    async def _run(cmd: str, use_sandbox: bool = False) -> dict:
        del use_sandbox
        for needle, out in responses.items():
            if needle in cmd:
                return {"stdout": out, "success": True}
        return {"stdout": "", "success": False}

    return _run


@pytest.mark.asyncio
async def test_full_weak_domain_produces_expected_findings():
    # All probes RAN (success True) but records are absent (empty) → "missing".
    responses = {
        "DNSKEY": f"{D}. 3600 IN A 1.2.3.4\n",  # unsigned: no DNSKEY/RRSIG
        "CAA +short": "",  # no CAA
        "_dmarc.alleksy.com TXT": "",  # no DMARC (checked before apex TXT)
        f"dig {D} TXT +short": "",  # no SPF
        "_domainkey": "",  # no DKIM
        "NS +short": f"ns1.{D}.\n",
        "AXFR": "; Transfer failed.\n",  # refused
        "subfinder": f"www.{D}\napi.{D}\n",
    }
    subdomains, findings = await collect_dns_security_findings(
        D, run_cmd=_make_runner(responses), dkim_selectors=("default",)
    )
    titles = " ".join(f["title"] for f in findings)
    assert "SPF record missing" in titles
    assert "DMARC record missing" in titles
    assert "DNSSEC not enabled" in titles
    assert "No CAA record" in titles
    assert "DKIM not detected" in titles
    assert "zone transfer" not in titles.lower()  # AXFR refused
    assert subdomains == [f"api.{D}", f"www.{D}"]


@pytest.mark.asyncio
async def test_failed_probes_do_not_emit_missing_findings():
    # Nothing matches → every probe "fails" (success False) → no missing findings.
    async def _all_fail(cmd: str, use_sandbox: bool = False) -> dict:
        del cmd, use_sandbox
        return {"stdout": "", "success": False}

    subs, findings = await collect_dns_security_findings(
        D, run_cmd=_all_fail, dkim_selectors=("default",)
    )
    assert findings == []
    assert subs == []


@pytest.mark.asyncio
async def test_clean_domain_no_findings():
    responses = {
        "DNSKEY": f"{D}. IN DNSKEY 257 3 13 abc\n{D}. IN RRSIG DNSKEY 13 2 3600 x\n",
        "CAA +short": '0 issue "letsencrypt.org"\n',
        "_dmarc.alleksy.com TXT": "v=DMARC1; p=reject; rua=mailto:d@alleksy.com\n",
        f"dig {D} TXT +short": "v=spf1 include:_spf.google.com -all\n",
        "_domainkey": "v=DKIM1; k=rsa; p=MIGf...\n",
        "NS +short": f"ns1.{D}.\n",
        "AXFR": "; Transfer failed.\n",
        "subfinder": "",
    }
    _subs, findings = await collect_dns_security_findings(
        D, run_cmd=_make_runner(responses), dkim_selectors=("default",)
    )
    assert findings == []


@pytest.mark.asyncio
async def test_axfr_open_is_flagged():
    axfr_ok = (
        f"{D}. 3600 IN SOA ns1.{D}. admin.{D}. 1 7200 3600 1209600 3600\n"
        f"www.{D}. 3600 IN A 1.2.3.4\n"
        f"{D}. 3600 IN SOA ns1.{D}. admin.{D}. 1 7200 3600 1209600 3600\n"
    )
    responses = {
        "NS +short": f"ns1.{D}.\n",
        "AXFR": axfr_ok,
        "DNSKEY": f"{D}. IN DNSKEY 257 3 13 abc\n{D}. IN RRSIG DNSKEY 13 2 3600 x\n",
        "CAA +short": '0 issue "letsencrypt.org"\n',
        f"dig {D} TXT +short": "v=spf1 -all\n",
        "_dmarc.alleksy.com TXT": "v=DMARC1; p=reject; rua=mailto:d@alleksy.com\n",
        "_domainkey": "v=DKIM1; k=rsa; p=x\n",
        "subfinder": "",
    }
    _subs, findings = await collect_dns_security_findings(
        D, run_cmd=_make_runner(responses), dkim_selectors=("default",)
    )
    assert any("zone transfer (axfr) allowed" in f["title"].lower() for f in findings)


@pytest.mark.asyncio
async def test_all_probes_raising_is_safe():
    async def _dead(cmd: str, use_sandbox: bool = False) -> dict:
        del cmd, use_sandbox
        raise RuntimeError("network down")

    subs, findings = await collect_dns_security_findings(
        D, run_cmd=_dead, dkim_selectors=("default",), emails=["sd@alleksy.com"]
    )
    assert findings == []  # probes failed → unknown, not "missing"
    assert subs == []
