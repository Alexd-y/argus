"""Block 2 wiring — DNS-security coordinator with a fake command runner."""

from __future__ import annotations

import pytest
from src.recon.dns_security.coordinator import collect_dns_security_findings

D = "alleksy.com"


def _make_runner(responses: dict[str, str]):
    async def _run(cmd: str, use_sandbox: bool = False) -> dict:
        for needle, out in responses.items():
            if needle in cmd:
                return {"stdout": out, "success": bool(out)}
        return {"stdout": "", "success": False}

    return _run


@pytest.mark.asyncio
async def test_full_weak_domain_produces_expected_findings():
    responses = {
        f"dig {D} ANY": (
            f"{D}. 3600 IN A 1.2.3.4\n{D}. 3600 IN NS ns1.{D}.\n"
        ),
        "DNSKEY": f"{D}. 3600 IN A 1.2.3.4\n",  # unsigned: no DNSKEY/RRSIG
        f"dig {D} TXT": "",  # no SPF
        f"dig _dmarc.{D} TXT": "",  # no DMARC
        "_domainkey": "",  # no DKIM
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
    # AXFR refused => no zone-transfer finding
    assert "zone transfer" not in titles.lower()
    assert subdomains == [f"api.{D}", f"www.{D}"]


@pytest.mark.asyncio
async def test_axfr_open_is_flagged():
    axfr_ok = (
        f"{D}. 3600 IN SOA ns1.{D}. admin.{D}. 1 7200 3600 1209600 3600\n"
        f"www.{D}. 3600 IN A 1.2.3.4\n"
        f"{D}. 3600 IN SOA ns1.{D}. admin.{D}. 1 7200 3600 1209600 3600\n"
    )
    responses = {
        f"dig {D} ANY": f"{D}. 3600 IN NS ns1.{D}.\n",
        "AXFR": axfr_ok,
        "DNSKEY": f"{D}. IN DNSKEY 257 3 13 abc\n{D}. IN RRSIG DNSKEY 13 2 3600 x\n",
        "subfinder": "",
    }
    _subs, findings = await collect_dns_security_findings(
        D, run_cmd=_make_runner(responses), dkim_selectors=("default",)
    )
    assert any("zone transfer (axfr) allowed" in f["title"].lower() for f in findings)


@pytest.mark.asyncio
async def test_all_probes_failing_is_safe():
    async def _dead(cmd: str, use_sandbox: bool = False) -> dict:
        raise RuntimeError("network down")

    subs, findings = await collect_dns_security_findings(
        D, run_cmd=_dead, dkim_selectors=("default",)
    )
    # Empty outputs still yield the "missing" findings (SPF/DMARC/DNSSEC/CAA),
    # but the coordinator never raises.
    assert isinstance(findings, list)
    assert subs == []
