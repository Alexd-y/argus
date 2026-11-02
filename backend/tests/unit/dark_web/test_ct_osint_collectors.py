"""§6 free OSINT collectors: CT logs + Shodan InternetDB, dedup, classification."""

from __future__ import annotations

import asyncio

import pytest
from src.intel.dark_web.catalog import load_catalog
from src.intel.dark_web.classifier import classify
from src.intel.dark_web.collectors import ct_logs
from src.intel.dark_web.collectors.ct_logs import (
    CertSpotterCollector,
    CrtShCollector,
    ShodanInternetDbCollector,
)
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    DarkWebSeverity,
    ExposureType,
    SelectorKind,
    SourceNetwork,
)
from src.intel.dark_web.coordinator import build_observations_from_raw

DOMAIN = "svalbard.ca"


class _FakeClient:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def is_available(self) -> bool:
        return True

    async def query(self, **_: object) -> dict[str, object]:
        return {"available": True, "data": self._payload}


def _selector() -> DarkWebSelector:
    return DarkWebSelector(kind=SelectorKind.DOMAIN, value=DOMAIN)


def test_crtsh_collector_extracts_in_scope_subdomains_only() -> None:
    client = _FakeClient(
        [
            {"name_value": "api.svalbard.ca\nwww.svalbard.ca"},
            {"common_name": "*.mail.svalbard.ca"},
            {"name_value": "attacker-evil.com"},  # out of scope -> dropped
        ]
    )
    recs = asyncio.run(CrtShCollector(client=client).collect(_selector()))
    refs = sorted(r.source_ref for r in recs)
    assert refs == ["api.svalbard.ca", "mail.svalbard.ca", "www.svalbard.ca"]
    assert all(r.source_network == SourceNetwork.CLEARNET_INDEX for r in recs)


def test_certspotter_collector_extracts_dns_names() -> None:
    client = _FakeClient([{"dns_names": ["dev.svalbard.ca", "svalbard.ca", "other.org"]}])
    recs = asyncio.run(CertSpotterCollector(client=client).collect(_selector()))
    assert sorted(r.source_ref for r in recs) == ["dev.svalbard.ca", "svalbard.ca"]


def test_ct_hits_from_both_sources_dedupe_to_one_observation() -> None:
    sel = _selector()
    crt = asyncio.run(
        CrtShCollector(client=_FakeClient([{"name_value": "api.svalbard.ca"}])).collect(sel)
    )
    cs = asyncio.run(
        CertSpotterCollector(client=_FakeClient([{"dns_names": ["api.svalbard.ca"]}])).collect(sel)
    )
    # Same subdomain, same network, identical content -> one observation after dedup.
    obs = build_observations_from_raw([(sel, crt), (sel, cs)])
    assert len(obs) == 1
    assert obs[0].source_ref == "api.svalbard.ca"


def test_shodan_collector_emits_cve_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_resolve(domain: str, max_ips: int = 3) -> list[str]:
        return ["203.0.113.10"]

    monkeypatch.setattr(ct_logs, "_resolve_ips", _fake_resolve)
    client = _FakeClient(None)

    async def _query(**_: object) -> dict[str, object]:
        return {"available": True, "data": {"ports": [22, 443], "vulns": ["CVE-2021-44228"]}}

    client.query = _query  # type: ignore[assignment]
    recs = asyncio.run(ShodanInternetDbCollector(client=client).collect(_selector()))
    assert len(recs) == 1
    assert "CVE-2021-44228" in recs[0].content
    assert recs[0].source_ref == "203.0.113.10"


def test_classifier_rules_score_new_exposure_signals() -> None:
    rules = load_catalog().classifier_rules
    ct = DarkWebRawRecord(
        source_network=SourceNetwork.CLEARNET_INDEX,
        source_ref="api.svalbard.ca",
        exposure_hint=ExposureType.MENTION,
        content="Subdomain 'api.svalbard.ca' observed in Certificate Transparency logs for svalbard.ca.",
    )
    assert classify(ct, rules).severity == DarkWebSeverity.INFO

    shodan = DarkWebRawRecord(
        source_network=SourceNetwork.FEED,
        source_ref="203.0.113.10",
        exposure_hint=ExposureType.MENTION,
        content="Exposed service at 203.0.113.10 (svalbard.ca). Open ports: 443. Known CVEs: CVE-2021-44228.",
    )
    c = classify(shodan, rules)
    assert c.severity == DarkWebSeverity.MEDIUM
    assert c.evidence_tier == 2  # still capped at SUSPECTED
