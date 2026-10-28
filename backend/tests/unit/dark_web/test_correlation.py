"""Correlation (T2) — provenance linked; evidence_tier NEVER changed."""

from __future__ import annotations

import pytest

from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    ExposureType,
    SelectorKind,
    SourceNetwork,
)
from src.intel.dark_web.correlation import attach_dark_web_provenance, correlate_findings


def test_attach_provenance_is_pure_and_idempotent() -> None:
    prov = attach_dark_web_provenance({"existing": 1}, ["o1", "o2"])
    assert prov["existing"] == 1
    assert prov["dark_web"] == ["o1", "o2"]
    # idempotent
    prov2 = attach_dark_web_provenance(prov, ["o2", "o3"])
    assert prov2["dark_web"] == ["o1", "o2", "o3"]


def test_attach_provenance_handles_non_dict() -> None:
    assert attach_dark_web_provenance(None, ["o1"])["dark_web"] == ["o1"]


class _Finding:
    """Finding-like object with the sensitive fields correlation must not touch."""

    def __init__(self) -> None:
        self.id = "f1"
        self.host = "acme.com"
        self.category = "known_cve"
        self.cve = "CVE-2021-1"
        self.evidence_tier = 3  # CONFIRMED — must stay 3
        self.confidence = "confirmed"
        self.verdict = "true_positive"
        self.provenance = None


class _StubCollector(BaseCollector):
    name = "stub_feed"
    network = SourceNetwork.FEED
    accepts = (SelectorKind.FINDING, SelectorKind.KEYWORD)

    def is_enabled(self) -> bool:
        return True

    async def collect(self, selector: DarkWebSelector):  # type: ignore[override]
        return [
            DarkWebRawRecord(
                selector_id=selector.id,
                source_network=SourceNetwork.FEED,
                source_ref="ransomware.live:acme",
                exposure_hint=ExposureType.ACCESS_SALE,
                content="acme.com listed for sale / ransomware victim",
            )
        ]


@pytest.mark.asyncio
async def test_correlation_links_provenance_without_touching_tier() -> None:
    finding = _Finding()
    report = await correlate_findings(
        session=None,
        tenant_id="t",
        scan_id="s",
        findings=[finding],
        collectors=[_StubCollector()],
        store_raw=False,
        persist=False,
        audit=False,
    )
    assert report.observations, "expected at least one correlated observation"
    # provenance linked
    assert finding.provenance is not None
    assert finding.provenance["dark_web"]
    assert all(oid for oid in finding.provenance["dark_web"])
    # the critical invariant: tier/confidence/verdict untouched
    assert finding.evidence_tier == 3
    assert finding.confidence == "confirmed"
    assert finding.verdict == "true_positive"
    # and the observation itself is capped at tier 2
    assert all(o.evidence_tier <= 2 for o in report.observations)
