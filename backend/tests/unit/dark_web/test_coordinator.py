"""Coordinator: pure observation assembly + sweep (no DB/MinIO) + audit chain."""

from __future__ import annotations

import pytest

from src.intel.dark_web.catalog import load_catalog
from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    ExposureType,
    SelectorKind,
    SourceNetwork,
)
from src.intel.dark_web.coordinator import build_observations_from_raw, run_sweep

_RULES = load_catalog().classifier_rules


def test_build_observations_classifies_and_redacts() -> None:
    sel = DarkWebSelector(kind=SelectorKind.EMAIL, value="alice@acme.com")
    rec = DarkWebRawRecord(
        selector_id=sel.id,
        source_network=SourceNetwork.BREACH_DB,
        source_ref="dehashed:SomeBreach",
        exposure_hint=ExposureType.CREDENTIAL,
        content="combolist alice@acme.com:TopSecret123 from redline stealer",
    )
    obs = build_observations_from_raw([(sel, [rec])], classifier_rules=_RULES)
    assert len(obs) == 1
    o = obs[0]
    assert o.exposure_type in (ExposureType.CREDENTIAL, ExposureType.STEALER_LOG)
    assert o.evidence_tier == 2
    assert "TopSecret123" not in o.redacted_summary
    assert len(o.raw_sha256) == 64
    assert o.selector_value_hash  # provenance


class _StubCollector(BaseCollector):
    name = "stub"
    network = SourceNetwork.BREACH_DB
    accepts = (SelectorKind.EMAIL,)

    def is_enabled(self) -> bool:
        return True

    async def collect(self, selector: DarkWebSelector):  # type: ignore[override]
        return [
            DarkWebRawRecord(
                selector_id=selector.id,
                source_network=SourceNetwork.BREACH_DB,
                source_ref="stub:breach",
                exposure_hint=ExposureType.CREDENTIAL,
                content=f"{selector.value}:password123 combolist",
            )
        ]


@pytest.mark.asyncio
async def test_run_sweep_no_persistence() -> None:
    sel = DarkWebSelector(kind=SelectorKind.EMAIL, value="a@acme.com")
    report = await run_sweep(
        session=None,
        tenant_id="not-a-uuid",
        scan_id="scan1",
        selectors=[sel],
        target="acme.com",
        collectors=[_StubCollector()],
        store_raw=False,
        persist=False,
        audit=False,
    )
    assert report.status.value == "present"
    assert len(report.observations) == 1
    assert report.observations[0].evidence_tier == 2


@pytest.mark.asyncio
async def test_run_sweep_empty_when_no_collectors_enabled() -> None:
    sel = DarkWebSelector(kind=SelectorKind.EMAIL, value="a@acme.com")
    report = await run_sweep(
        session=None, tenant_id="t", scan_id="s", selectors=[sel],
        collectors=[], store_raw=False, persist=False, audit=False,
    )
    assert report.status.value == "ran_empty"
    assert report.observations == []


@pytest.mark.asyncio
async def test_run_sweep_audit_sets_chain_hash_for_uuid_tenant() -> None:
    import uuid

    sel = DarkWebSelector(kind=SelectorKind.EMAIL, value="a@acme.com")
    report = await run_sweep(
        session=None,
        tenant_id=str(uuid.uuid4()),
        scan_id=str(uuid.uuid4()),
        selectors=[sel],
        collectors=[_StubCollector()],
        store_raw=False,
        persist=False,
        audit=True,
    )
    assert report.observations
    assert len(report.observations[0].chain_hash) == 64
