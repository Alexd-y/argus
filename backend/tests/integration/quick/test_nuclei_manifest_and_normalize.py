"""QUICK-009 — mocked Nuclei manifest + normalize (no live scanner)."""

from __future__ import annotations

from typing import Any

import pytest
from src.nuclei.template_registry import NucleiTemplateRegistry
from src.quick.normalize import QuickNormalizeContext, normalize_tool_output
from src.quick.schemas import (
    AssetFingerprint,
    FingerprintFact,
    QuickProfileName,
    QuickScanConfig,
    SeverityFloor,
)
from src.quick.template_selector import QuickTemplateSelector

_FAKE_ARTIFACT = "t/s/vuln_analysis/raw/quick_tool_raw.json"


@pytest.fixture(autouse=True)
def _mock_minio(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.quick.normalize.sink_raw_json", lambda **_kwargs: _FAKE_ARTIFACT)


def test_nuclei_manifest_and_normalize_mocked() -> None:
    config = QuickScanConfig(
        profile=QuickProfileName.BALANCED,
        wall_clock_budget_seconds=900,
        ai_budget_seconds=90,
        reserve_for_validation_percent=20,
        max_targets=10,
        max_urls_per_host=50,
        crawl_depth=2,
        severity_floor=SeverityFloor.MEDIUM,
    )
    fingerprint = AssetFingerprint(
        asset_id="abcdef01-2345-6789-abcd-ef0123456789",
        protocol=FingerprintFact(value="https", confidence=1.0),
        product=FingerprintFact(value="nginx", confidence=0.9),
    )
    selector = QuickTemplateSelector(registry=NucleiTemplateRegistry())
    manifest = selector.select(fingerprint, config)
    assert manifest.template_ids == tuple(sorted(manifest.template_ids))
    ctx = QuickNormalizeContext(
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        scan_id="11111111-2222-3333-4444-555555555555",
        engagement_id="99999999-8888-7777-6666-555555555555",
        asset_id=fingerprint.asset_id,
        asset="https://app.example",
        tool_id="nuclei",
        tool_version="3.3.0",
        capability_id="web.application.cve.known_product",
        phase="vuln_analysis",
        task_id="fedcba98-7654-3210-fedc-ba9876543210",
        policy_decision_id="01234567-89ab-cdef-0123-456789abcdef",
        lease_id="aa11bb22-cc33-dd44-ee55-ff6677889900",
        template_id="http-cve-nginx",
        template_digest="b" * 64,
    )
    payload: dict[str, Any] = {
        "results": [
            {
                "template-id": "http-cve-nginx",
                "info": {"name": "nginx cve", "severity": "high"},
                "matched-at": "https://app.example/",
                "type": "http",
            }
        ]
    }
    result = normalize_tool_output(payload, ctx=ctx)
    assert isinstance(result, tuple)
