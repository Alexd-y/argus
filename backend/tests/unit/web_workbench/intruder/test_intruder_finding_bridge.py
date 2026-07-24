"""Unit tests for the Intruder flagged-result → FindingDTO bridge (WB-P4b)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.pipeline.contracts.finding_dto import ConfidenceLevel, EvidenceTier, FindingCategory
from src.web_workbench.intruder.finding_bridge import flagged_request_to_finding
from src.web_workbench.intruder.repository import IntruderRequestDTO

_IDS = {
    "tenant_id": uuid4(),
    "scan_id": uuid4(),
    "asset_id": uuid4(),
    "tool_run_id": uuid4(),
}


def _request(*, flagged: bool = True) -> IntruderRequestDTO:
    return IntruderRequestDTO(
        id="req-1",
        tenant_id="t-1",
        project_id="p-1",
        attack_id="a-1",
        request_index=7,
        payload_label="sqli[3]",
        payload_index=7,
        forward_outcome="forward",
        block_reason=None,
        status_code=500,
        response_length=1234,
        response_time_ms=42,
        response_sha256="a" * 64,
        flagged=flagged,
        error_reason=None,
        created_at=datetime.now(tz=timezone.utc),
    )


def test_flagged_request_maps_to_suspected_finding() -> None:
    dto = flagged_request_to_finding(
        _request(),
        attack_name="orders-fuzz",
        attack_config={"finding": {"category": "sqli", "cwe": [89]}},
        **_IDS,
    )
    assert dto.category is FindingCategory.SQLI
    assert dto.cwe == [89]
    assert dto.confidence is ConfidenceLevel.SUSPECTED
    assert dto.evidence_tier is EvidenceTier.SUSPECTED


def test_missing_config_falls_back_to_generic() -> None:
    dto = flagged_request_to_finding(_request(), attack_name="a", **_IDS)
    assert dto.category is FindingCategory.OTHER
    assert dto.cwe == [20]


def test_unknown_category_falls_back_to_other() -> None:
    dto = flagged_request_to_finding(
        _request(), attack_name="a", attack_config={"finding": {"category": "not-a-cat"}}, **_IDS
    )
    assert dto.category is FindingCategory.OTHER


def test_non_flagged_request_rejected() -> None:
    with pytest.raises(ValueError, match="flagged"):
        flagged_request_to_finding(_request(flagged=False), attack_name="a", **_IDS)


def test_summary_references_payload_not_raw_value() -> None:
    dto = flagged_request_to_finding(_request(), attack_name="orders-fuzz", **_IDS)
    assert dto.remediation is not None
    assert "sqli[3]" in dto.remediation.summary
