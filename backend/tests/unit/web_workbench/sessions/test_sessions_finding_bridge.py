"""Unit tests for the authorization finding → FindingDTO bridge (WB-P6b)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from src.pipeline.contracts.finding_dto import ConfidenceLevel, EvidenceTier, FindingCategory
from src.playbooks.oracles import OracleVerdict
from src.web_workbench.checks.authorization_analyzer import AuthorizationFinding, AuthzClass
from src.web_workbench.sessions.finding_bridge import authorization_finding_to_dto

_IDS = {
    "tenant_id": uuid4(),
    "scan_id": uuid4(),
    "asset_id": uuid4(),
    "tool_run_id": uuid4(),
}


def _finding(
    classification: AuthzClass, *, object_id: str | None = "12345"
) -> AuthorizationFinding:
    return AuthorizationFinding(
        classification=classification,
        verdict=OracleVerdict.FINDING,
        confidence=ConfidenceLevel.CONFIRMED,
        reason="attacker read the victim's sensitive field(s): ssn",
        principal="mallory",
        location="GET /api/orders/12345",
        object_id=object_id,
        differing_fields=("ssn",),
    )


def test_idor_maps_to_idor_category_and_cwe() -> None:
    dto = authorization_finding_to_dto(_finding(AuthzClass.IDOR), **_IDS)
    assert dto.category is FindingCategory.IDOR
    assert dto.cwe == [639]
    assert dto.evidence_tier is EvidenceTier.CONFIRMED
    assert dto.confidence is ConfidenceLevel.CONFIRMED


def test_bfla_maps_to_auth_category() -> None:
    dto = authorization_finding_to_dto(_finding(AuthzClass.BFLA, object_id=None), **_IDS)
    assert dto.category is FindingCategory.AUTH
    assert dto.cwe == [862]


def test_unauth_access_maps_to_auth_category() -> None:
    dto = authorization_finding_to_dto(_finding(AuthzClass.UNAUTH_ACCESS), **_IDS)
    assert dto.category is FindingCategory.AUTH
    assert dto.cwe == [306]


def test_summary_carries_field_paths_not_values() -> None:
    dto = authorization_finding_to_dto(_finding(AuthzClass.IDOR), **_IDS)
    assert dto.remediation is not None
    assert "ssn" in dto.remediation.summary
    assert "111-22-3333" not in dto.remediation.summary  # never a value


def test_valid_cvss_vector() -> None:
    dto = authorization_finding_to_dto(_finding(AuthzClass.IDOR), **_IDS)
    assert dto.cvss_v3_vector.startswith("CVSS:3.1/")
    assert 0.0 <= dto.cvss_v3_score <= 10.0
