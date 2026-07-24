"""Offline unit tests for the Sessions router DTO mappers (WB-P6b).

Pure functions (repository dataclass → API contract). Verifies the split-plane
projection (only ``secret_ref``/``secrets_ref`` handles surface) without a DB.
"""

from __future__ import annotations

from datetime import UTC, datetime

from src.api.routers.web_workbench.sessions import _macro_to_api, _principal_to_api
from src.web_workbench.sessions.repository import SessionMacroDTO, SessionPrincipalDTO

_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)


def test_macro_mapper_carries_steps_and_rules() -> None:
    row = SessionMacroDTO(
        id="m-1",
        tenant_id="t-1",
        project_id="p-1",
        name="login",
        steps=[{"method": "POST", "target": "/login", "body": "u={{secret_ref:user}}"}],
        match_rules={"status": 200},
        config=None,
        version=3,
        created_at=_NOW,
        updated_at=_NOW,
    )
    dto = _macro_to_api(row)
    assert dto.name == "login"
    assert dto.match_rules == {"status": 200}
    assert dto.steps is not None
    assert dto.version == 3


def test_principal_mapper_only_exposes_secrets_ref_handle() -> None:
    row = SessionPrincipalDTO(
        id="pr-1",
        tenant_id="t-1",
        project_id="p-1",
        name="owner1",
        role="owner",
        secrets_ref="vault://tenant-a/owner1",
        macro_id="m-1",
        config=None,
        version=1,
        created_at=_NOW,
        updated_at=_NOW,
    )
    dto = _principal_to_api(row)
    assert dto.role == "owner"
    assert dto.secrets_ref == "vault://tenant-a/owner1"
    assert dto.macro_id == "m-1"
    # No raw-secret attribute is ever projected.
    assert not hasattr(dto, "password")
    assert not hasattr(dto, "secret")
