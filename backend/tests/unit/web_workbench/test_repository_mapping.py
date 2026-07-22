"""Unit tests for Web Workbench repository ORM<->domain mapping (WB-P1b).

Pure, no database: exercises the mapping helpers that translate between
:class:`ScopeRule` / DTOs and the ORM rows, ensuring round-trip fidelity of
scope semantics (kind, deny, port ranges) and the EAP projection.
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.db.models_web_workbench import (
    WbScopeRule,
    WebWorkbenchEapRecord,
    WebWorkbenchProject,
)
from src.policy.scope import PortRange, ScopeKind, ScopeRule
from src.web_workbench.contracts import ProjectStatus
from src.web_workbench.projects.repository import (
    _eap_to_view,
    _project_to_dto,
    _row_to_rule,
    _rule_to_row_kwargs,
)


def test_rule_to_row_kwargs_serialises_ports() -> None:
    rule = ScopeRule(
        kind=ScopeKind.URL,
        pattern="https://api.example.com/v1",
        ports=(PortRange(low=443, high=443),),
        note="prod api",
    )
    kwargs = _rule_to_row_kwargs(rule)
    assert kwargs["kind"] == "url"
    assert kwargs["ports"] == [{"low": 443, "high": 443}]
    assert kwargs["note"] == "prod api"
    assert kwargs["deny"] is False


def test_rule_to_row_kwargs_no_ports_is_none() -> None:
    rule = ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")
    assert _rule_to_row_kwargs(rule)["ports"] is None


def test_row_to_rule_round_trip() -> None:
    original = ScopeRule(
        kind=ScopeKind.CIDR,
        pattern="10.0.0.0/8",
        deny=True,
        ports=(PortRange(low=80, high=90),),
    )
    row = WbScopeRule(tenant_id="t", project_id="p", **_rule_to_row_kwargs(original))
    rebuilt = _row_to_rule(row)
    assert rebuilt == original


def test_eap_to_view_none_is_none() -> None:
    assert _eap_to_view(None) is None


def test_eap_to_view_projects_fields() -> None:
    expires = datetime(2026, 12, 31, tzinfo=timezone.utc)
    record = WebWorkbenchEapRecord(
        tenant_id="t",
        project_id="p",
        engagement_id="eng-1",
        signed_profile={"engagement_id": "eng-1"},
        signer_key_id="0123456789abcdef",
        status="verified",
        expires=expires,
    )
    view = _eap_to_view(record)
    assert view is not None
    assert view.engagement_id == "eng-1"
    assert view.status == "verified"
    assert view.signer_key_id == "0123456789abcdef"
    assert view.expires == expires


def test_project_to_dto_maps_all_fields() -> None:
    now = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)
    project = WebWorkbenchProject(
        id="proj-1",
        tenant_id="tenant-1",
        name="app",
        description="desc",
        status=ProjectStatus.ACTIVE.value,
        secrets_ref="vault://x",
        version=3,
    )
    project.created_at = now
    project.updated_at = now
    rules = [
        WbScopeRule(
            tenant_id="tenant-1",
            project_id="proj-1",
            **_rule_to_row_kwargs(ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")),
        )
    ]
    dto = _project_to_dto(project, rules, None)
    assert dto.id == "proj-1"
    assert dto.tenant_id == "tenant-1"
    assert dto.status is ProjectStatus.ACTIVE
    assert dto.version == 3
    assert dto.secrets_ref == "vault://x"
    assert len(dto.scope_rules) == 1
    assert dto.scope_rules[0].pattern == "example.com"
    assert dto.eap is None
