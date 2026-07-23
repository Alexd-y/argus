"""Unit tests for Intruder + Session ORM models (WB-P4b / WB-P6b, offline).

Pure schema-level assertions (no database): verify the new tenant-scoped tables
declare the expected columns, tenant/project foreign keys, uniqueness and
optimistic-locking / kill-switch invariants. These guard the model contract so
the accompanying Alembic 051 migration and the (infra-gated) service layer stay
aligned.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Integer, LargeBinary, String

from src.db.models_web_workbench import (
    WbIntruderAttack,
    WbIntruderRequest,
    WbSessionMacro,
    WbSessionPrincipal,
)


def _cols(model: type) -> dict[str, object]:
    return {c.name: c for c in model.__table__.columns}


def _fk_targets(model: type) -> set[tuple[str, str]]:
    return {
        (fk.column.table.name, fk.column.name)
        for col in model.__table__.columns
        for fk in col.foreign_keys
    }


def test_table_names() -> None:
    assert WbIntruderAttack.__tablename__ == "wb_intruder_attacks"
    assert WbIntruderRequest.__tablename__ == "wb_intruder_requests"
    assert WbSessionMacro.__tablename__ == "wb_session_macros"
    assert WbSessionPrincipal.__tablename__ == "wb_session_principals"


def test_intruder_attack_columns_and_invariants() -> None:
    cols = _cols(WbIntruderAttack)
    # byte-exact request template is required and stored as raw bytes.
    assert isinstance(cols["raw_request_template"].type, LargeBinary)
    assert cols["raw_request_template"].nullable is False
    # optimistic lock + kill-switch status column present.
    assert isinstance(cols["version"].type, Integer)
    assert cols["version"].nullable is False
    assert isinstance(cols["status"].type, String)
    # payload references live in JSON config, never as raw payload bytes.
    assert "payload_config" in cols
    assert "raw_request_template" in cols
    # audit provenance without raw identity.
    assert "created_by_subject_hash" in cols
    # tenant + project isolation FKs.
    assert ("tenants", "id") in _fk_targets(WbIntruderAttack)
    assert ("wb_projects", "id") in _fk_targets(WbIntruderAttack)


def test_intruder_attack_unique_name_per_project() -> None:
    uniques = {
        tuple(sorted(col.name for col in c.columns))
        for c in WbIntruderAttack.__table__.constraints
        if c.__class__.__name__ == "UniqueConstraint"
    }
    assert ("name", "project_id", "tenant_id") in uniques


def test_intruder_request_is_metadata_only() -> None:
    cols = _cols(WbIntruderRequest)
    # No inline body columns — high-volume rows stay metadata-only.
    assert not any(isinstance(c.type, LargeBinary) for c in cols.values())
    # Forward-gate verdict + block reason recorded for every attempt (audit).
    assert cols["forward_outcome"].nullable is False
    assert "block_reason" in cols
    # Payload identified by reference, not by raw value.
    assert "payload_label" in cols
    assert "payload_index" in cols
    assert isinstance(cols["flagged"].type, Boolean)
    assert ("wb_intruder_attacks", "id") in _fk_targets(WbIntruderRequest)


def test_intruder_request_unique_index_per_attack() -> None:
    uniques = {
        tuple(sorted(col.name for col in c.columns))
        for c in WbIntruderRequest.__table__.constraints
        if c.__class__.__name__ == "UniqueConstraint"
    }
    assert ("attack_id", "request_index", "tenant_id") in uniques


def test_session_principal_split_plane_secrets() -> None:
    cols = _cols(WbSessionPrincipal)
    # Credentials are referenced, never stored inline (SI-3 split-plane).
    assert "secrets_ref" in cols
    assert not any(name in cols for name in ("password", "token", "secret", "credentials"))
    assert cols["role"].nullable is False
    assert isinstance(cols["version"].type, Integer)
    # macro link is optional (SET NULL on delete) and points at session macros.
    assert ("wb_session_macros", "id") in _fk_targets(WbSessionPrincipal)
    assert cols["macro_id"].nullable is True
    assert ("tenants", "id") in _fk_targets(WbSessionPrincipal)
    assert ("wb_projects", "id") in _fk_targets(WbSessionPrincipal)


def test_session_macro_has_no_inline_secrets() -> None:
    cols = _cols(WbSessionMacro)
    # Steps/match-rules are JSON; no raw secret columns.
    assert "steps" in cols
    assert "match_rules" in cols
    assert not any(name in cols for name in ("password", "token", "secret", "credentials"))
    assert isinstance(cols["version"].type, Integer)
    assert ("wb_projects", "id") in _fk_targets(WbSessionMacro)


def test_all_new_models_are_tenant_scoped() -> None:
    for model in (WbIntruderAttack, WbIntruderRequest, WbSessionMacro, WbSessionPrincipal):
        cols = _cols(model)
        assert "tenant_id" in cols, f"{model.__tablename__} missing tenant_id"
        assert cols["tenant_id"].nullable is False
        assert ("tenants", "id") in _fk_targets(model)
