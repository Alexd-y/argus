"""P1 — AliasRegistry.load_from_db merges per-tenant overrides from the DB."""

from __future__ import annotations

import pytest
from src.llm.model_aliases import AliasRegistry


class _Row:
    def __init__(self, alias: str, role: str, providers: list) -> None:
        self.alias = alias
        self.role = role
        self.providers = providers


class _Scalars:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def all(self) -> list:
        return self._rows


class _Result:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self) -> _Scalars:
        return _Scalars(self._rows)


class _FakeSession:
    def __init__(self, rows: list | None = None, raise_exc: Exception | None = None) -> None:
        self._rows = rows or []
        self._exc = raise_exc
        self.last_sql: str = ""

    async def execute(self, statement, *_a, **_k) -> _Result:
        self.last_sql = str(statement)
        if self._exc is not None:
            raise self._exc
        return _Result(self._rows)


@pytest.mark.asyncio
async def test_db_row_overrides_default_alias() -> None:
    reg = AliasRegistry()
    assert reg.resolve("argus-pentest-primary") is not None  # from defaults
    session = _FakeSession(
        rows=[
            _Row(
                "argus-pentest-primary",
                "pentest",
                [{"key": "custom-7b", "base_url": "http://local:8000", "model": "m", "cloud_allowed": False}],
            )
        ]
    )
    await reg.load_from_db(session, tenant_id="t1")
    entry = reg.resolve("argus-pentest-primary")
    assert entry is not None
    assert entry.providers[0].key == "custom-7b"
    assert entry.providers[0].base_url == "http://local:8000"
    # query is explicitly tenant-scoped (no reliance on RLS alone)
    assert "WHERE" in session.last_sql and "tenant_id" in session.last_sql


@pytest.mark.asyncio
async def test_db_row_adds_new_alias_and_filters_unknown_keys() -> None:
    reg = AliasRegistry()
    assert reg.resolve("tenant-custom") is None
    session = _FakeSession(
        rows=[
            _Row(
                "tenant-custom",
                "code",
                # includes an unknown key that must be filtered, not crash
                [{"key": "x", "model": "y", "cloud_allowed": True, "bogus_field": 1}],
            )
        ]
    )
    await reg.load_from_db(session, tenant_id="t1")
    entry = reg.resolve("tenant-custom")
    assert entry is not None
    assert entry.role == "code"
    assert entry.providers[0].key == "x"
    assert reg.is_cloud("tenant-custom") is True


@pytest.mark.asyncio
async def test_db_error_keeps_defaults() -> None:
    reg = AliasRegistry()
    before = reg.resolve("argus-pentest-primary")
    assert before is not None
    session = _FakeSession(raise_exc=RuntimeError("relation does not exist"))
    await reg.load_from_db(session, tenant_id="t1")  # must not raise
    after = reg.resolve("argus-pentest-primary")
    assert after is not None
    assert after.providers[0].key == before.providers[0].key  # unchanged


@pytest.mark.asyncio
async def test_empty_tenant_id_is_noop() -> None:
    reg = AliasRegistry()
    session = _FakeSession(rows=[_Row("x", "code", [{"key": "k"}])])
    await reg.load_from_db(session, tenant_id="")  # no tenant → skip, no query
    assert reg.resolve("x") is None
    assert session.last_sql == ""  # execute never called
