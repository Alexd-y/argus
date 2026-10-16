"""Wave 5 / R-9.2 — LLM proposal → arbiter-verdict outcome linkage.

Pins the objective-label derivation and the isolated, best-effort persistence
that links each finding an LLM proposal produced to the wave-1 arbiter verdict.
"""

from __future__ import annotations

import asyncio

import pytest
from src.llm import invocation_outcome
from src.llm.invocation_outcome import (
    OutcomeRecord,
    derive_outcome,
    persist_invocation_outcomes,
)


@pytest.mark.parametrize(
    "applicable,arbiter_tier,expected",
    [
        (False, 1, "not_applicable"),  # out-of-domain finding → no signal
        (True, None, "unknown"),  # applicable but arbiter produced nothing
        (True, 4, "confirmed"),  # EXPLOITED
        (True, 3, "confirmed"),  # CONFIRMED
        (True, 2, "suspected"),  # only SUSPECTED artifacts
        (True, 1, "rejected"),  # INFORMATIONAL — nothing proven
    ],
)
def test_derive_outcome(applicable, arbiter_tier, expected):
    assert derive_outcome(applicable=applicable, arbiter_tier=arbiter_tier) == expected


class _FakeSession:
    def __init__(self):
        self.added = []
        self.committed = False
        self.tenant = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True


@pytest.fixture
def _fake_db(monkeypatch):
    session = _FakeSession()

    async def _set_tenant(sess, tenant_id):
        sess.tenant = tenant_id

    monkeypatch.setattr("src.db.session.async_session_factory", lambda: session)
    monkeypatch.setattr("src.db.session.set_session_tenant", _set_tenant)
    return session


def test_persist_writes_rows_with_derived_outcome(_fake_db):
    records = [
        OutcomeRecord(
            finding_id="f1",
            vuln_class="sqli",
            phase="vuln_analysis",
            task="VULN_ANALYSIS",
            model_tier=4,
            arbiter_tier=3,
            applicable=True,
        ),
        OutcomeRecord(
            finding_id="f2",
            vuln_class="xss",
            model_tier=3,
            arbiter_tier=1,
            applicable=True,
        ),
    ]
    n = asyncio.run(
        persist_invocation_outcomes(tenant_id="tenant-a", scan_id="scan-a", records=records)
    )
    assert n == 2
    assert _fake_db.committed is True
    assert _fake_db.tenant == "tenant-a"
    assert [r.outcome for r in _fake_db.added] == ["confirmed", "rejected"]
    assert _fake_db.added[0].tenant_id == "tenant-a"
    assert _fake_db.added[0].finding_id == "f1"


def test_persist_noop_on_empty_or_missing_tenant(_fake_db):
    assert asyncio.run(persist_invocation_outcomes(tenant_id="t", scan_id="s", records=[])) == 0
    assert (
        asyncio.run(
            persist_invocation_outcomes(
                tenant_id="", scan_id="s", records=[OutcomeRecord(finding_id="f")]
            )
        )
        == 0
    )
    assert _fake_db.added == []


def test_persist_is_best_effort(monkeypatch):
    def _boom():
        raise RuntimeError("db down")

    monkeypatch.setattr("src.db.session.async_session_factory", _boom)
    n = asyncio.run(
        persist_invocation_outcomes(
            tenant_id="t", scan_id="s", records=[OutcomeRecord(finding_id="f", applicable=True)]
        )
    )
    assert n == 0


def test_module_exports():
    assert set(invocation_outcome.__all__) == {
        "OutcomeRecord",
        "derive_outcome",
        "persist_invocation_outcomes",
    }
