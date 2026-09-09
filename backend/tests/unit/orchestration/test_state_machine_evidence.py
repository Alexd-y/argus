"""Isolation contract for finding-evidence materialisation (ARGUS-WSTG-COV-1).

Evidence is *auxiliary provenance*: a failure in the MinIO upload or the
Evidence INSERT must never propagate out of ``_materialise_finding_evidence``
(and therefore never roll back findings / fail the scan). These tests pin that
contract with a minimal fake session so the regression that produced a
``failed`` scan with 0 persisted findings cannot recur.
"""

from __future__ import annotations

import pytest
from src.orchestration import state_machine
from src.orchestration.state_machine import _materialise_finding_evidence


class _FakeNested:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        # Do not suppress — mirror a real SAVEPOINT context manager.
        return False


class _FakeScalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _FakeScalars(self._rows)


class _FakeFinding:
    def __init__(
        self,
        *,
        id,
        proof_of_concept=None,
        evidence_refs=None,
        description=None,
        reproducible_steps=None,
    ):
        self.id = id
        self.proof_of_concept = proof_of_concept
        self.evidence_refs = evidence_refs
        self.description = description
        self.reproducible_steps = reproducible_steps


class _FakeSession:
    def __init__(self, *, merge_raises: bool = False, rows=None, commit_raises: bool = False):
        self.merge_raises = merge_raises
        self.commit_raises = commit_raises
        self.rows = rows or []
        self.merged: list[object] = []
        self.flushed = 0
        self.commits = 0
        self.rollbacks = 0

    async def flush(self):
        self.flushed += 1

    def begin_nested(self):
        return _FakeNested()

    async def merge(self, obj):
        if self.merge_raises:
            raise RuntimeError("db boom")
        self.merged.append(obj)
        return obj

    async def execute(self, *_a, **_k):
        return _FakeResult(self.rows)

    async def commit(self):
        self.commits += 1
        if self.commit_raises:
            raise RuntimeError("commit boom")

    async def rollback(self):
        self.rollbacks += 1


async def test_poc_materialises_single_evidence_row(monkeypatch):
    monkeypatch.setattr(state_machine, "upload_finding_poc_json", lambda *a, **k: "t/s/poc/F.json")
    session = _FakeSession()
    await _materialise_finding_evidence(
        session,
        tenant_id="t",
        scan_id="s",
        finding_id="F",
        poc_db={"url": "https://x", "response": "y"},
        evidence_refs=None,
        description=None,
        reproducible_steps=None,
    )
    assert len(session.merged) == 1
    assert session.merged[0].object_key == "t/s/poc/F.json"


async def test_observation_path_materialises_from_refs(monkeypatch):
    monkeypatch.setattr(state_machine, "upload_finding_poc_json", lambda *a, **k: "t/s/poc/F.json")
    session = _FakeSession()
    await _materialise_finding_evidence(
        session,
        tenant_id="t",
        scan_id="s",
        finding_id="F",
        poc_db=None,
        evidence_refs=["dns_scan.json:4"],
        description="No CAA record",
        reproducible_steps=None,
    )
    assert len(session.merged) == 1


async def test_no_artifact_no_evidence(monkeypatch):
    # No poc_db and no evidence_refs → nothing uploaded, no rows (never fabricated).
    called = {"n": 0}

    def _up(*_a, **_k):
        called["n"] += 1
        return "k"

    monkeypatch.setattr(state_machine, "upload_finding_poc_json", _up)
    session = _FakeSession()
    await _materialise_finding_evidence(
        session,
        tenant_id="t",
        scan_id="s",
        finding_id="F",
        poc_db=None,
        evidence_refs=[],
        description="obs",
        reproducible_steps=None,
    )
    assert called["n"] == 0
    assert session.merged == []


async def test_upload_failure_is_swallowed(monkeypatch):
    def _boom(*_a, **_k):
        raise RuntimeError("minio down")

    monkeypatch.setattr(state_machine, "upload_finding_poc_json", _boom)
    session = _FakeSession()
    # Must NOT raise — evidence is best-effort.
    await _materialise_finding_evidence(
        session,
        tenant_id="t",
        scan_id="s",
        finding_id="F",
        poc_db={"url": "https://x"},
        evidence_refs=None,
        description=None,
        reproducible_steps=None,
    )
    assert session.merged == []


async def test_persist_failure_is_swallowed(monkeypatch):
    monkeypatch.setattr(state_machine, "upload_finding_poc_json", lambda *a, **k: "t/s/poc/F.json")
    session = _FakeSession(merge_raises=True)
    # A DB error inside the SAVEPOINT must be contained, not propagated.
    await _materialise_finding_evidence(
        session,
        tenant_id="t",
        scan_id="s",
        finding_id="F",
        poc_db={"url": "https://x"},
        evidence_refs=None,
        description=None,
        reproducible_steps=None,
    )
    assert session.merged == []


# --------------------------------------------------------------------------- #
# _materialise_scan_evidence — post-commit, orphan-free scan-level pass.
# --------------------------------------------------------------------------- #
async def test_scan_evidence_processes_committed_findings(monkeypatch):
    monkeypatch.setattr(
        state_machine, "upload_finding_poc_json", lambda *a, **k: f"t/s/poc/{a[3]}.json"
    )
    rows = [
        _FakeFinding(id="F1", proof_of_concept={"url": "https://x", "response": "y"}),
        _FakeFinding(id="F2", evidence_refs=["dns_scan.json:4"], description="No CAA record"),
        _FakeFinding(id="F3"),  # no artifact → skipped, never fabricated
    ]
    session = _FakeSession(rows=rows)
    from src.orchestration.state_machine import _materialise_scan_evidence

    n = await _materialise_scan_evidence(session, "t", "s")
    assert n == 3
    # Two findings had artifacts → two Evidence rows; F3 produced none.
    assert len(session.merged) == 2
    assert session.commits == 1


async def test_scan_evidence_commit_failure_is_swallowed(monkeypatch):
    monkeypatch.setattr(state_machine, "upload_finding_poc_json", lambda *a, **k: "t/s/poc/F.json")
    rows = [_FakeFinding(id="F1", proof_of_concept={"url": "https://x"})]
    session = _FakeSession(rows=rows, commit_raises=True)
    from src.orchestration.state_machine import _materialise_scan_evidence

    # Must not raise; rollback attempted after failed commit.
    n = await _materialise_scan_evidence(session, "t", "s")
    assert n == 1
    assert session.rollbacks == 1


async def test_scan_evidence_no_findings_commits_empty(monkeypatch):
    monkeypatch.setattr(state_machine, "upload_finding_poc_json", lambda *a, **k: "k")
    session = _FakeSession(rows=[])
    from src.orchestration.state_machine import _materialise_scan_evidence

    n = await _materialise_scan_evidence(session, "t", "s")
    assert n == 0
    assert session.merged == []
    assert session.commits == 1


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
