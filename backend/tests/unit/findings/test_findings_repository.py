"""Persistence tests for FindingsRepository (InMemory + SQLAlchemy/SQLite)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from src.db.models import Tenant
from src.findings.fingerprint import (
    compute_evidence_signal_hash,
    compute_finding_key,
    compute_occurrence_key,
)
from src.findings.lifecycle import (
    FindingAssessment,
    FindingLifecycleService,
    FindingOccurrence,
    FindingState,
    LogicalFinding,
)
from src.findings.repository import (
    InMemoryFindingsRepository,
    SqlAlchemyFindingsRepository,
    set_findings_repository,
)
from src.reports.coverage_occurrence_context import build_coverage_occurrence_context


def _finding_key(tenant_id: str, engagement_id: str = "eng-1") -> str:
    return compute_finding_key(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset="https://app.example",
        category="xss",
        normalized_location="/search",
        parameter_or_component="q",
        root_cause_family="reflected_input",
    )


@pytest.fixture
def memory_repo() -> InMemoryFindingsRepository:
    repo = InMemoryFindingsRepository()
    set_findings_repository(repo)
    yield repo
    set_findings_repository(InMemoryFindingsRepository())


@pytest.mark.asyncio
async def test_inmemory_persist_reload_and_scan_snapshots(
    memory_repo: InMemoryFindingsRepository,
) -> None:
    tenant_id = "t-1"
    key = _finding_key(tenant_id)
    finding = LogicalFinding(
        finding_key=key,
        tenant_id=tenant_id,
        engagement_id="eng-1",
        title="XSS",
        category="xss",
    )
    await memory_repo.upsert_logical_finding(finding, scan_id="scan-a")
    finding.state = FindingState.RESOLVED
    await memory_repo.upsert_logical_finding(finding, scan_id="scan-b")

    loaded = await memory_repo.get_logical_finding(tenant_id=tenant_id, finding_key=key)
    assert loaded is not None
    assert loaded.state is FindingState.RESOLVED

    snap_a = await memory_repo.list_logical_findings_for_scan(tenant_id=tenant_id, scan_id="scan-a")
    snap_b = await memory_repo.list_logical_findings_for_scan(tenant_id=tenant_id, scan_id="scan-b")
    assert snap_a[key].state is FindingState.CANDIDATE
    assert snap_b[key].state is FindingState.RESOLVED


@pytest.mark.asyncio
async def test_repository_has_no_delete_api(memory_repo: InMemoryFindingsRepository) -> None:
    assert not hasattr(memory_repo, "delete_logical_finding")
    assert not hasattr(memory_repo, "delete_occurrence")
    finding = LogicalFinding(
        finding_key=_finding_key("t-1"),
        tenant_id="t-1",
        engagement_id="eng-1",
    )
    with pytest.raises(RuntimeError, match="finding_deletion_forbidden"):
        FindingLifecycleService().delete_finding(finding)


@pytest.mark.asyncio
async def test_save_occurrence_bumps_last_seen(
    memory_repo: InMemoryFindingsRepository,
) -> None:
    tenant_id = "t-1"
    key = _finding_key(tenant_id)
    occ_key = compute_occurrence_key(
        finding_key=key,
        scanner="nuclei",
        detector_id="xss-reflected",
        detector_version="1.0.0",
        request_signature="GET /search",
        evidence_signal_hash=compute_evidence_signal_hash("payload"),
    )
    first = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
    second = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    base = FindingOccurrence(
        occurrence_key=occ_key,
        finding_key=key,
        tenant_id=tenant_id,
        scan_id="scan-1",
        scanner="nuclei",
        detector_id="xss-reflected",
        detector_version="1.0.0",
        evidence_refs=("ev-1",),
        first_seen_at=first,
        last_seen_at=first,
    )
    await memory_repo.save_occurrence(base)
    await memory_repo.save_occurrence(
        base.model_copy(update={"last_seen_at": second, "evidence_refs": ("ev-2",)})
    )
    listed = await memory_repo.list_occurrences_for_scan(tenant_id=tenant_id, scan_id="scan-1")
    assert len(listed) == 1
    assert listed[0].first_seen_at == first
    assert listed[0].last_seen_at == second
    assert "ev-1" in listed[0].evidence_refs
    assert "ev-2" in listed[0].evidence_refs


@pytest.fixture
async def sqlite_findings_env() -> AsyncIterator[
    tuple[SqlAlchemyFindingsRepository, str]
]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.execute(
            text(
                "CREATE TABLE tenants ("
                "id VARCHAR(36) PRIMARY KEY NOT NULL, "
                "name VARCHAR(255) NOT NULL)"
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE logical_findings ("
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, "
                "finding_key VARCHAR(64) NOT NULL, "
                "engagement_id VARCHAR(36) NOT NULL, "
                "state VARCHAR(32) NOT NULL DEFAULT 'candidate', "
                "title VARCHAR(500) NOT NULL DEFAULT '', "
                "category VARCHAR(128) NOT NULL DEFAULT '', "
                "evidence_refs JSON NOT NULL, "
                "occurrence_keys JSON NOT NULL, "
                "scan_ids JSON NOT NULL, "
                "coverage_equivalent BOOLEAN NOT NULL DEFAULT 0, "
                "payload JSON NOT NULL, "
                "created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL, "
                "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL, "
                "PRIMARY KEY (tenant_id, finding_key))"
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE logical_finding_scan_snapshots ("
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, "
                "scan_id VARCHAR(36) NOT NULL, "
                "finding_key VARCHAR(64) NOT NULL, "
                "payload JSON NOT NULL, "
                "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL, "
                "PRIMARY KEY (tenant_id, scan_id, finding_key))"
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE finding_occurrences ("
                "id VARCHAR(36) PRIMARY KEY NOT NULL, "
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, "
                "engagement_id VARCHAR(36) NOT NULL, "
                "finding_key VARCHAR(64) NOT NULL, "
                "occurrence_key VARCHAR(64) NOT NULL, "
                "scanner VARCHAR(64) NOT NULL, "
                "detector_id VARCHAR(256) NOT NULL, "
                "detector_version VARCHAR(64) NOT NULL, "
                "evidence_refs JSON, "
                "scan_id VARCHAR(36), "
                "first_seen_at DATETIME, "
                "last_seen_at DATETIME, "
                "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE finding_assessments ("
                "id VARCHAR(36) PRIMARY KEY NOT NULL, "
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, "
                "finding_key VARCHAR(64) NOT NULL, "
                "payload JSON NOT NULL, "
                "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE retest_jobs ("
                "id VARCHAR(36) PRIMARY KEY NOT NULL, "
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, "
                "engagement_id VARCHAR(36) NOT NULL, "
                "finding_key VARCHAR(64) NOT NULL, "
                "status VARCHAR(32) NOT NULL DEFAULT 'pending', "
                "result VARCHAR(32), "
                "coverage_equivalent BOOLEAN NOT NULL DEFAULT 0, "
                "payload JSON, "
                "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
                "completed_at DATETIME)"
            )
        )
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    tenant_id = str(uuid4())
    assert Tenant.__tablename__ == "tenants"
    async with factory() as session:
        await session.execute(
            text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
            {"id": tenant_id, "name": "findings-persist"},
        )
        await session.commit()
    repo = SqlAlchemyFindingsRepository(session_factory=factory)
    set_findings_repository(repo)
    try:
        yield repo, tenant_id
    finally:
        set_findings_repository(InMemoryFindingsRepository())
        await engine.dispose()


@pytest.mark.asyncio
async def test_sqlalchemy_finding_survives_new_repository_instance(
    sqlite_findings_env: tuple[SqlAlchemyFindingsRepository, str],
) -> None:
    _repo, tenant_id = sqlite_findings_env
    key = _finding_key(tenant_id)
    finding = LogicalFinding(
        finding_key=key,
        tenant_id=tenant_id,
        engagement_id=str(uuid4()),
        title="SQLi",
        category="sqli",
    )
    FindingLifecycleService().attach_assessment(
        finding,
        FindingAssessment(
            finding_key=key,
            tenant_id=tenant_id,
            classification="supported",
            observation="error based",
        ),
    )
    await _repo.upsert_logical_finding(finding, scan_id="scan-live")
    occ_key = compute_occurrence_key(
        finding_key=key,
        scanner="sqlmap",
        detector_id="sqli",
        detector_version="1.0.0",
        request_signature="POST /login",
        evidence_signal_hash=compute_evidence_signal_hash("union"),
    )
    now = datetime.now(tz=UTC)
    await _repo.save_occurrence(
        FindingOccurrence(
            occurrence_key=occ_key,
            finding_key=key,
            tenant_id=tenant_id,
            scan_id="scan-live",
            scanner="sqlmap",
            detector_id="sqli",
            detector_version="1.0.0",
            evidence_refs=("ev-sql",),
            first_seen_at=now,
            last_seen_at=now,
        )
    )

    restarted = SqlAlchemyFindingsRepository(session_factory=_repo._session_factory)
    loaded = await restarted.get_logical_finding(tenant_id=tenant_id, finding_key=key)
    assert loaded is not None
    assert loaded.title == "SQLi"
    assert loaded.state is FindingState.AI_REVIEWED
    snaps = await restarted.list_logical_findings_for_scan(
        tenant_id=tenant_id, scan_id="scan-live"
    )
    assert key in snaps
    occs = await restarted.list_occurrences_for_scan(tenant_id=tenant_id, scan_id="scan-live")
    assert len(occs) == 1
    assert occs[0].occurrence_key == occ_key


def test_report_merge_uses_persisted_when_blobs_empty() -> None:
    tenant_id = "018f4a2e-7c8b-7b4d-8e0e-6b6579317431"
    scan_id = "018f4a2e-7c8b-7b4d-8e0e-6b6579317432"
    key = _finding_key(tenant_id, "018f4a2e-7c8b-7b4d-8e0e-6b6579317433")
    occ_key = compute_occurrence_key(
        finding_key=key,
        scanner="nuclei",
        detector_id="xss-reflected",
        detector_version="1.0.0",
        request_signature="GET /search",
        evidence_signal_hash="a" * 64,
    )
    now = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    finding = LogicalFinding(
        finding_key=key,
        tenant_id=tenant_id,
        engagement_id="018f4a2e-7c8b-7b4d-8e0e-6b6579317433",
        title="Persisted XSS",
        category="xss",
        occurrence_keys=[occ_key],
    )
    occurrence = FindingOccurrence(
        occurrence_key=occ_key,
        finding_key=key,
        tenant_id=tenant_id,
        scan_id=scan_id,
        scanner="nuclei",
        detector_id="xss-reflected",
        detector_version="1.0.0",
        evidence_refs=("ev-1",),
        first_seen_at=now,
        last_seen_at=now,
    )
    ctx = build_coverage_occurrence_context(
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase_outputs=[],
        persisted_logical_findings={key: finding},
        persisted_occurrences={occ_key: occurrence},
    )
    assert ctx["totals"]["logical_findings"] == 1
    assert ctx["totals"]["occurrences"] == 1
    assert ctx["logical_findings"][key]["title"] == "Persisted XSS"
