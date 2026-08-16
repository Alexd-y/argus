"""Persistence for logical findings, occurrences, assessments, and retests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.db.session import async_session_factory, set_session_tenant
from src.findings.lifecycle import FindingAssessment, FindingOccurrence, LogicalFinding
from src.findings.models import (
    FindingAssessmentRow,
    FindingOccurrenceRow,
    LogicalFindingRow,
    LogicalFindingScanSnapshotRow,
    RetestJobRow,
)
from src.findings.retest import RetestJob

_SCAN_IDS_KEY = "scan_ids"


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None and str(item)]


def _finding_to_payload(finding: LogicalFinding, scan_ids: list[str]) -> dict[str, Any]:
    payload = finding.model_dump(mode="json")
    payload[_SCAN_IDS_KEY] = list(dict.fromkeys(scan_ids))
    return payload


def _finding_from_payload(payload: dict[str, Any], row: LogicalFindingRow) -> LogicalFinding:
    data = dict(payload)
    data.pop(_SCAN_IDS_KEY, None)
    data.setdefault("finding_key", row.finding_key)
    data.setdefault("tenant_id", row.tenant_id)
    data.setdefault("engagement_id", row.engagement_id)
    data.setdefault("state", row.state)
    data.setdefault("title", row.title)
    data.setdefault("category", row.category)
    data.setdefault("evidence_refs", row.evidence_refs or [])
    data.setdefault("occurrence_keys", row.occurrence_keys or [])
    data.setdefault("coverage_equivalent", row.coverage_equivalent)
    assessments = data.get("assessments") or []
    parsed: list[FindingAssessment] = []
    for item in assessments:
        if isinstance(item, FindingAssessment):
            parsed.append(item)
            continue
        if isinstance(item, dict):
            try:
                parsed.append(FindingAssessment.model_validate(item))
            except (TypeError, ValueError):
                continue
    data["assessments"] = parsed
    return LogicalFinding.model_validate(data)


def _occurrence_from_row(row: FindingOccurrenceRow) -> FindingOccurrence | None:
    if not row.scan_id:
        return None
    first_seen = row.first_seen_at or row.created_at or _utcnow()
    last_seen = row.last_seen_at or first_seen
    refs = row.evidence_refs or []
    try:
        return FindingOccurrence(
            occurrence_key=row.occurrence_key,
            finding_key=row.finding_key,
            tenant_id=row.tenant_id,
            scan_id=row.scan_id,
            scanner=row.scanner,
            detector_id=row.detector_id,
            detector_version=row.detector_version,
            evidence_refs=tuple(str(x) for x in refs),
            first_seen_at=first_seen,
            last_seen_at=last_seen,
        )
    except (TypeError, ValueError):
        return None


@runtime_checkable
class FindingsRepository(Protocol):
    """Persistence contract for logical findings. No delete API."""

    async def get_logical_finding(
        self, *, tenant_id: str, finding_key: str
    ) -> LogicalFinding | None: ...

    async def upsert_logical_finding(
        self, finding: LogicalFinding, *, scan_id: str | None = None
    ) -> LogicalFinding: ...

    async def list_logical_findings_for_scan(
        self, *, tenant_id: str, scan_id: str
    ) -> dict[str, LogicalFinding]: ...

    async def save_occurrence(self, occurrence: FindingOccurrence) -> None: ...

    async def list_occurrences_for_scan(
        self, *, tenant_id: str, scan_id: str
    ) -> list[FindingOccurrence]: ...

    async def save_assessment(self, assessment: FindingAssessment) -> None: ...

    async def save_retest_job(self, job: RetestJob) -> None: ...

    async def reset(self) -> None: ...


class InMemoryFindingsRepository:
    """In-memory test double. Production default is SQLAlchemy."""

    def __init__(self) -> None:
        self._findings: dict[tuple[str, str], LogicalFinding] = {}
        self._scan_ids: dict[tuple[str, str], list[str]] = {}
        self._snapshots: dict[tuple[str, str], dict[str, LogicalFinding]] = {}
        self._occurrences: dict[tuple[str, str], FindingOccurrence] = {}
        self._assessments: list[FindingAssessment] = []
        self._retests: list[RetestJob] = []

    async def get_logical_finding(
        self, *, tenant_id: str, finding_key: str
    ) -> LogicalFinding | None:
        finding = self._findings.get((tenant_id, finding_key))
        if finding is None:
            return None
        return finding.model_copy(deep=True)

    async def upsert_logical_finding(
        self, finding: LogicalFinding, *, scan_id: str | None = None
    ) -> LogicalFinding:
        key = (finding.tenant_id, finding.finding_key)
        stored = finding.model_copy(deep=True)
        self._findings[key] = stored
        scans = list(self._scan_ids.get(key, []))
        if scan_id and scan_id not in scans:
            scans.append(scan_id)
            self._scan_ids[key] = scans
        if scan_id:
            self._snapshots.setdefault((finding.tenant_id, scan_id), {})[finding.finding_key] = (
                stored.model_copy(deep=True)
            )
        return stored.model_copy(deep=True)

    async def list_logical_findings_for_scan(
        self, *, tenant_id: str, scan_id: str
    ) -> dict[str, LogicalFinding]:
        snaps = self._snapshots.get((tenant_id, scan_id), {})
        out = {key: finding.model_copy(deep=True) for key, finding in snaps.items()}
        for (tid, _occ_key), occurrence in self._occurrences.items():
            if tid != tenant_id or occurrence.scan_id != scan_id:
                continue
            if occurrence.finding_key in out:
                continue
            loaded = await self.get_logical_finding(
                tenant_id=tenant_id, finding_key=occurrence.finding_key
            )
            if loaded is not None:
                out[loaded.finding_key] = loaded
        return out

    async def save_occurrence(self, occurrence: FindingOccurrence) -> None:
        key = (occurrence.tenant_id, occurrence.occurrence_key)
        existing = self._occurrences.get(key)
        if existing is not None:
            first_seen = min(existing.first_seen_at, occurrence.first_seen_at)
            last_seen = max(existing.last_seen_at, occurrence.last_seen_at)
            refs = tuple(dict.fromkeys((*existing.evidence_refs, *occurrence.evidence_refs)))
            occurrence = occurrence.model_copy(
                update={
                    "first_seen_at": first_seen,
                    "last_seen_at": last_seen,
                    "evidence_refs": refs,
                }
            )
        self._occurrences[key] = occurrence
        finding_key = (occurrence.tenant_id, occurrence.finding_key)
        scans = list(self._scan_ids.get(finding_key, []))
        if occurrence.scan_id and occurrence.scan_id not in scans:
            scans.append(occurrence.scan_id)
            self._scan_ids[finding_key] = scans

    async def list_occurrences_for_scan(
        self, *, tenant_id: str, scan_id: str
    ) -> list[FindingOccurrence]:
        return [
            occ.model_copy(deep=True)
            for (tid, _), occ in self._occurrences.items()
            if tid == tenant_id and occ.scan_id == scan_id
        ]

    async def save_assessment(self, assessment: FindingAssessment) -> None:
        self._assessments.append(assessment)

    async def save_retest_job(self, job: RetestJob) -> None:
        self._retests.append(job.model_copy(deep=True))
        if job.scan_id:
            key = (job.tenant_id, job.finding_key)
            scans = list(self._scan_ids.get(key, []))
            if job.scan_id not in scans:
                scans.append(job.scan_id)
                self._scan_ids[key] = scans

    async def reset(self) -> None:
        self._findings.clear()
        self._scan_ids.clear()
        self._snapshots.clear()
        self._occurrences.clear()
        self._assessments.clear()
        self._retests.clear()


class SqlAlchemyFindingsRepository:
    """PostgreSQL/SQLite persistence via SQLAlchemy async session."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        self._session_factory = session_factory or async_session_factory

    async def get_logical_finding(
        self, *, tenant_id: str, finding_key: str
    ) -> LogicalFinding | None:
        async with self._session_factory() as session:
            await set_session_tenant(session, tenant_id)
            result = await session.execute(
                select(LogicalFindingRow).where(
                    LogicalFindingRow.tenant_id == tenant_id,
                    LogicalFindingRow.finding_key == finding_key,
                )
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            return _finding_from_payload(dict(row.payload or {}), row)

    async def upsert_logical_finding(
        self, finding: LogicalFinding, *, scan_id: str | None = None
    ) -> LogicalFinding:
        async with self._session_factory() as session:
            await set_session_tenant(session, finding.tenant_id)
            result = await session.execute(
                select(LogicalFindingRow).where(
                    LogicalFindingRow.tenant_id == finding.tenant_id,
                    LogicalFindingRow.finding_key == finding.finding_key,
                )
            )
            row = result.scalar_one_or_none()
            existing_scans = _as_str_list(row.scan_ids) if row is not None else []
            if scan_id and scan_id not in existing_scans:
                existing_scans.append(scan_id)
            payload = _finding_to_payload(finding, existing_scans)
            if row is None:
                row = LogicalFindingRow(
                    tenant_id=finding.tenant_id,
                    finding_key=finding.finding_key,
                    engagement_id=finding.engagement_id,
                    state=finding.state.value,
                    title=finding.title,
                    category=finding.category,
                    evidence_refs=list(finding.evidence_refs),
                    occurrence_keys=list(finding.occurrence_keys),
                    scan_ids=existing_scans,
                    coverage_equivalent=finding.coverage_equivalent,
                    payload=payload,
                )
                session.add(row)
            else:
                row.engagement_id = finding.engagement_id
                row.state = finding.state.value
                row.title = finding.title
                row.category = finding.category
                row.evidence_refs = list(finding.evidence_refs)
                row.occurrence_keys = list(finding.occurrence_keys)
                row.scan_ids = existing_scans
                row.coverage_equivalent = finding.coverage_equivalent
                row.payload = payload
                row.updated_at = _utcnow()
            await session.commit()
            await session.refresh(row)
            if scan_id:
                snap_result = await session.execute(
                    select(LogicalFindingScanSnapshotRow).where(
                        LogicalFindingScanSnapshotRow.tenant_id == finding.tenant_id,
                        LogicalFindingScanSnapshotRow.scan_id == scan_id,
                        LogicalFindingScanSnapshotRow.finding_key == finding.finding_key,
                    )
                )
                snap = snap_result.scalar_one_or_none()
                snap_payload = _finding_to_payload(finding, existing_scans)
                if snap is None:
                    session.add(
                        LogicalFindingScanSnapshotRow(
                            tenant_id=finding.tenant_id,
                            scan_id=scan_id,
                            finding_key=finding.finding_key,
                            payload=snap_payload,
                        )
                    )
                else:
                    snap.payload = snap_payload
                    snap.updated_at = _utcnow()
                await session.commit()
            return _finding_from_payload(dict(row.payload or {}), row)

    async def list_logical_findings_for_scan(
        self, *, tenant_id: str, scan_id: str
    ) -> dict[str, LogicalFinding]:
        async with self._session_factory() as session:
            await set_session_tenant(session, tenant_id)
            result = await session.execute(
                select(LogicalFindingScanSnapshotRow).where(
                    LogicalFindingScanSnapshotRow.tenant_id == tenant_id,
                    LogicalFindingScanSnapshotRow.scan_id == scan_id,
                )
            )
            out: dict[str, LogicalFinding] = {}
            for snap in result.scalars().all():
                try:
                    data = dict(snap.payload or {})
                    data.pop(_SCAN_IDS_KEY, None)
                    out[snap.finding_key] = LogicalFinding.model_validate(data)
                except (TypeError, ValueError):
                    continue
            occ_result = await session.execute(
                select(FindingOccurrenceRow).where(
                    FindingOccurrenceRow.tenant_id == tenant_id,
                    FindingOccurrenceRow.scan_id == scan_id,
                )
            )
            missing_keys = {
                occ.finding_key
                for occ in occ_result.scalars().all()
                if occ.finding_key not in out
            }
        for finding_key in missing_keys:
            loaded = await self.get_logical_finding(tenant_id=tenant_id, finding_key=finding_key)
            if loaded is not None:
                out[finding_key] = loaded
        return out

    async def save_occurrence(self, occurrence: FindingOccurrence) -> None:
        async with self._session_factory() as session:
            await set_session_tenant(session, occurrence.tenant_id)
            result = await session.execute(
                select(FindingOccurrenceRow).where(
                    FindingOccurrenceRow.tenant_id == occurrence.tenant_id,
                    FindingOccurrenceRow.occurrence_key == occurrence.occurrence_key,
                )
            )
            row = result.scalar_one_or_none()
            refs = list(occurrence.evidence_refs)
            if row is None:
                session.add(
                    FindingOccurrenceRow(
                        id=str(uuid4()),
                        tenant_id=occurrence.tenant_id,
                        engagement_id="",
                        finding_key=occurrence.finding_key,
                        occurrence_key=occurrence.occurrence_key,
                        scanner=occurrence.scanner,
                        detector_id=occurrence.detector_id,
                        detector_version=occurrence.detector_version,
                        evidence_refs=refs,
                        scan_id=occurrence.scan_id,
                        first_seen_at=occurrence.first_seen_at,
                        last_seen_at=occurrence.last_seen_at,
                    )
                )
            else:
                first_seen = min(row.first_seen_at or occurrence.first_seen_at, occurrence.first_seen_at)
                last_seen = max(row.last_seen_at or occurrence.last_seen_at, occurrence.last_seen_at)
                merged_refs = list(dict.fromkeys([*(row.evidence_refs or []), *refs]))
                row.scanner = occurrence.scanner
                row.detector_id = occurrence.detector_id
                row.detector_version = occurrence.detector_version
                row.evidence_refs = merged_refs
                row.scan_id = occurrence.scan_id or row.scan_id
                row.first_seen_at = first_seen
                row.last_seen_at = last_seen
            finding_row = (
                await session.execute(
                    select(LogicalFindingRow).where(
                        LogicalFindingRow.tenant_id == occurrence.tenant_id,
                        LogicalFindingRow.finding_key == occurrence.finding_key,
                    )
                )
            ).scalar_one_or_none()
            if finding_row is not None and occurrence.scan_id:
                scans = _as_str_list(finding_row.scan_ids)
                if occurrence.scan_id not in scans:
                    scans.append(occurrence.scan_id)
                    finding_row.scan_ids = scans
                    payload = dict(finding_row.payload or {})
                    payload[_SCAN_IDS_KEY] = scans
                    finding_row.payload = payload
            await session.commit()

    async def list_occurrences_for_scan(
        self, *, tenant_id: str, scan_id: str
    ) -> list[FindingOccurrence]:
        async with self._session_factory() as session:
            await set_session_tenant(session, tenant_id)
            result = await session.execute(
                select(FindingOccurrenceRow).where(
                    FindingOccurrenceRow.tenant_id == tenant_id,
                    FindingOccurrenceRow.scan_id == scan_id,
                )
            )
            return [occ for occ in (_occurrence_from_row(row) for row in result.scalars().all()) if occ is not None]

    async def save_assessment(self, assessment: FindingAssessment) -> None:
        tenant_id = assessment.tenant_id or "unknown"
        async with self._session_factory() as session:
            await set_session_tenant(session, tenant_id)
            session.add(
                FindingAssessmentRow(
                    id=assessment.id,
                    tenant_id=tenant_id,
                    finding_key=assessment.finding_key,
                    payload=assessment.model_dump(mode="json"),
                )
            )
            await session.commit()

    async def save_retest_job(self, job: RetestJob) -> None:
        async with self._session_factory() as session:
            await set_session_tenant(session, job.tenant_id)
            session.add(
                RetestJobRow(
                    id=job.id,
                    tenant_id=job.tenant_id,
                    engagement_id=job.engagement_id or "",
                    finding_key=job.finding_key,
                    status=job.status,
                    result=job.result.value,
                    coverage_equivalent=job.coverage_equivalent,
                    payload=job.model_dump(mode="json"),
                    created_at=job.created_at,
                    completed_at=job.completed_at,
                )
            )
            if job.scan_id:
                finding_row = (
                    await session.execute(
                        select(LogicalFindingRow).where(
                            LogicalFindingRow.tenant_id == job.tenant_id,
                            LogicalFindingRow.finding_key == job.finding_key,
                        )
                    )
                ).scalar_one_or_none()
                if finding_row is not None:
                    scans = _as_str_list(finding_row.scan_ids)
                    if job.scan_id not in scans:
                        scans.append(job.scan_id)
                        finding_row.scan_ids = scans
                        payload = dict(finding_row.payload or {})
                        payload[_SCAN_IDS_KEY] = scans
                        finding_row.payload = payload
            await session.commit()

    async def reset(self) -> None:
        """No-op for DB-backed repository (tests use in-memory)."""


_default_repository: FindingsRepository = SqlAlchemyFindingsRepository()


def get_findings_repository() -> FindingsRepository:
    return _default_repository


def set_findings_repository(repo: FindingsRepository) -> None:
    global _default_repository
    _default_repository = repo


__all__ = [
    "FindingsRepository",
    "InMemoryFindingsRepository",
    "SqlAlchemyFindingsRepository",
    "get_findings_repository",
    "set_findings_repository",
]
