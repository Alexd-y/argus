"""ARG-044 — EPSS score persistence layer.

Stores per-CVE EPSS probability + percentile in PostgreSQL. The repository
is the single I/O point used by:

* :class:`src.celery.tasks.intel_refresh.epss_batch_refresh_task`
  (writer — daily Celery beat refresh from FIRST.org).
* :class:`src.findings.normalizer.Normalizer` (reader — enrichment of
  FindingDTOs that carry one or more CVE IDs).

Schema (Alembic migration ``023_epss_kev_tables`` lands in ARG-045):

* ``cve_id`` ``VARCHAR(20)`` — primary key (CVE-YYYY-NNNNN).
* ``epss_score`` ``DOUBLE PRECISION`` — 0..1 probability of exploitation
  in the next 30 days.
* ``epss_percentile`` ``DOUBLE PRECISION`` — 0..100 model percentile.
* ``model_date`` ``DATE`` — FIRST.org model snapshot the row was sampled
  from (used for staleness queries).
* ``created_at`` / ``updated_at`` ``TIMESTAMPTZ`` — bookkeeping.

The repository is dialect-aware: PostgreSQL gets a true ``ON CONFLICT
... DO UPDATE`` upsert (one round-trip per chunk); SQLite (used by the
unit suite) emulates the same semantics with two statements per row,
which is acceptable for the test footprint and keeps the surface
backend-agnostic.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Final, cast

from sqlalchemy import (
    Date,
    DateTime,
    Float,
    Index,
    String,
    Table,
    func,
    select,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base

_logger = logging.getLogger(__name__)

_CVE_RE: Final[re.Pattern[str]] = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_DEFAULT_BATCH_SIZE: Final[int] = 500


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class EpssScore(Base):
    """ORM mapping for the ``epss_scores`` table.

    The model is intentionally write-light — it is populated exclusively by
    the daily Celery refresh job. Reads are point lookups by ``cve_id``.
    """

    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    epss_score: Mapped[float] = mapped_column(Float, nullable=False)
    epss_percentile: Mapped[float] = mapped_column(Float, nullable=False)
    model_date: Mapped[date] = mapped_column(Date, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (Index("ix_epss_scores_model_date", "model_date"),)


@dataclass(frozen=True)
class EpssScoreRecord:
    """Plain-data DTO returned by the repository.

    Decoupling readers from the SQLAlchemy ORM keeps consumers (normalizer,
    prioritizer) free of stale-attribute issues when sessions close.
    """

    cve_id: str
    epss_score: float
    epss_percentile: float
    model_date: date
    updated_at: datetime


class EpssScoreRepository:
    """Async repository for the ``epss_scores`` table.

    The repository is stateless apart from the injected
    :class:`AsyncSession`; the session lifecycle (begin / commit / close)
    is the caller's responsibility so the repository composes cleanly with
    FastAPI request scopes and Celery task scopes alike.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_batch(
        self,
        items: Iterable[EpssScoreRecord],
        *,
        chunk_size: int = _DEFAULT_BATCH_SIZE,
    ) -> int:
        """Insert / update ``items`` in chunks.

        Returns the number of valid rows written (invalid rows are dropped
        with a warning log entry). ``chunk_size`` caps the round-trip
        payload — important for very large EPSS dumps (~250k rows).
        """
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        rows = [r for r in items if _is_valid_record(r)]
        if not rows:
            return 0
        dialect = self._session.bind.dialect.name if self._session.bind else "default"
        written = 0
        for chunk in _chunked(rows, chunk_size):
            written += await self._upsert_chunk(chunk, dialect=dialect)
        return written

    async def get(self, cve_id: str) -> EpssScoreRecord | None:
        """Return the record for ``cve_id`` (case-insensitive) or ``None``."""
        if not _CVE_RE.fullmatch(cve_id.upper()):
            return None
        row = await self._session.get(EpssScore, cve_id.upper())
        if row is None:
            return None
        return _to_record(row)

    async def get_many(
        self, cve_ids: Iterable[str]
    ) -> dict[str, EpssScoreRecord]:
        """Bulk fetch records for ``cve_ids``; missing entries are skipped."""
        normalised = {cid.upper() for cid in cve_ids if _CVE_RE.fullmatch(cid.upper())}
        if not normalised:
            return {}
        stmt = select(EpssScore).where(EpssScore.cve_id.in_(normalised))
        result = await self._session.execute(stmt)
        return {row.cve_id: _to_record(row) for row in result.scalars().all()}

    async def get_stale_after(self, age: timedelta) -> list[str]:
        """Return CVE IDs whose ``model_date`` is older than ``age``.

        Used by the daily Celery refresh job to prioritise re-fetching
        stale rows when the upstream rate limit forces a partial refresh.
        """
        if age.total_seconds() < 0:
            raise ValueError("age must be non-negative")
        cutoff = _utcnow().date() - age
        stmt = select(EpssScore.cve_id).where(EpssScore.model_date < cutoff)
        result = await self._session.execute(stmt)
        return [r for (r,) in result.all()]

    async def count(self) -> int:
        """Return total rows in the table (used by health endpoints)."""
        stmt = select(func.count()).select_from(EpssScore)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def _upsert_chunk(
        self, chunk: Sequence[EpssScoreRecord], *, dialect: str
    ) -> int:
        if dialect == "postgresql":
            return await self._upsert_chunk_postgres(chunk)
        return await self._upsert_chunk_generic(chunk)

    async def _upsert_chunk_postgres(self, chunk: Sequence[EpssScoreRecord]) -> int:
        payload = [
            {
                "cve_id": r.cve_id.upper(),
                "epss_score": float(r.epss_score),
                "epss_percentile": float(r.epss_percentile),
                "model_date": r.model_date,
            }
            for r in chunk
        ]
        table = cast(Table, EpssScore.__table__)
        stmt = pg_insert(table).values(payload)
        stmt = stmt.on_conflict_do_update(
            index_elements=[EpssScore.cve_id],
            set_={
                "epss_score": stmt.excluded.epss_score,
                "epss_percentile": stmt.excluded.epss_percentile,
                "model_date": stmt.excluded.model_date,
                "updated_at": func.now(),
            },
        )
        await self._session.execute(stmt)
        return len(payload)

    async def _upsert_chunk_generic(self, chunk: Sequence[EpssScoreRecord]) -> int:
        written = 0
        for r in chunk:
            existing = await self._session.get(EpssScore, r.cve_id.upper())
            if existing is None:
                self._session.add(
                    EpssScore(
                        cve_id=r.cve_id.upper(),
                        epss_score=float(r.epss_score),
                        epss_percentile=float(r.epss_percentile),
                        model_date=r.model_date,
                    )
                )
            else:
                existing.epss_score = float(r.epss_score)
                existing.epss_percentile = float(r.epss_percentile)
                existing.model_date = r.model_date
                existing.updated_at = _utcnow()
            written += 1
        await self._session.flush()
        return written


def _to_record(row: EpssScore) -> EpssScoreRecord:
    return EpssScoreRecord(
        cve_id=row.cve_id,
        epss_score=float(row.epss_score),
        epss_percentile=float(row.epss_percentile),
        model_date=row.model_date,
        updated_at=row.updated_at,
    )


def _is_valid_record(r: EpssScoreRecord) -> bool:
    if not _CVE_RE.fullmatch(r.cve_id.upper()):
        _logger.warning(
            "epss_persistence.invalid_cve",
            extra={"event": "epss_persistence_invalid_cve"},
        )
        return False
    if not 0.0 <= r.epss_score <= 1.0:
        _logger.warning(
            "epss_persistence.invalid_score",
            extra={"event": "epss_persistence_invalid_score"},
        )
        return False
    if not 0.0 <= r.epss_percentile <= 1.0:
        # FIRST.org returns percentile as 0..1; we keep that convention.
        # Values outside the band are dropped to keep downstream maths sane.
        _logger.warning(
            "epss_persistence.invalid_percentile",
            extra={"event": "epss_persistence_invalid_percentile"},
        )
        return False
    return True


def _chunked(items: Sequence[EpssScoreRecord], size: int) -> Iterable[list[EpssScoreRecord]]:
    if size <= 0:
        raise ValueError("size must be positive")
    for i in range(0, len(items), size):
        yield list(items[i : i + size])


__all__ = [
    "EpssScore",
    "EpssScoreRecord",
    "EpssScoreRepository",
]
