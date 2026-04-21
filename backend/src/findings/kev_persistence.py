"""ARG-044 — CISA KEV catalog persistence layer.

Stores the full CISA Known-Exploited-Vulnerabilities catalog in PostgreSQL
so the normalizer / prioritizer can answer ``is_listed(cve_id)`` and
``get(cve_id) → KevEntry`` synchronously without any HTTP round-trip.

Schema (Alembic ``023_epss_kev_tables`` lands in ARG-045):

* ``cve_id`` ``VARCHAR(20)`` — primary key.
* ``vendor_project`` / ``product`` / ``vulnerability_name`` ``VARCHAR(255)``.
* ``date_added`` ``DATE`` — indexed for "added in last 30 days" queries.
* ``short_description`` / ``required_action`` / ``notes`` ``TEXT``.
* ``due_date`` ``DATE`` (nullable per CISA spec).
* ``known_ransomware_use`` ``BOOLEAN`` — default ``FALSE``.
* ``created_at`` / ``updated_at`` ``TIMESTAMPTZ``.

The catalog is replaced wholesale on every refresh (~1k rows total).
We use ``upsert_batch`` so concurrent reads keep working during the
refresh window (no ``DELETE`` then ``INSERT`` race window).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Final

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Index,
    String,
    Text,
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


class KevEntry(Base):
    """ORM mapping for the ``kev_catalog`` table.

    The mandatory CISA columns are non-null; vendor-specific fields
    (``due_date``, ``notes``) are nullable to mirror upstream gaps.
    """

    __tablename__ = "kev_catalog"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    product: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    vulnerability_name: Mapped[str] = mapped_column(
        String(500), nullable=False, default=""
    )
    date_added: Mapped[date] = mapped_column(Date, nullable=False)
    short_description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    required_action: Mapped[str] = mapped_column(Text, nullable=False, default="")
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True, default=None)
    known_ransomware_use: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (Index("ix_kev_catalog_date_added", "date_added"),)


@dataclass(frozen=True)
class KevRecord:
    """Plain-data DTO for the catalog (decoupled from ORM identity map)."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    short_description: str
    required_action: str
    due_date: date | None = None
    known_ransomware_use: bool = False
    notes: str | None = None


class KevCatalogRepository:
    """Async repository for the ``kev_catalog`` table.

    All methods accept normalised CVE IDs (``CVE-YYYY-NNNNN``); inputs are
    upper-cased before query / write. Invalid CVE strings are silently
    dropped — KEV enrichment is best-effort, never a hard dependency.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_batch(
        self,
        items: Iterable[KevRecord],
        *,
        chunk_size: int = _DEFAULT_BATCH_SIZE,
    ) -> int:
        """Insert / update ``items`` in chunks; returns rows written."""
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

    async def get(self, cve_id: str) -> KevRecord | None:
        """Return the record for ``cve_id`` or ``None``."""
        if not _CVE_RE.fullmatch(cve_id.upper()):
            return None
        row = await self._session.get(KevEntry, cve_id.upper())
        if row is None:
            return None
        return _to_record(row)

    async def is_listed(self, cve_id: str) -> bool:
        """Convenience predicate (avoids materialising the full row)."""
        if not _CVE_RE.fullmatch(cve_id.upper()):
            return False
        stmt = (
            select(func.count())
            .select_from(KevEntry)
            .where(KevEntry.cve_id == cve_id.upper())
        )
        result = await self._session.execute(stmt)
        return int(result.scalar_one()) > 0

    async def get_listed_set(self, cve_ids: Iterable[str]) -> set[str]:
        """Return the subset of ``cve_ids`` present in the KEV catalog."""
        normalised = {cid.upper() for cid in cve_ids if _CVE_RE.fullmatch(cid.upper())}
        if not normalised:
            return set()
        stmt = select(KevEntry.cve_id).where(KevEntry.cve_id.in_(normalised))
        result = await self._session.execute(stmt)
        return {row for (row,) in result.all()}

    async def count(self) -> int:
        """Return total catalog size (used by health endpoints)."""
        stmt = select(func.count()).select_from(KevEntry)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def _upsert_chunk(
        self, chunk: Sequence[KevRecord], *, dialect: str
    ) -> int:
        if dialect == "postgresql":
            return await self._upsert_chunk_postgres(chunk)
        return await self._upsert_chunk_generic(chunk)

    async def _upsert_chunk_postgres(self, chunk: Sequence[KevRecord]) -> int:
        payload = [_record_to_dict(r) for r in chunk]
        stmt = pg_insert(KevEntry.__table__).values(payload)
        stmt = stmt.on_conflict_do_update(
            index_elements=[KevEntry.cve_id],
            set_={
                "vendor_project": stmt.excluded.vendor_project,
                "product": stmt.excluded.product,
                "vulnerability_name": stmt.excluded.vulnerability_name,
                "date_added": stmt.excluded.date_added,
                "short_description": stmt.excluded.short_description,
                "required_action": stmt.excluded.required_action,
                "due_date": stmt.excluded.due_date,
                "known_ransomware_use": stmt.excluded.known_ransomware_use,
                "notes": stmt.excluded.notes,
                "updated_at": func.now(),
            },
        )
        await self._session.execute(stmt)
        return len(payload)

    async def _upsert_chunk_generic(self, chunk: Sequence[KevRecord]) -> int:
        written = 0
        for r in chunk:
            existing = await self._session.get(KevEntry, r.cve_id.upper())
            data = _record_to_dict(r)
            if existing is None:
                self._session.add(KevEntry(**data))
            else:
                existing.vendor_project = r.vendor_project or ""
                existing.product = r.product or ""
                existing.vulnerability_name = r.vulnerability_name or ""
                existing.date_added = r.date_added
                existing.short_description = r.short_description or ""
                existing.required_action = r.required_action or ""
                existing.due_date = r.due_date
                existing.known_ransomware_use = bool(r.known_ransomware_use)
                existing.notes = r.notes
                existing.updated_at = _utcnow()
            written += 1
        await self._session.flush()
        return written


def _to_record(row: KevEntry) -> KevRecord:
    return KevRecord(
        cve_id=row.cve_id,
        vendor_project=row.vendor_project or "",
        product=row.product or "",
        vulnerability_name=row.vulnerability_name or "",
        date_added=row.date_added,
        short_description=row.short_description or "",
        required_action=row.required_action or "",
        due_date=row.due_date,
        known_ransomware_use=bool(row.known_ransomware_use),
        notes=row.notes,
    )


def _record_to_dict(r: KevRecord) -> dict[str, object]:
    return {
        "cve_id": r.cve_id.upper(),
        "vendor_project": r.vendor_project or "",
        "product": r.product or "",
        "vulnerability_name": r.vulnerability_name or "",
        "date_added": r.date_added,
        "short_description": r.short_description or "",
        "required_action": r.required_action or "",
        "due_date": r.due_date,
        "known_ransomware_use": bool(r.known_ransomware_use),
        "notes": r.notes,
    }


def _is_valid_record(r: KevRecord) -> bool:
    if not _CVE_RE.fullmatch(r.cve_id.upper()):
        _logger.warning(
            "kev_persistence.invalid_cve",
            extra={"event": "kev_persistence_invalid_cve"},
        )
        return False
    if not isinstance(r.date_added, date):
        _logger.warning(
            "kev_persistence.invalid_date_added",
            extra={"event": "kev_persistence_invalid_date_added"},
        )
        return False
    return True


def _chunked(items: Sequence[KevRecord], size: int) -> Iterable[list[KevRecord]]:
    if size <= 0:
        raise ValueError("size must be positive")
    for i in range(0, len(items), size):
        yield list(items[i : i + size])


__all__ = [
    "KevCatalogRepository",
    "KevEntry",
    "KevRecord",
]
