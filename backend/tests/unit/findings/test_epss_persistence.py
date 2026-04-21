"""ARG-044 — unit tests for :mod:`src.findings.epss_persistence`.

Uses an in-memory SQLite engine so the tests run without requiring a
live Postgres. The repository's PostgreSQL ``ON CONFLICT`` path is
covered by integration tests (out of scope for the unit suite); the
generic upsert path exercised here mirrors the same semantics from the
caller's perspective.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.findings.epss_persistence import (
    EpssScore,
    EpssScoreRecord,
    EpssScoreRepository,
)


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    """Per-test in-memory SQLite session with the EPSS table provisioned."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        future=True,
    )
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: EpssScore.__table__.create(c, checkfirst=True))

    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        try:
            yield s
        finally:
            await s.rollback()
    await engine.dispose()


def _rec(
    *,
    cve_id: str = "CVE-2024-12345",
    epss_score: float = 0.42,
    epss_percentile: float = 0.85,
    model_date: date | None = None,
) -> EpssScoreRecord:
    return EpssScoreRecord(
        cve_id=cve_id,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        model_date=model_date or date(2026, 4, 15),
        updated_at=datetime(2026, 4, 16, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# upsert_batch
# ---------------------------------------------------------------------------


async def test_upsert_inserts_new_rows(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    written = await repo.upsert_batch(
        [
            _rec(cve_id="CVE-2024-0001"),
            _rec(cve_id="CVE-2024-0002", epss_score=0.1, epss_percentile=0.2),
        ]
    )
    await session.commit()
    assert written == 2
    assert await repo.count() == 2


async def test_upsert_updates_existing_row(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    await repo.upsert_batch([_rec(cve_id="CVE-2024-1111", epss_score=0.1)])
    await session.commit()
    written = await repo.upsert_batch(
        [_rec(cve_id="CVE-2024-1111", epss_score=0.95, epss_percentile=0.99)]
    )
    await session.commit()
    assert written == 1
    rec = await repo.get("CVE-2024-1111")
    assert rec is not None
    assert rec.epss_score == pytest.approx(0.95)
    assert rec.epss_percentile == pytest.approx(0.99)


async def test_upsert_drops_invalid_records(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    written = await repo.upsert_batch(
        [
            _rec(cve_id="bogus"),  # invalid CVE
            _rec(cve_id="CVE-2024-0001", epss_score=1.5),  # out-of-range score
            _rec(cve_id="CVE-2024-0002", epss_percentile=-0.1),  # invalid pct
            _rec(cve_id="CVE-2024-0003"),  # valid
        ]
    )
    await session.commit()
    assert written == 1
    assert await repo.count() == 1


async def test_upsert_empty_returns_zero(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    assert await repo.upsert_batch([]) == 0


async def test_upsert_chunk_size_must_be_positive(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    with pytest.raises(ValueError):
        await repo.upsert_batch([_rec()], chunk_size=0)


async def test_upsert_chunks_large_batch(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    rows = [_rec(cve_id=f"CVE-2024-{i:05d}") for i in range(1, 13)]
    written = await repo.upsert_batch(rows, chunk_size=5)
    await session.commit()
    assert written == 12
    assert await repo.count() == 12


# ---------------------------------------------------------------------------
# get / get_many
# ---------------------------------------------------------------------------


async def test_get_returns_none_for_invalid_cve(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    assert await repo.get("not-a-cve") is None
    assert await repo.get("") is None


async def test_get_returns_none_for_missing(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    assert await repo.get("CVE-1999-0001") is None


async def test_get_normalises_case(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    await repo.upsert_batch([_rec(cve_id="CVE-2024-9999")])
    await session.commit()
    rec = await repo.get("cve-2024-9999")
    assert rec is not None
    assert rec.cve_id == "CVE-2024-9999"


async def test_get_many_skips_invalid_and_missing(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    await repo.upsert_batch(
        [_rec(cve_id="CVE-2024-0001"), _rec(cve_id="CVE-2024-0002")]
    )
    await session.commit()
    out = await repo.get_many(["CVE-2024-0001", "bogus", "CVE-1999-9999"])
    assert set(out.keys()) == {"CVE-2024-0001"}


async def test_get_many_empty(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    assert await repo.get_many([]) == {}
    assert await repo.get_many(["bogus"]) == {}


# ---------------------------------------------------------------------------
# get_stale_after
# ---------------------------------------------------------------------------


async def test_get_stale_after_returns_old_rows(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    fresh = date.today() - timedelta(days=1)
    stale = date.today() - timedelta(days=60)
    await repo.upsert_batch(
        [
            _rec(cve_id="CVE-2024-1010", model_date=fresh),
            _rec(cve_id="CVE-2024-2020", model_date=stale),
        ]
    )
    await session.commit()
    stale_ids = await repo.get_stale_after(timedelta(days=30))
    assert "CVE-2024-2020" in stale_ids
    assert "CVE-2024-1010" not in stale_ids


async def test_get_stale_after_rejects_negative(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    with pytest.raises(ValueError):
        await repo.get_stale_after(timedelta(days=-1))


# ---------------------------------------------------------------------------
# count
# ---------------------------------------------------------------------------


async def test_count_starts_at_zero(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    assert await repo.count() == 0


async def test_count_reflects_upserts(session: AsyncSession) -> None:
    repo = EpssScoreRepository(session)
    await repo.upsert_batch(
        [_rec(cve_id=f"CVE-2024-{i:05d}") for i in range(1, 6)]
    )
    await session.commit()
    assert await repo.count() == 5
