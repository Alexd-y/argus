"""ARG-044 — unit tests for :mod:`src.findings.kev_persistence`.

In-memory SQLite engine; the PostgreSQL ``ON CONFLICT`` upsert path is
covered separately by integration tests. Generic upsert path is exercised
here.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import date

import pytest
import pytest_asyncio
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.findings.kev_persistence import (
    KevCatalogRepository,
    KevEntry,
    KevRecord,
)


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    """Per-test in-memory SQLite session with the KEV catalog table provisioned."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        future=True,
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_foreign_keys(conn, _conn_record) -> None:  # type: ignore[no-untyped-def]
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    async with engine.begin() as conn:
        await conn.run_sync(lambda c: KevEntry.__table__.create(c, checkfirst=True))

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as s:
        try:
            yield s
        finally:
            await s.rollback()
    await engine.dispose()


def _rec(
    *,
    cve_id: str = "CVE-2024-12345",
    vendor_project: str = "Acme",
    product: str = "Widget",
    vulnerability_name: str = "Remote Code Execution",
    date_added: date | None = None,
    short_description: str = "A nasty bug",
    required_action: str = "Patch immediately",
    due_date: date | None = None,
    known_ransomware_use: bool = False,
    notes: str | None = None,
) -> KevRecord:
    return KevRecord(
        cve_id=cve_id,
        vendor_project=vendor_project,
        product=product,
        vulnerability_name=vulnerability_name,
        date_added=date_added or date(2026, 4, 15),
        short_description=short_description,
        required_action=required_action,
        due_date=due_date,
        known_ransomware_use=known_ransomware_use,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# upsert_batch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_inserts_new_rows(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    written = await repo.upsert_batch(
        [_rec(cve_id="CVE-2024-0001"), _rec(cve_id="CVE-2024-0002")]
    )
    await session.commit()
    assert written == 2
    assert await repo.count() == 2


@pytest.mark.asyncio
async def test_upsert_updates_existing_row(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    await repo.upsert_batch(
        [_rec(cve_id="CVE-2024-1111", vendor_project="Old", product="OldP")]
    )
    await session.commit()
    written = await repo.upsert_batch(
        [
            _rec(
                cve_id="CVE-2024-1111",
                vendor_project="NewVendor",
                product="NewProduct",
                known_ransomware_use=True,
            )
        ]
    )
    await session.commit()
    assert written == 1
    rec = await repo.get("CVE-2024-1111")
    assert rec is not None
    assert rec.vendor_project == "NewVendor"
    assert rec.product == "NewProduct"
    assert rec.known_ransomware_use is True


@pytest.mark.asyncio
async def test_upsert_drops_invalid_cve(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    written = await repo.upsert_batch(
        [
            _rec(cve_id="not-a-cve"),  # invalid
            _rec(cve_id="CVE-2024-0001"),  # valid
        ]
    )
    await session.commit()
    assert written == 1
    assert await repo.count() == 1


@pytest.mark.asyncio
async def test_upsert_empty_returns_zero(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    assert await repo.upsert_batch([]) == 0


@pytest.mark.asyncio
async def test_upsert_chunk_size_must_be_positive(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    with pytest.raises(ValueError):
        await repo.upsert_batch([_rec()], chunk_size=0)


@pytest.mark.asyncio
async def test_upsert_chunks_large_batch(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    rows = [_rec(cve_id=f"CVE-2024-{i:05d}") for i in range(1, 13)]
    written = await repo.upsert_batch(rows, chunk_size=5)
    await session.commit()
    assert written == 12
    assert await repo.count() == 12


# ---------------------------------------------------------------------------
# is_listed / get / get_listed_set
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_listed_returns_true_for_present_cve(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    await repo.upsert_batch([_rec(cve_id="CVE-2024-AAAA0", date_added=date(2026, 4, 1))])
    await session.commit()
    assert await repo.is_listed("CVE-2024-AAAA0") is False  # invalid format
    await repo.upsert_batch([_rec(cve_id="CVE-2024-1234")])
    await session.commit()
    assert await repo.is_listed("CVE-2024-1234") is True


@pytest.mark.asyncio
async def test_is_listed_returns_false_for_missing_or_invalid(
    session: AsyncSession,
) -> None:
    repo = KevCatalogRepository(session)
    assert await repo.is_listed("CVE-9999-9999") is False
    assert await repo.is_listed("not-a-cve") is False
    assert await repo.is_listed("") is False


@pytest.mark.asyncio
async def test_is_listed_normalises_case(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    await repo.upsert_batch([_rec(cve_id="CVE-2024-1234")])
    await session.commit()
    assert await repo.is_listed("cve-2024-1234") is True


@pytest.mark.asyncio
async def test_get_listed_set_returns_intersection(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    await repo.upsert_batch(
        [
            _rec(cve_id="CVE-2024-0001"),
            _rec(cve_id="CVE-2024-0002"),
            _rec(cve_id="CVE-2024-0003"),
        ]
    )
    await session.commit()
    out = await repo.get_listed_set(
        ["CVE-2024-0001", "CVE-2024-9999", "CVE-2024-0003", "bogus"]
    )
    assert out == {"CVE-2024-0001", "CVE-2024-0003"}


@pytest.mark.asyncio
async def test_get_listed_set_empty_returns_empty(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    assert await repo.get_listed_set([]) == set()
    assert await repo.get_listed_set(["bogus"]) == set()


@pytest.mark.asyncio
async def test_get_returns_record_with_full_payload(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    await repo.upsert_batch(
        [
            _rec(
                cve_id="CVE-2024-1234",
                vendor_project="Acme",
                product="Widget",
                vulnerability_name="RCE in Widget",
                date_added=date(2026, 4, 1),
                short_description="A nasty RCE",
                required_action="Patch",
                due_date=date(2026, 4, 15),
                known_ransomware_use=True,
                notes="Active in the wild",
            )
        ]
    )
    await session.commit()
    rec = await repo.get("CVE-2024-1234")
    assert rec is not None
    assert rec.vendor_project == "Acme"
    assert rec.product == "Widget"
    assert rec.vulnerability_name == "RCE in Widget"
    assert rec.short_description == "A nasty RCE"
    assert rec.required_action == "Patch"
    assert rec.due_date == date(2026, 4, 15)
    assert rec.known_ransomware_use is True
    assert rec.notes == "Active in the wild"


@pytest.mark.asyncio
async def test_get_returns_none_for_missing(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    assert await repo.get("CVE-1999-0001") is None
    assert await repo.get("not-a-cve") is None


# ---------------------------------------------------------------------------
# count
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_count_starts_at_zero(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    assert await repo.count() == 0


@pytest.mark.asyncio
async def test_count_reflects_upserts(session: AsyncSession) -> None:
    repo = KevCatalogRepository(session)
    await repo.upsert_batch(
        [_rec(cve_id=f"CVE-2024-{i:05d}") for i in range(1, 6)]
    )
    await session.commit()
    assert await repo.count() == 5
