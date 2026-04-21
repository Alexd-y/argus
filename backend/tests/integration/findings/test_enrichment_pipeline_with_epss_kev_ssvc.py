"""ARG-044 — integration: end-to-end EPSS + KEV + SSVC enrichment.

Wires the full Postgres-backed flow (EPSS / KEV repositories, Findings
enricher, deterministic prioritiser) on an in-memory SQLite engine so the
test stays hermetic. Exercises:

* Enrichment populates the five new :class:`FindingDTO` fields.
* Air-gap mode short-circuits both lookups.
* Multi-CVE findings receive the worst signal across all referenced CVEs.
* Findings without CVE associations still get a SSVC decision (defaults).
* Repository failures degrade gracefully (the original DTO is returned).
* :class:`FindingPrioritizer` ranking respects the enriched values.
* Backwards-compat: pre-Cycle-4 producers (no enrichment) keep working.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import date
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.findings.enrichment import FindingEnricher
from src.findings.epss_persistence import (
    EpssScore,
    EpssScoreRecord,
    EpssScoreRepository,
)
from src.findings.kev_persistence import (
    KevCatalogRepository,
    KevEntry,
    KevRecord,
)
from src.findings.prioritizer import FindingPrioritizer
from src.findings.ssvc import MissionWellbeing
from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    SSVCDecision,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    """In-memory SQLite session with both intel tables provisioned."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: EpssScore.__table__.create(c, checkfirst=True))
        await conn.run_sync(lambda c: KevEntry.__table__.create(c, checkfirst=True))
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as s:
        try:
            yield s
        finally:
            await s.rollback()
    await engine.dispose()


def _finding(
    *,
    finding_id=None,
    category: FindingCategory = FindingCategory.RCE,
    cvss_v3_score: float = 9.0,
    epss_score: float | None = None,
    kev_listed: bool = False,
    ssvc_decision: SSVCDecision = SSVCDecision.TRACK,
) -> FindingDTO:
    return FindingDTO(
        id=finding_id or uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        asset_id=uuid4(),
        tool_run_id=uuid4(),
        category=category,
        cwe=[200],
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_v3_score=cvss_v3_score,
        epss_score=epss_score,
        kev_listed=kev_listed,
        ssvc_decision=ssvc_decision,
        confidence=ConfidenceLevel.SUSPECTED,
        status=FindingStatus.NEW,
        mitre_attack=[],
    )


async def _seed_epss(repo: EpssScoreRepository, *records: EpssScoreRecord) -> None:
    await repo.upsert_batch(records)
    await repo._session.commit()  # type: ignore[attr-defined]


async def _seed_kev(repo: KevCatalogRepository, *records: KevRecord) -> None:
    await repo.upsert_batch(records)
    await repo._session.commit()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Happy path: full enrichment populates the 5 new fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrich_populates_all_five_intel_fields(
    session: AsyncSession,
) -> None:
    epss_repo = EpssScoreRepository(session)
    kev_repo = KevCatalogRepository(session)
    await _seed_epss(
        epss_repo,
        EpssScoreRecord(
            cve_id="CVE-2024-1234",
            epss_score=0.91,
            epss_percentile=0.99,
            model_date=date(2026, 4, 15),
            updated_at=date(2026, 4, 16),  # type: ignore[arg-type]
        ),
    )
    await _seed_kev(
        kev_repo,
        KevRecord(
            cve_id="CVE-2024-1234",
            vendor_project="Acme",
            product="Widget",
            vulnerability_name="RCE",
            date_added=date(2026, 4, 1),
            short_description="Nasty",
            required_action="Patch",
        ),
    )

    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=kev_repo)
    finding = _finding()
    enriched = await enricher.enrich(
        [finding],
        cve_ids_by_finding={str(finding.id): ["CVE-2024-1234"]},
    )
    assert len(enriched) == 1
    out = enriched[0]
    assert out.epss_score == pytest.approx(0.91)
    assert out.epss_percentile == pytest.approx(0.99)
    assert out.kev_listed is True
    assert out.kev_added_date == date(2026, 4, 1)
    assert out.ssvc_decision is SSVCDecision.ACT


# ---------------------------------------------------------------------------
# Air-gap mode short-circuits lookups but still derives SSVC
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_airgap_mode_returns_dto_unchanged_intel_but_with_ssvc(
    session: AsyncSession,
) -> None:
    epss_repo = EpssScoreRepository(session)
    kev_repo = KevCatalogRepository(session)
    await _seed_epss(
        epss_repo,
        EpssScoreRecord(
            cve_id="CVE-2024-9999",
            epss_score=0.5,
            epss_percentile=0.5,
            model_date=date(2026, 4, 1),
            updated_at=date(2026, 4, 2),  # type: ignore[arg-type]
        ),
    )

    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=kev_repo, airgap=True)
    finding = _finding()
    enriched = await enricher.enrich(
        [finding],
        cve_ids_by_finding={str(finding.id): ["CVE-2024-9999"]},
    )
    out = enriched[0]
    assert out.epss_score is None
    assert out.kev_listed is False
    # SSVC is still derived (using defaults).
    assert isinstance(out.ssvc_decision, SSVCDecision)


# ---------------------------------------------------------------------------
# Multi-CVE findings adopt the worst signal
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_cve_finding_uses_worst_signal(session: AsyncSession) -> None:
    epss_repo = EpssScoreRepository(session)
    kev_repo = KevCatalogRepository(session)
    await _seed_epss(
        epss_repo,
        EpssScoreRecord(
            cve_id="CVE-2024-22221",
            epss_score=0.10,
            epss_percentile=0.10,
            model_date=date(2026, 4, 15),
            updated_at=date(2026, 4, 16),  # type: ignore[arg-type]
        ),
        EpssScoreRecord(
            cve_id="CVE-2024-33332",
            epss_score=0.95,
            epss_percentile=0.99,
            model_date=date(2026, 4, 15),
            updated_at=date(2026, 4, 16),  # type: ignore[arg-type]
        ),
    )
    await _seed_kev(
        kev_repo,
        KevRecord(
            cve_id="CVE-2024-33332",
            vendor_project="Acme",
            product="Widget",
            vulnerability_name="RCE",
            date_added=date(2026, 3, 1),
            short_description="Nasty",
            required_action="Patch",
        ),
    )

    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=kev_repo)
    finding = _finding()
    enriched = await enricher.enrich(
        [finding],
        cve_ids_by_finding={
            str(finding.id): ["CVE-2024-22221", "CVE-2024-33332"]
        },
    )
    out = enriched[0]
    assert out.epss_score == pytest.approx(0.95)
    assert out.epss_percentile == pytest.approx(0.99)
    assert out.kev_listed is True
    assert out.kev_added_date == date(2026, 3, 1)


# ---------------------------------------------------------------------------
# Backward-compat: findings without CVE associations
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finding_without_cve_keeps_defaults_but_gets_ssvc(
    session: AsyncSession,
) -> None:
    epss_repo = EpssScoreRepository(session)
    kev_repo = KevCatalogRepository(session)
    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=kev_repo)
    finding = _finding(category=FindingCategory.MISCONFIG, cvss_v3_score=4.0)
    enriched = await enricher.enrich([finding])
    out = enriched[0]
    assert out.epss_score is None
    assert out.kev_listed is False
    assert isinstance(out.ssvc_decision, SSVCDecision)


# ---------------------------------------------------------------------------
# Repository failure → graceful degradation (returns the original DTO)
# ---------------------------------------------------------------------------


class _BoomEpssRepo:
    async def get_many(self, _cve_ids):  # type: ignore[no-untyped-def]
        raise RuntimeError("db down")


class _BoomKevRepo:
    async def get_listed_set(self, _cve_ids):  # type: ignore[no-untyped-def]
        raise RuntimeError("db down")

    async def get(self, _cve_id):  # type: ignore[no-untyped-def]
        raise RuntimeError("db down")


@pytest.mark.asyncio
async def test_repo_failure_does_not_raise_and_keeps_dto_intact() -> None:
    enricher = FindingEnricher(
        epss_repo=_BoomEpssRepo(),  # type: ignore[arg-type]
        kev_repo=_BoomKevRepo(),  # type: ignore[arg-type]
    )
    finding = _finding()
    enriched = await enricher.enrich(
        [finding],
        cve_ids_by_finding={str(finding.id): ["CVE-2024-1234"]},
    )
    out = enriched[0]
    assert out.epss_score is None
    assert out.kev_listed is False
    # SSVC is still derived (no exception escapes).
    assert isinstance(out.ssvc_decision, SSVCDecision)


# ---------------------------------------------------------------------------
# Empty / no-op input
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrich_empty_returns_empty(session: AsyncSession) -> None:
    enricher = FindingEnricher(
        epss_repo=EpssScoreRepository(session),
        kev_repo=KevCatalogRepository(session),
    )
    assert await enricher.enrich([]) == []


@pytest.mark.asyncio
async def test_invalid_cve_in_map_is_dropped(session: AsyncSession) -> None:
    """The enricher must filter out malformed CVE IDs without raising."""
    epss_repo = EpssScoreRepository(session)
    kev_repo = KevCatalogRepository(session)
    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=kev_repo)
    finding = _finding()
    enriched = await enricher.enrich(
        [finding],
        cve_ids_by_finding={str(finding.id): ["bogus", "not-a-cve", ""]},
    )
    assert enriched[0].epss_score is None


# ---------------------------------------------------------------------------
# Prioritizer interaction — enriched values drive the ranking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prioritizer_uses_enriched_kev_status(session: AsyncSession) -> None:
    epss_repo = EpssScoreRepository(session)
    kev_repo = KevCatalogRepository(session)
    await _seed_kev(
        kev_repo,
        KevRecord(
            cve_id="CVE-2024-44441",
            vendor_project="Acme",
            product="Widget",
            vulnerability_name="RCE",
            date_added=date(2026, 4, 1),
            short_description="Nasty",
            required_action="Patch",
        ),
    )

    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=kev_repo)
    kev_finding = _finding(cvss_v3_score=4.0)
    other = _finding(cvss_v3_score=9.5)

    enriched = await enricher.enrich(
        [kev_finding, other],
        cve_ids_by_finding={
            str(kev_finding.id): ["CVE-2024-44441"],
            str(other.id): [],
        },
    )
    ranked = FindingPrioritizer.rank_findings(enriched)
    # KEV-listed `kev_finding` outranks higher-CVSS `other`.
    assert ranked[0].id == kev_finding.id


@pytest.mark.asyncio
async def test_prioritizer_uses_enriched_epss_for_tie_break(
    session: AsyncSession,
) -> None:
    epss_repo = EpssScoreRepository(session)
    kev_repo = KevCatalogRepository(session)
    await _seed_epss(
        epss_repo,
        EpssScoreRecord(
            cve_id="CVE-2024-55551",
            epss_score=0.95,
            epss_percentile=0.99,
            model_date=date(2026, 4, 15),
            updated_at=date(2026, 4, 16),  # type: ignore[arg-type]
        ),
        EpssScoreRecord(
            cve_id="CVE-2024-66662",
            epss_score=0.05,
            epss_percentile=0.10,
            model_date=date(2026, 4, 15),
            updated_at=date(2026, 4, 16),  # type: ignore[arg-type]
        ),
    )

    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=kev_repo)
    high = _finding(cvss_v3_score=7.5)
    low = _finding(cvss_v3_score=7.5)
    enriched = await enricher.enrich(
        [low, high],
        cve_ids_by_finding={
            str(high.id): ["CVE-2024-55551"],
            str(low.id): ["CVE-2024-66662"],
        },
    )
    ranked = FindingPrioritizer.rank_findings(enriched)
    assert ranked[0].id == high.id


# ---------------------------------------------------------------------------
# Mission-wellbeing override flows through to SSVC
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mission_wellbeing_high_lifts_ssvc_outcome(
    session: AsyncSession,
) -> None:
    epss_repo = EpssScoreRepository(session)
    kev_repo = KevCatalogRepository(session)
    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=kev_repo)
    finding = _finding(category=FindingCategory.RCE, cvss_v3_score=9.5)

    low = await enricher.enrich(
        [finding], mission_wellbeing=MissionWellbeing.LOW
    )
    high = await enricher.enrich(
        [finding], mission_wellbeing=MissionWellbeing.HIGH
    )
    # Higher mission_wellbeing must not yield a *less* urgent decision.
    weight = {
        SSVCDecision.TRACK: 1,
        SSVCDecision.TRACK_STAR: 2,
        SSVCDecision.ATTEND: 3,
        SSVCDecision.ACT: 4,
    }
    assert weight[high[0].ssvc_decision] >= weight[low[0].ssvc_decision]


# ---------------------------------------------------------------------------
# Idempotency — re-running enrichment is a no-op when nothing changed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrichment_is_idempotent(session: AsyncSession) -> None:
    epss_repo = EpssScoreRepository(session)
    kev_repo = KevCatalogRepository(session)
    await _seed_epss(
        epss_repo,
        EpssScoreRecord(
            cve_id="CVE-2024-77771",
            epss_score=0.42,
            epss_percentile=0.55,
            model_date=date(2026, 4, 15),
            updated_at=date(2026, 4, 16),  # type: ignore[arg-type]
        ),
    )
    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=kev_repo)
    finding = _finding()
    once = await enricher.enrich(
        [finding], cve_ids_by_finding={str(finding.id): ["CVE-2024-77771"]}
    )
    twice = await enricher.enrich(
        once, cve_ids_by_finding={str(finding.id): ["CVE-2024-77771"]}
    )
    assert once[0].epss_score == twice[0].epss_score
    assert once[0].epss_percentile == twice[0].epss_percentile
    assert once[0].kev_listed == twice[0].kev_listed
    assert once[0].ssvc_decision == twice[0].ssvc_decision
