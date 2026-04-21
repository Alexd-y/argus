"""ARG-044 — unit tests for :class:`src.findings.enrichment.FindingEnricher`.

The enricher composes EPSS / KEV repositories with the SSVC v2.1
matrix. We use lightweight fakes for both repositories so the tests
stay synchronous-fast and offline. The Postgres-backed integration
contract is covered by ``test_epss_persistence.py`` and
``test_kev_persistence.py``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

from src.findings.enrichment import FindingEnricher
from src.findings.epss_persistence import EpssScoreRecord
from src.findings.kev_persistence import KevRecord
from src.pipeline.contracts.finding_dto import (
    FindingCategory,
    FindingDTO,
    SSVCDecision,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeEpssRepo:
    def __init__(
        self,
        rows: dict[str, EpssScoreRecord] | None = None,
        *,
        raise_on_get_many: bool = False,
    ) -> None:
        self._rows = {k.upper(): v for k, v in (rows or {}).items()}
        self.raise_on_get_many = raise_on_get_many
        self.get_many_calls: list[list[str]] = []

    async def get_many(self, cve_ids: Iterable[str]) -> dict[str, EpssScoreRecord]:
        ids = sorted({c.upper() for c in cve_ids})
        self.get_many_calls.append(ids)
        if self.raise_on_get_many:
            raise RuntimeError("epss db down")
        return {cid: self._rows[cid] for cid in ids if cid in self._rows}


class _FakeKevRepo:
    def __init__(
        self,
        records: dict[str, KevRecord] | None = None,
        *,
        raise_on_listed: bool = False,
    ) -> None:
        self._records = {k.upper(): v for k, v in (records or {}).items()}
        self.raise_on_listed = raise_on_listed
        self.listed_calls: list[list[str]] = []
        self.get_calls: list[str] = []

    async def get_listed_set(self, cve_ids: Iterable[str]) -> set[str]:
        ids = sorted({c.upper() for c in cve_ids})
        self.listed_calls.append(ids)
        if self.raise_on_listed:
            raise RuntimeError("kev db down")
        return {cid for cid in ids if cid in self._records}

    async def get(self, cve_id: str) -> KevRecord | None:
        self.get_calls.append(cve_id.upper())
        return self._records.get(cve_id.upper())


def _epss(score: float, pct: float) -> EpssScoreRecord:
    return EpssScoreRecord(
        cve_id="CVE-2024-0001",
        epss_score=score,
        epss_percentile=pct,
        model_date=date(2026, 4, 1),
        updated_at=datetime(2026, 4, 1, tzinfo=timezone.utc),
    )


def _kev(cve_id: str, *, added: date | None = None) -> KevRecord:
    return KevRecord(
        cve_id=cve_id,
        vendor_project="Acme",
        product="Foo",
        vulnerability_name="Foo RCE",
        date_added=added or date(2026, 1, 1),
        short_description="rce",
        required_action="patch",
        due_date=None,
        known_ransomware_use=False,
        notes=None,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_enrich_empty_input(make_finding: Callable[..., FindingDTO]) -> None:
    enricher = FindingEnricher(epss_repo=None, kev_repo=None)
    assert await enricher.enrich([]) == []


async def test_enrich_passthrough_without_repos(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """No repos + no CVE map → SSVC still derived but EPSS/KEV untouched."""
    enricher = FindingEnricher(epss_repo=None, kev_repo=None)
    f = make_finding()
    out = await enricher.enrich([f])
    assert len(out) == 1
    assert out[0].epss_score == f.epss_score
    assert out[0].kev_listed == f.kev_listed
    # SSVC must always be assigned.
    assert isinstance(out[0].ssvc_decision, SSVCDecision)


async def test_enrich_populates_epss(
    make_finding: Callable[..., FindingDTO],
) -> None:
    f = make_finding()
    epss_repo = _FakeEpssRepo({"CVE-2024-1234": _epss(0.42, 0.85)})
    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=None)
    out = await enricher.enrich(
        [f], cve_ids_by_finding={str(f.id): ["cve-2024-1234"]}
    )
    assert out[0].epss_score == pytest.approx(0.42)
    assert out[0].epss_percentile == pytest.approx(0.85)
    # CVE map normalisation: lowercase input becomes upper-case in the repo call.
    assert epss_repo.get_many_calls == [["CVE-2024-1234"]]


async def test_enrich_populates_kev(
    make_finding: Callable[..., FindingDTO],
) -> None:
    f = make_finding()
    kev_repo = _FakeKevRepo({"CVE-2024-1234": _kev("CVE-2024-1234", added=date(2026, 2, 14))})
    enricher = FindingEnricher(epss_repo=None, kev_repo=kev_repo)
    out = await enricher.enrich(
        [f], cve_ids_by_finding={str(f.id): ["CVE-2024-1234"]}
    )
    assert out[0].kev_listed is True
    assert out[0].kev_added_date == date(2026, 2, 14)


async def test_enrich_picks_worst_epss_for_multi_cve(
    make_finding: Callable[..., FindingDTO],
) -> None:
    f = make_finding()
    epss_repo = _FakeEpssRepo(
        {
            "CVE-2024-0001": _epss(0.10, 0.20),
            "CVE-2024-0002": _epss(0.95, 0.99),
        }
    )
    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=None)
    out = await enricher.enrich(
        [f],
        cve_ids_by_finding={str(f.id): ["CVE-2024-0001", "CVE-2024-0002"]},
    )
    assert out[0].epss_score == pytest.approx(0.95)
    assert out[0].epss_percentile == pytest.approx(0.99)


async def test_enrich_kev_picks_earliest_added_date(
    make_finding: Callable[..., FindingDTO],
) -> None:
    f = make_finding()
    kev_repo = _FakeKevRepo(
        {
            "CVE-2024-0001": _kev("CVE-2024-0001", added=date(2026, 6, 1)),
            "CVE-2024-0002": _kev("CVE-2024-0002", added=date(2026, 1, 1)),
        }
    )
    enricher = FindingEnricher(epss_repo=None, kev_repo=kev_repo)
    out = await enricher.enrich(
        [f],
        cve_ids_by_finding={str(f.id): ["CVE-2024-0001", "CVE-2024-0002"]},
    )
    assert out[0].kev_listed is True
    assert out[0].kev_added_date == date(2026, 1, 1)


async def test_invalid_cve_ids_dropped(
    make_finding: Callable[..., FindingDTO],
) -> None:
    f = make_finding()
    epss_repo = _FakeEpssRepo({"CVE-2024-1234": _epss(0.1, 0.2)})
    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=None)
    out = await enricher.enrich(
        [f],
        cve_ids_by_finding={str(f.id): ["bogus", "CVE-2024-1234", "also-bogus"]},
    )
    assert out[0].epss_score == pytest.approx(0.1)


async def test_airgap_skips_repo_calls(
    make_finding: Callable[..., FindingDTO],
) -> None:
    f = make_finding()
    epss_repo = _FakeEpssRepo({"CVE-2024-1234": _epss(0.9, 0.99)})
    kev_repo = _FakeKevRepo({"CVE-2024-1234": _kev("CVE-2024-1234")})
    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=kev_repo, airgap=True)
    out = await enricher.enrich(
        [f], cve_ids_by_finding={str(f.id): ["CVE-2024-1234"]}
    )
    assert out[0].epss_score == f.epss_score  # unchanged
    assert out[0].kev_listed == f.kev_listed
    assert epss_repo.get_many_calls == []
    assert kev_repo.listed_calls == []


async def test_repo_failure_returns_dto_without_epss(
    make_finding: Callable[..., FindingDTO],
) -> None:
    f = make_finding()
    enricher = FindingEnricher(
        epss_repo=_FakeEpssRepo(raise_on_get_many=True),
        kev_repo=None,
    )
    out = await enricher.enrich(
        [f], cve_ids_by_finding={str(f.id): ["CVE-2024-1234"]}
    )
    assert out[0].epss_score == f.epss_score


async def test_repo_failure_returns_dto_without_kev(
    make_finding: Callable[..., FindingDTO],
) -> None:
    f = make_finding()
    enricher = FindingEnricher(
        epss_repo=None,
        kev_repo=_FakeKevRepo(raise_on_listed=True),
    )
    out = await enricher.enrich(
        [f], cve_ids_by_finding={str(f.id): ["CVE-2024-1234"]}
    )
    assert out[0].kev_listed is False


async def test_kev_listing_propagates_to_ssvc(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """KEV listing should drive Exploitation=ACTIVE → at least Track*."""
    f = make_finding(
        category=FindingCategory.RCE,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_v3_score=9.8,
    )
    kev_repo = _FakeKevRepo({"CVE-2024-7777": _kev("CVE-2024-7777")})
    enricher = FindingEnricher(epss_repo=None, kev_repo=kev_repo)
    out = await enricher.enrich(
        [f], cve_ids_by_finding={str(f.id): ["CVE-2024-7777"]}
    )
    # Active exploitation + total impact → at least Attend.
    assert out[0].kev_listed is True
    assert out[0].ssvc_decision in {SSVCDecision.ATTEND, SSVCDecision.ACT}


async def test_returned_findings_are_immutable(
    make_finding: Callable[..., FindingDTO],
) -> None:
    f = make_finding()
    enricher = FindingEnricher(epss_repo=None, kev_repo=None)
    out = await enricher.enrich([f])
    with pytest.raises(Exception):
        out[0].epss_score = 0.99  # type: ignore[misc]


async def test_finding_id_lookup_uses_str_form(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """``cve_ids_by_finding`` keys are matched via ``str(finding.id)``."""
    fid = uuid4()
    f = make_finding(finding_id=fid)
    epss_repo = _FakeEpssRepo({"CVE-2024-0001": _epss(0.5, 0.5)})
    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=None)
    out = await enricher.enrich(
        [f], cve_ids_by_finding={str(fid): ["CVE-2024-0001"]}
    )
    assert out[0].epss_score == pytest.approx(0.5)


async def test_cve_id_dedup(
    make_finding: Callable[..., FindingDTO],
) -> None:
    f = make_finding()
    epss_repo = _FakeEpssRepo({"CVE-2024-0001": _epss(0.5, 0.5)})
    enricher = FindingEnricher(epss_repo=epss_repo, kev_repo=None)
    await enricher.enrich(
        [f],
        cve_ids_by_finding={
            str(f.id): ["CVE-2024-0001", "cve-2024-0001", "CVE-2024-0001"]
        },
    )
    # Only one round-trip — the CVE list was deduped before the repo call.
    assert epss_repo.get_many_calls == [["CVE-2024-0001"]]
