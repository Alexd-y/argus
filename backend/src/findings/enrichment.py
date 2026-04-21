"""ARG-044 — FindingDTO intel enrichment (EPSS + KEV + SSVC).

The :class:`FindingEnricher` is the I/O-aware companion to the pure
:class:`src.findings.normalizer.Normalizer`. It takes a list of
already-normalised findings and decorates each with:

* ``epss_score`` / ``epss_percentile`` — looked up from the
  ``epss_scores`` Postgres table via :class:`EpssScoreRepository`.
* ``kev_listed`` / ``kev_added_date`` — looked up from the
  ``kev_catalog`` table via :class:`KevCatalogRepository`.
* ``ssvc_decision`` — computed by :func:`evaluate_ssvc` after deriving
  the four CISA SSVC v2.1 axes from the enriched DTO.

Design constraints honoured here:

* **Backward compat.** Findings produced by Cycle 1-3 normalisers (no
  CVE IDs, only CVSS / category / status) flow through unchanged when
  no CVE bag is supplied — ``epss_score`` stays ``None``, ``kev_listed``
  stays ``False``. SSVC is still derived (using the conservative defaults
  in :func:`derive_ssvc_inputs`) so every DTO leaves the enricher with a
  populated ``ssvc_decision``.
* **No network egress in the hot path.** The enricher reads from
  Postgres only — the daily Celery beat refresh is responsible for
  keeping the tables fresh. Air-gap deployments therefore Just Work
  once the operator seeds the tables manually.
* **Graceful degradation.** A failed DB call (timeout, transient lock
  contention) returns the original DTO. We log the failure once per
  batch but never raise; intel enrichment is best-effort.
* **Immutability.** :class:`FindingDTO` is frozen; ``model_copy`` is
  used to materialise the enriched copy.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Final

from src.findings.epss_persistence import EpssScoreRepository
from src.findings.kev_persistence import KevCatalogRepository
from src.findings.ssvc import (
    MissionWellbeing,
    derive_ssvc_inputs,
    evaluate_ssvc,
)
from src.pipeline.contracts.finding_dto import FindingDTO

_logger = logging.getLogger(__name__)


_CVE_RE: Final[re.Pattern[str]] = re.compile(r"^CVE-\d{4}-\d{4,7}$")


# ---------------------------------------------------------------------------
# Lightweight intermediate value rows
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EpssRow:
    """Trimmed EPSS lookup result (decoupled from the ORM record)."""

    score: float
    percentile: float


@dataclass(frozen=True, slots=True)
class KevRow:
    """Trimmed KEV lookup result (decoupled from the ORM record)."""

    listed: bool
    date_added: date


# ---------------------------------------------------------------------------
# Enricher
# ---------------------------------------------------------------------------


class FindingEnricher:
    """I/O-aware enrichment layer for :class:`FindingDTO` lists.

    The enricher is intentionally stateless apart from the injected
    repositories — composition with FastAPI request scopes / Celery task
    scopes is the caller's responsibility.
    """

    def __init__(
        self,
        *,
        epss_repo: EpssScoreRepository | None,
        kev_repo: KevCatalogRepository | None,
        airgap: bool = False,
    ) -> None:
        self._epss_repo = epss_repo
        self._kev_repo = kev_repo
        self._airgap = bool(airgap)

    async def enrich(
        self,
        findings: Sequence[FindingDTO],
        *,
        cve_ids_by_finding: dict[str, list[str]] | None = None,
        mission_wellbeing: MissionWellbeing = MissionWellbeing.MEDIUM,
    ) -> list[FindingDTO]:
        """Return ``findings`` with EPSS / KEV / SSVC populated.

        ``cve_ids_by_finding`` maps a stringified ``finding.id`` to one or
        more CVE IDs; absent entries are treated as "no CVE association",
        in which case EPSS / KEV stay at their defaults but SSVC is still
        derived from the existing DTO state.
        """
        if not findings:
            return []

        cve_map = _normalise_cve_map(cve_ids_by_finding or {})
        all_cves = sorted({c for cs in cve_map.values() for c in cs})
        epss_lookup, kev_lookup = await self._fetch_intel(all_cves)

        out: list[FindingDTO] = []
        for finding in findings:
            cves = cve_map.get(str(finding.id), [])
            enriched = self._enrich_one(
                finding,
                cve_ids=cves,
                epss=epss_lookup,
                kev=kev_lookup,
                mission_wellbeing=mission_wellbeing,
            )
            out.append(enriched)
        return out

    async def _fetch_intel(
        self, cves: list[str]
    ) -> tuple[dict[str, EpssRow], dict[str, KevRow]]:
        """Pull EPSS + KEV rows for ``cves`` (best-effort)."""
        epss_rows: dict[str, EpssRow] = {}
        kev_rows: dict[str, KevRow] = {}
        if not cves or self._airgap:
            return epss_rows, kev_rows

        if self._epss_repo is not None:
            try:
                raw = await self._epss_repo.get_many(cves)
                for cid, rec in raw.items():
                    epss_rows[cid] = EpssRow(
                        score=float(rec.epss_score),
                        percentile=float(rec.epss_percentile),
                    )
            except Exception:
                _logger.warning(
                    "enrichment.epss_lookup_failed",
                    extra={"event": "enrichment_epss_lookup_failed"},
                )

        if self._kev_repo is not None:
            try:
                listed = await self._kev_repo.get_listed_set(cves)
                for cid in listed:
                    kev_rec = await self._kev_repo.get(cid)
                    if kev_rec is not None:
                        kev_rows[cid] = KevRow(
                            listed=True, date_added=kev_rec.date_added
                        )
            except Exception:
                _logger.warning(
                    "enrichment.kev_lookup_failed",
                    extra={"event": "enrichment_kev_lookup_failed"},
                )

        return epss_rows, kev_rows

    def _enrich_one(
        self,
        finding: FindingDTO,
        *,
        cve_ids: list[str],
        epss: dict[str, EpssRow],
        kev: dict[str, KevRow],
        mission_wellbeing: MissionWellbeing,
    ) -> FindingDTO:
        """Return a copy of ``finding`` with intel fields populated.

        For multi-CVE findings (rare, but possible — some scanners emit
        a finding per template referencing 2+ CVEs) we pick the *worst*
        signal: highest EPSS, "is listed" if any CVE is listed.
        """
        epss_score = finding.epss_score
        epss_percentile = finding.epss_percentile
        kev_listed = finding.kev_listed
        kev_added_date = finding.kev_added_date

        for cid in cve_ids:
            row = epss.get(cid)
            if row is not None:
                if epss_score is None or row.score > epss_score:
                    epss_score = row.score
                if epss_percentile is None or row.percentile > epss_percentile:
                    epss_percentile = row.percentile

            kev_row = kev.get(cid)
            if kev_row is not None and kev_row.listed:
                kev_listed = True
                if kev_added_date is None or kev_row.date_added < kev_added_date:
                    kev_added_date = kev_row.date_added

        # SSVC is derived from the *enriched* DTO state — KEV / EPSS may
        # have just changed. ``public_exploit_known`` is a heuristic: if
        # EPSS percentile crosses 0.5, treat it as a published PoC.
        public_exploit_known = bool(
            epss_percentile is not None and epss_percentile >= 0.5
        )
        inputs = derive_ssvc_inputs(
            finding,
            kev_listed=bool(kev_listed),
            public_exploit_known=public_exploit_known,
            mission_wellbeing=mission_wellbeing,
        )
        ssvc_decision = evaluate_ssvc(
            exploitation=inputs.exploitation,
            automatable=inputs.automatable,
            technical_impact=inputs.technical_impact,
            mission_wellbeing=inputs.mission_wellbeing,
        )

        return finding.model_copy(
            update={
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
                "kev_listed": bool(kev_listed),
                "kev_added_date": kev_added_date,
                "ssvc_decision": ssvc_decision,
            }
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_cve_map(
    raw: Mapping[str, Iterable[str]],
) -> dict[str, list[str]]:
    """Upper-case + filter invalid CVE IDs from the per-finding map."""
    out: dict[str, list[str]] = {}
    for finding_id, cves in raw.items():
        cleaned: list[str] = []
        seen: set[str] = set()
        for c in cves or []:
            up = c.upper()
            if _CVE_RE.fullmatch(up) and up not in seen:
                cleaned.append(up)
                seen.add(up)
        if cleaned:
            out[finding_id] = cleaned
    return out


__all__ = [
    "EpssRow",
    "FindingEnricher",
    "KevRow",
]
