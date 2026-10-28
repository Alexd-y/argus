"""Correlate DWM observations with findings (T2).

A DWM observation is external context, NOT proof of exploitation. Correlation
writes observation ids into ``Finding.provenance['dark_web']`` and NEVER touches
``evidence_tier`` / ``confidence`` / ``verdict``. A unit test asserts the tier
is unchanged after correlation.
"""

from __future__ import annotations

import logging
from typing import Any

from src.intel.dark_web.catalog import DarkWebCatalog, load_catalog
from src.intel.dark_web.contracts import DarkWebReport, DarkWebReportStatus
from src.intel.dark_web.coordinator import run_sweep
from src.intel.dark_web.selectors import build_finding_selectors

logger = logging.getLogger(__name__)


def attach_dark_web_provenance(provenance: Any, observation_ids: list[str]) -> dict[str, Any]:
    """Return an updated provenance dict with the DWM observation ids merged in.

    Pure + idempotent. Does not read or write evidence_tier/confidence/verdict.
    """

    prov: dict[str, Any] = dict(provenance) if isinstance(provenance, dict) else {}
    existing = prov.get("dark_web")
    merged: list[str] = list(existing) if isinstance(existing, list) else []
    for oid in observation_ids:
        if oid and oid not in merged:
            merged.append(oid)
    prov["dark_web"] = merged
    return prov


async def correlate_findings(
    session: Any,
    tenant_id: str,
    scan_id: str,
    findings: list[Any],
    *,
    target: str = "",
    catalog: DarkWebCatalog | None = None,
    collectors: list[Any] | None = None,
    scope_engine: Any | None = None,
    persist: bool = True,
    store_raw: bool = True,
    audit: bool = True,
    max_findings: int = 50,
) -> DarkWebReport:
    """Build per-finding selectors, sweep, persist observations with finding_id,
    and link observation ids into each finding's provenance (never the tier)."""

    catalog = catalog or load_catalog()
    all_obs: list[Any] = []
    per_finding: dict[str, list[str]] = {}

    for finding in findings[:max_findings]:
        fid = _finding_id(finding)
        selectors = build_finding_selectors(
            finding,
            rules=catalog.selector_rules,
            scope_engine=scope_engine,
            target_domain=target,
        )
        if not selectors:
            continue
        report = await run_sweep(
            session=session,
            tenant_id=tenant_id,
            scan_id=scan_id,
            selectors=selectors,
            target=target,
            collectors=collectors,
            catalog=catalog,
            store_raw=store_raw,
            persist=persist,
            audit=audit,
        )
        for obs in report.observations:
            all_obs.append(obs)
            if fid:
                per_finding.setdefault(fid, []).append(obs.id)

    # Link provenance WITHOUT touching tier/confidence/verdict.
    for finding in findings[:max_findings]:
        fid = _finding_id(finding)
        obs_ids = per_finding.get(fid)
        if not obs_ids:
            continue
        _set_provenance(finding, attach_dark_web_provenance(_get_provenance(finding), obs_ids))

    status = DarkWebReportStatus.PRESENT if all_obs else DarkWebReportStatus.RAN_EMPTY
    return DarkWebReport(scan_id=scan_id, target=target, observations=all_obs, status=status)


def _finding_id(finding: Any) -> str:
    for key in ("id", "finding_id"):
        val = getattr(finding, key, None) if not isinstance(finding, dict) else finding.get(key)
        if val:
            return str(val)
    return ""


def _get_provenance(finding: Any) -> Any:
    if isinstance(finding, dict):
        return finding.get("provenance")
    return getattr(finding, "provenance", None)


def _set_provenance(finding: Any, provenance: dict[str, Any]) -> None:
    if isinstance(finding, dict):
        finding["provenance"] = provenance
    else:
        try:
            finding.provenance = provenance
        except Exception:  # noqa: BLE001 - frozen/odd objects: skip silently
            logger.debug("darkweb_provenance_set_skipped")


__all__ = ["attach_dark_web_provenance", "correlate_findings"]
