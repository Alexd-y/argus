"""Stage 2 parsers — map prior_outputs and bundle to Stage 3 schemas (TM2-002).

Parses AI task outputs (critical_assets, trust_boundaries, entry_points, etc.)
into normalized Stage3 models. Handles missing/empty data and infers source
from bundle or task metadata.
"""

from __future__ import annotations

import logging
from typing import Any

from app.schemas.ai.common import PriorityLevel
from app.schemas.threat_modeling.schemas import ThreatModelInputBundle
from app.schemas.threat_modeling.stage2_artifacts import (
    AiTmPriorityHypotheses,
    PriorityHypothesis,
    Stage3ApplicationFlow,
    Stage3CriticalAsset,
    Stage3EntryPoint,
    Stage3ThreatScenario,
    Stage3TrustBoundary,
)

logger = logging.getLogger(__name__)

# Default source when task/bundle metadata unavailable
_DEFAULT_SOURCE = "ai_tm_pipeline"


def _parse_priority(val: str | float | Any) -> PriorityLevel:
    """Convert priority string or value to PriorityLevel."""
    if isinstance(val, PriorityLevel):
        return val
    s = str(val).lower().strip()
    if s in ("high", "critical"):
        return PriorityLevel.HIGH
    if s in ("low", "minimal"):
        return PriorityLevel.LOW
    return PriorityLevel.MEDIUM


def _statement_type_to_provenance(st: str | None) -> str:
    """Map StatementType to Stage3 type (observation | hypothesis)."""
    if not st:
        return "hypothesis"
    s = str(st).lower()
    if s in ("evidence", "observation"):
        return "observation"
    return "hypothesis"


def parse_critical_assets_to_stage3(
    prior_outputs: dict[str, Any],
    bundle: ThreatModelInputBundle,
) -> list[Stage3CriticalAsset]:
    """Parse critical_assets from prior_outputs to Stage3CriticalAsset list.

    Maps from prior_outputs["critical_assets"]["assets"]. Falls back to
    bundle.critical_assets when empty. Infers source from task name or bundle.
    """
    result: list[Stage3CriticalAsset] = []
    source = f"ai_tm_critical_assets"
    assets = prior_outputs.get("critical_assets", {}) or {}
    raw = (assets.get("assets") if isinstance(assets, dict) else []) or []

    if not raw:
        for i, a in enumerate(bundle.critical_assets[:100]):
            try:
                result.append(
                    Stage3CriticalAsset(
                        id=a.id,
                        name=a.name[:500],
                        type="observation",
                        source="bundle.critical_assets",
                    )
                )
            except Exception as e:
                logger.debug("Skip invalid bundle asset", extra={"idx": i, "error": str(e)})
        return result

    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        try:
            aid = str(item.get("id") or f"ca_{i}").strip()[:100]
            name = str(item.get("name") or "").strip()[:500] or f"asset_{i}"
            if not aid:
                aid = f"ca_{i}"
            st = item.get("statement_type")
            if hasattr(st, "value"):
                st = st.value
            provenance = _statement_type_to_provenance(st)
            result.append(
                Stage3CriticalAsset(
                    id=aid,
                    name=name,
                    type=provenance,
                    source=source,
                )
            )
        except Exception as e:
            logger.debug("Skip invalid critical asset", extra={"idx": i, "error": str(e)})
    return result


def parse_trust_boundaries_to_stage3(
    prior_outputs: dict[str, Any],
    bundle: ThreatModelInputBundle,
) -> list[Stage3TrustBoundary]:
    """Parse trust_boundaries from prior_outputs to Stage3TrustBoundary list.

    Maps from prior_outputs["trust_boundaries"]["boundaries"]. Falls back to
    bundle.trust_boundaries when empty.
    """
    result: list[Stage3TrustBoundary] = []
    source = "ai_tm_trust_boundaries"
    data = prior_outputs.get("trust_boundaries", {}) or {}
    raw = data.get("boundaries") if isinstance(data, dict) else []
    if not raw:
        raw = []

    if not raw:
        for i, b in enumerate(bundle.trust_boundaries[:100]):
            try:
                result.append(
                    Stage3TrustBoundary(
                        id=b.id,
                        name=b.name[:500],
                        components=list(b.components or [])[:100],
                        source="bundle.trust_boundaries",
                    )
                )
            except Exception as e:
                logger.debug("Skip invalid bundle boundary", extra={"idx": i, "error": str(e)})
        return result

    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        try:
            bid = str(item.get("id") or f"tb_{i}").strip()[:100]
            name = str(item.get("name") or "").strip()[:500] or f"boundary_{i}"
            if not bid:
                bid = f"tb_{i}"
            comps = item.get("components")
            if not isinstance(comps, list):
                comps = []
            comps = [str(c)[:500] for c in comps[:100] if c]
            result.append(
                Stage3TrustBoundary(
                    id=bid,
                    name=name,
                    components=comps,
                    source=source,
                )
            )
        except Exception as e:
            logger.debug("Skip invalid trust boundary", extra={"idx": i, "error": str(e)})
    return result


def parse_entry_points_to_stage3(
    prior_outputs: dict[str, Any],
    bundle: ThreatModelInputBundle,
) -> list[Stage3EntryPoint]:
    """Parse entry_points from prior_outputs to Stage3EntryPoint list.

    Maps from prior_outputs["entry_points"]["entry_points"]. Stage3EntryPoint
    requires component_id and type='hypothesis'. Infers component_id from
    host_or_component or first trust boundary component.
    """
    result: list[Stage3EntryPoint] = []
    source = "ai_tm_entry_points"
    data = prior_outputs.get("entry_points", {}) or {}
    raw = data.get("entry_points") if isinstance(data, dict) else []
    if not raw:
        raw = []

    boundaries = prior_outputs.get("trust_boundaries", {}) or {}
    boundary_list = boundaries.get("boundaries", []) if isinstance(boundaries, dict) else []
    first_comp = None
    if boundary_list and isinstance(boundary_list[0], dict):
        comps = boundary_list[0].get("components") or []
        if comps:
            first_comp = str(comps[0])[:100]

    if not raw:
        for i, e in enumerate(bundle.entry_points[:100]):
            try:
                comp_id = (e.host_or_component or first_comp or f"ep_comp_{i}")[:100]
                result.append(
                    Stage3EntryPoint(
                        id=e.id,
                        name=e.name[:500],
                        component_id=comp_id,
                        type="hypothesis",
                        source="bundle.entry_points",
                    )
                )
            except Exception as ex:
                logger.debug("Skip invalid bundle entry point", extra={"idx": i, "error": str(ex)})
        if not result and bundle.endpoint_inventory:
            for i, row in enumerate(bundle.endpoint_inventory[:50]):
                url = row.get("url") or row.get("path") or str(i)
                result.append(
                    Stage3EntryPoint(
                        id=f"ep_{i}",
                        name=str(url)[:500],
                        component_id=first_comp or "endpoint_inventory",
                        type="hypothesis",
                        source="bundle.endpoint_inventory",
                    )
                )
        return result

    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        try:
            eid = str(item.get("id") or f"ep_{i}").strip()[:100]
            name = str(item.get("name") or "").strip()[:500] or f"entry_{i}"
            host = item.get("host_or_component")
            comp_id = (str(host) if host else first_comp or f"ep_comp_{i}")[:100]
            if not eid:
                eid = f"ep_{i}"
            result.append(
                Stage3EntryPoint(
                    id=eid,
                    name=name,
                    component_id=comp_id,
                    type="hypothesis",
                    source=source,
                )
            )
        except Exception as e:
            logger.debug("Skip invalid entry point", extra={"idx": i, "error": str(e)})
    return result


def parse_threat_scenarios_to_stage3(
    prior_outputs: dict[str, Any],
) -> list[Stage3ThreatScenario]:
    """Parse threat_scenarios from prior_outputs to Stage3ThreatScenario list.

    Maps from prior_outputs["threat_scenarios"]["scenarios"]. Requires
    entry_point_id and attacker_profile_id (from entry_point/attacker_profile refs).
    """
    result: list[Stage3ThreatScenario] = []
    data = prior_outputs.get("threat_scenarios", {}) or {}
    raw = data.get("scenarios") if isinstance(data, dict) else []
    if not raw or not isinstance(raw, list):
        return result

    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        try:
            sid = str(item.get("id") or f"ts_{i}").strip()[:100]
            desc = str(item.get("description") or item.get("title") or "").strip()[:5000]
            if not desc:
                desc = "No description"
            entry_ref = item.get("entry_point")
            att_ref = item.get("attacker_profile")
            entry_id = str(entry_ref)[:100] if entry_ref else f"ep_{i}"
            att_id = str(att_ref)[:100] if att_ref else "ap_default"
            prio = str(item.get("priority", "medium")).lower()[:50]
            if not prio:
                prio = "medium"
            if not sid:
                sid = f"ts_{i}"
            result.append(
                Stage3ThreatScenario(
                    id=sid,
                    priority=prio,
                    entry_point_id=entry_id,
                    attacker_profile_id=att_id,
                    description=desc,
                )
            )
        except Exception as e:
            logger.debug("Skip invalid threat scenario", extra={"idx": i, "error": str(e)})
    return result


def parse_priority_hypotheses(
    bundle: ThreatModelInputBundle,
    prior_outputs: dict[str, Any],
) -> AiTmPriorityHypotheses:
    """Parse priority hypotheses from bundle and prior_outputs to AiTmPriorityHypotheses.

    Primary source: bundle.priority_hypotheses. Can augment from prior_outputs
    (e.g. threat_scenarios assumptions, testing_roadmap items) when bundle is empty.
    """
    hypotheses: list[PriorityHypothesis] = []
    source_artifact = "stage2_structured.json"

    for i, h in enumerate(bundle.priority_hypotheses or []):
        if not isinstance(h, dict):
            continue
        try:
            text = h.get("text") or h.get("hypothesis_text") or h.get("description") or ""
            text = str(text).strip()[:5000]
            if not text:
                continue
            hid = str(h.get("id") or f"ph_{i}").strip()[:100]
            if not hid:
                hid = f"ph_{i}"
            prio = _parse_priority(h.get("priority", "medium"))
            conf = float(h.get("confidence", 0.5))
            conf = max(0.0, min(1.0, conf))
            rel_asset = h.get("related_asset_id")
            if rel_asset is not None:
                rel_asset = str(rel_asset)[:100] or None
            src = str(h.get("source") or h.get("source_artifact") or source_artifact)[:500]
            hypotheses.append(
                PriorityHypothesis(
                    id=hid,
                    hypothesis_text=text,
                    priority=prio,
                    confidence=conf,
                    related_asset_id=rel_asset,
                    source_artifact=src,
                )
            )
        except Exception as e:
            logger.debug("Skip invalid priority hypothesis", extra={"idx": i, "error": str(e)})

    if not hypotheses:
        scenarios = prior_outputs.get("threat_scenarios", {}) or {}
        raw_scenarios = scenarios.get("scenarios", []) if isinstance(scenarios, dict) else []
        for i, s in enumerate(raw_scenarios[:30]):
            if not isinstance(s, dict):
                continue
            desc = s.get("description") or s.get("title") or ""
            if not desc:
                continue
            try:
                hypotheses.append(
                    PriorityHypothesis(
                        id=f"ph_ts_{i}",
                        hypothesis_text=str(desc)[:5000],
                        priority=_parse_priority(s.get("priority", "medium")),
                        confidence=0.5,
                        related_asset_id=None,
                        source_artifact="ai_tm_threat_scenarios",
                    )
                )
            except Exception:
                pass

    return AiTmPriorityHypotheses(hypotheses=hypotheses)


def parse_application_flows_to_stage3(
    prior_outputs: dict[str, Any],
    bundle: ThreatModelInputBundle,
) -> list[Stage3ApplicationFlow]:
    """Parse application_flows from prior_outputs to Stage3ApplicationFlow list.

    Maps from prior_outputs["application_flows"]["flows"]. Falls back to
    bundle.application_flows or bundle.api_surface when empty.
    """
    result: list[Stage3ApplicationFlow] = []
    data = prior_outputs.get("application_flows", {}) or {}
    raw = data.get("flows") if isinstance(data, dict) else []
    if not raw:
        raw = []

    if not raw:
        for i, f in enumerate(bundle.application_flows[:100]):
            try:
                result.append(
                    Stage3ApplicationFlow(
                        id=f.id,
                        source=f.source[:500],
                        sink=f.sink[:500],
                        data_type=f.data_type[:200] if f.data_type else None,
                        description=f.description[:2000] if f.description else None,
                    )
                )
            except Exception as e:
                logger.debug("Skip invalid bundle flow", extra={"idx": i, "error": str(e)})
        if not result and bundle.api_surface:
            for i, row in enumerate(bundle.api_surface[:50]):
                src = row.get("source") or "client"
                sink = row.get("sink") or row.get("path") or "server"
                result.append(
                    Stage3ApplicationFlow(
                        id=f"flow_{i}",
                        source=str(src)[:500],
                        sink=str(sink)[:500],
                        data_type=row.get("data_type"),
                        description="From api_surface",
                    )
                )
        return result

    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        try:
            fid = str(item.get("id") or f"flow_{i}").strip()[:100]
            src = str(item.get("source") or "").strip()[:500] or "unknown"
            sink = str(item.get("sink") or "").strip()[:500] or "unknown"
            if not fid:
                fid = f"flow_{i}"
            dtype = item.get("data_type")
            dtype = str(dtype)[:200] if dtype else None
            desc = item.get("description")
            desc = str(desc)[:2000] if desc else None
            result.append(
                Stage3ApplicationFlow(
                    id=fid,
                    source=src,
                    sink=sink,
                    data_type=dtype,
                    description=desc,
                )
            )
        except Exception as e:
            logger.debug("Skip invalid application flow", extra={"idx": i, "error": str(e)})
    return result
