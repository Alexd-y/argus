"""Report/artifact generators for Threat Modeling — 13 artifact types.

Generates stage2_inputs.json (traceability), threat_model.md, CSVs, markdown
reports, and JSON traces from pipeline outputs (bundle, AI task results, MCP traces).
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from io import StringIO
from typing import Any

from app.schemas.ai.common import PriorityLevel
from app.schemas.threat_modeling.schemas import (
    AIReasoningTrace,
    AttackerProfile,
    MCPInvocationTrace,
    ThreatModelArtifact,
    ThreatModelInputBundle,
)
from app.schemas.threat_modeling.stage2_artifacts import ThreatModelUnified
from src.recon.threat_modeling.stage2_parsers import (
    parse_application_flows_to_stage3,
    parse_critical_assets_to_stage3,
    parse_entry_points_to_stage3,
    parse_priority_hypotheses,
    parse_threat_scenarios_to_stage3,
    parse_trust_boundaries_to_stage3,
)

# --- Helpers ---


def _escape_csv_field(value: str | None) -> str:
    """Return safe string for CSV; None -> empty."""
    if value is None:
        return ""
    return str(value)


def _serialize_datetime(dt: datetime | None) -> str | None:
    """Serialize datetime to ISO string for JSON."""
    if dt is None:
        return None
    return dt.isoformat()


def _get_assets(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None,
) -> list[tuple[str, str, str, str, str | None]]:
    """Return list of (id, name, asset_type, description, statement_type) from bundle or AI output."""
    if ai_results:
        out = ai_results.get("critical_assets")
        if out is not None and hasattr(out, "assets"):
            return [
                (
                    getattr(a, "id", ""),
                    getattr(a, "name", ""),
                    getattr(a, "asset_type", ""),
                    _escape_csv_field(getattr(a, "description", None)),
                    _stmt_type(getattr(a, "statement_type", None)),
                )
                for a in out.assets
            ]
    return [
        (a.id, a.name, a.asset_type, _escape_csv_field(a.description), None)
        for a in bundle.critical_assets
    ]


def _stmt_type(val: Any) -> str | None:
    """Extract string from StatementType enum or return as-is if str."""
    if val is None:
        return None
    return getattr(val, "value", val) if hasattr(val, "value") else str(val)


def _tag(st: str | None) -> str:
    """Return inline tag for statement type, e.g. ' [Evidence]'."""
    if not st:
        return ""
    return f" *[{st}]*"


def _get_entry_points(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None,
) -> list[tuple[str, str, str, str, str]]:
    """Return list of (id, name, entry_type, host_or_component, description)."""
    if ai_results:
        out = ai_results.get("entry_points")
        if out is not None and hasattr(out, "entry_points"):
            return [
                (
                    getattr(e, "id", ""),
                    getattr(e, "name", ""),
                    getattr(e, "entry_type", ""),
                    _escape_csv_field(getattr(e, "host_or_component", None)),
                    _escape_csv_field(getattr(e, "description", None)),
                )
                for e in out.entry_points
            ]
    return [
        (
            e.id,
            e.name,
            e.entry_type,
            _escape_csv_field(e.host_or_component),
            _escape_csv_field(e.description),
        )
        for e in bundle.entry_points
    ]


def _get_attacker_profiles(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None,
) -> list[tuple[str, str, str, str]]:
    """Return list of (id, name, capability_level, description)."""
    if ai_results:
        out = ai_results.get("attacker_profiles")
        if out is not None and hasattr(out, "profiles"):
            return [
                (
                    getattr(p, "id", ""),
                    getattr(p, "name", ""),
                    getattr(p, "capability_level", ""),
                    _escape_csv_field(getattr(p, "description", None)),
                )
                for p in out.profiles
            ]
    return [
        (
            p.id,
            p.name,
            p.capability_level,
            _escape_csv_field(p.description),
        )
        for p in bundle.attacker_profiles
    ]


def _get_trust_boundaries(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None,
) -> list[tuple[str, str, str, list[str]]]:
    """Return list of (id, name, description, components)."""
    if ai_results:
        out = ai_results.get("trust_boundaries")
        if out is not None and hasattr(out, "boundaries"):
            return [
                (
                    getattr(b, "id", ""),
                    getattr(b, "name", ""),
                    _escape_csv_field(getattr(b, "description", None)),
                    list(getattr(b, "components", []) or []),
                )
                for b in out.boundaries
            ]
    return [
        (b.id, b.name, _escape_csv_field(b.description), list(b.components or []))
        for b in bundle.trust_boundaries
    ]


def _get_application_flows(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None,
) -> list[tuple[str, str, str, str, str]]:
    """Return list of (id, source, sink, data_type, description)."""
    if ai_results:
        out = ai_results.get("application_flows")
        if out is not None and hasattr(out, "flows"):
            return [
                (
                    getattr(f, "id", ""),
                    getattr(f, "source", ""),
                    getattr(f, "sink", ""),
                    _escape_csv_field(getattr(f, "data_type", None)),
                    _escape_csv_field(getattr(f, "description", None)),
                )
                for f in out.flows
            ]
    return [
        (
            f.id,
            f.source,
            f.sink,
            _escape_csv_field(f.data_type),
            _escape_csv_field(f.description),
        )
        for f in bundle.application_flows
    ]


def _get_executive_summary(ai_results: dict[str, Any] | None) -> str:
    """Extract executive summary from report_summary task output."""
    if ai_results:
        out = ai_results.get("report_summary")
        if out is not None and hasattr(out, "executive_summary"):
            return str(out.executive_summary)
    return ""


def _get_unknowns_from_ai_results(ai_results: dict[str, Any] | None) -> list[str]:
    """Extract unknowns/gaps from report_summary or gaps field."""
    if not ai_results:
        return []
    out = ai_results.get("report_summary")
    if out is None:
        return []
    unknowns: list[str] = []
    if hasattr(out, "unknowns") and isinstance(out.unknowns, list):
        unknowns.extend(str(u) for u in out.unknowns)
    if hasattr(out, "gaps") and isinstance(out.gaps, list):
        unknowns.extend(str(g) for g in out.gaps)
    return unknowns


# --- CSV generators ---


def generate_critical_assets_csv(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None = None,
) -> str:
    """Generate critical_assets.csv with id, name, asset_type, description."""
    rows = _get_assets(bundle, ai_results)
    buf = StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(["id", "name", "asset_type", "description"])
    for r in rows:
        writer.writerow(r[:4])
    return buf.getvalue()


def generate_entry_points_csv(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None = None,
) -> str:
    """Generate entry_points.csv with id, name, entry_type, host_or_component, description."""
    rows = _get_entry_points(bundle, ai_results)
    buf = StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(["id", "name", "entry_type", "host_or_component", "description"])
    for r in rows:
        writer.writerow(r)
    return buf.getvalue()


def generate_attacker_profiles_csv(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None = None,
) -> str:
    """Generate attacker_profiles.csv with id, name, capability_level, description."""
    rows = _get_attacker_profiles(bundle, ai_results)
    buf = StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(["id", "name", "capability_level", "description"])
    for r in rows:
        writer.writerow(r)
    return buf.getvalue()


def generate_trust_boundaries_csv(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None = None,
) -> str:
    """Generate trust_boundaries.csv with id, name, description, components (pipe-separated)."""
    rows = _get_trust_boundaries(bundle, ai_results)
    buf = StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(["id", "name", "description", "components"])
    for r in rows:
        writer.writerow([r[0], r[1], r[2], "|".join(r[3])])
    return buf.getvalue()


def generate_threat_scenarios_csv(
    artifact: ThreatModelArtifact,
) -> str:
    """Generate threat_scenarios.csv with full scenario fields."""
    buf = StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow([
        "id",
        "title",
        "related_assets",
        "host_component",
        "entry_point",
        "attacker_profile",
        "trust_boundary",
        "description",
        "likelihood",
        "impact",
        "priority",
        "recon_evidence_refs",
        "assumptions",
        "recommended_next_manual_checks",
    ])
    for s in artifact.scenarios:
        writer.writerow([
            s.id,
            s.title,
            "|".join(s.related_assets) if s.related_assets else "",
            _escape_csv_field(s.host_component),
            _escape_csv_field(s.entry_point),
            _escape_csv_field(s.attacker_profile),
            _escape_csv_field(s.trust_boundary),
            s.description,
            s.likelihood,
            s.impact,
            s.priority.value if isinstance(s.priority, PriorityLevel) else str(s.priority),
            "|".join(s.recon_evidence_refs) if s.recon_evidence_refs else "",
            "|".join(s.assumptions) if s.assumptions else "",
            "|".join(s.recommended_next_manual_checks)
            if s.recommended_next_manual_checks
            else "",
        ])
    return buf.getvalue()


# --- Markdown generators ---


def generate_threat_model_md(
    bundle: ThreatModelInputBundle,
    artifact: ThreatModelArtifact,
    ai_results: dict[str, Any] | None = None,
) -> str:
    """Generate threat_model.md — executive summary with tagged sections.

    Sections: Executive Summary, Recon Inputs Used, Scope Preconditions, Critical Assets,
    Architecture/Component View, Trust Boundaries, Attacker Profiles, Entry Points,
    Application Flow Hints, Threat Scenarios, Scenario Prioritization, Unknowns/Evidence Gaps,
    Recommended Next Manual Validation.
    Tag statements as Evidence/Observation/Inference/Hypothesis where applicable.
    """
    lines: list[str] = []
    exec_summary = _get_executive_summary(ai_results)

    lines.append("# Threat Model Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    if exec_summary:
        lines.append(exec_summary)
    else:
        lines.append("*[No executive summary from report_summary task.]*")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Recon Inputs Used")
    lines.append("")
    lines.append(f"- **Engagement ID**: {bundle.engagement_id}")
    if bundle.target_id:
        lines.append(f"- **Target ID**: {bundle.target_id}")
    lines.append(f"- **Artifact refs**: {', '.join(bundle.artifact_refs[:20])}")
    if len(bundle.artifact_refs) > 20:
        lines.append(f"  *(and {len(bundle.artifact_refs) - 20} more)*")
    lines.append("")

    lines.append("## Scope Preconditions")
    lines.append("")
    lines.append("- Threat model derived from recon artifacts listed above.")
    lines.append("- Scope limited to discovered endpoints, hosts, and API surface.")
    lines.append("")

    lines.append("## Critical Assets")
    lines.append("")
    lines.append("*Statements tagged as Evidence | Observation | Inference | Hypothesis where available.*")
    lines.append("")
    assets = _get_assets(bundle, ai_results)
    if assets:
        for aid, name, atype, desc, st in assets:
            tag = _tag(st)
            lines.append(f"- **{name}** (id: `{aid}`, type: {atype}){tag}")
            if desc:
                lines.append(f"  - {desc}")
        lines.append("")
    else:
        lines.append("*None identified.*")
        lines.append("")

    lines.append("## Architecture/Component View")
    lines.append("")
    boundaries = _get_trust_boundaries(bundle, ai_results)
    if boundaries:
        for bid, bname, bdesc, comps in boundaries:
            lines.append(f"- **{bname}** (id: `{bid}`)")
            if bdesc:
                lines.append(f"  - {bdesc}")
            if comps:
                lines.append(f"  - Components: {', '.join(comps)}")
        lines.append("")
    else:
        lines.append("*No trust boundaries mapped.*")
        lines.append("")

    lines.append("## Trust Boundaries")
    lines.append("")
    for bid, bname, bdesc, comps in boundaries:
        lines.append(f"- **{bname}** (`{bid}`): {bdesc or 'No description'}")
        if comps:
            lines.append(f"  - Components: {' | '.join(comps)}")
    if not boundaries:
        lines.append("*None.*")
    lines.append("")

    lines.append("## Attacker Profiles")
    lines.append("")
    profiles = _get_attacker_profiles(bundle, ai_results)
    for pid, pname, cap, pdesc in profiles:
        lines.append(f"- **{pname}** (id: `{pid}`, capability: {cap})")
        if pdesc:
            lines.append(f"  - {pdesc}")
    if not profiles:
        lines.append("*None defined.*")
    lines.append("")

    lines.append("## Entry Points")
    lines.append("")
    entry_pts = _get_entry_points(bundle, ai_results)
    for eid, ename, etype, host, edesc in entry_pts:
        lines.append(f"- **{ename}** (id: `{eid}`, type: {etype})")
        if host:
            lines.append(f"  - Host/component: {host}")
        if edesc:
            lines.append(f"  - {edesc}")
    if not entry_pts:
        lines.append("*None identified.*")
    lines.append("")

    lines.append("## Application Flow Hints")
    lines.append("")
    flows = _get_application_flows(bundle, ai_results)
    for fid, src, sink, dtype, fdesc in flows:
        lines.append(f"- **{fid}**: {src} → {sink}")
        if dtype:
            lines.append(f"  - Data type: {dtype}")
        if fdesc:
            lines.append(f"  - {fdesc}")
    if not flows:
        lines.append("*None inferred.*")
    lines.append("")

    lines.append("## Threat Scenarios")
    lines.append("")
    for s in artifact.scenarios:
        prio = s.priority.value if isinstance(s.priority, PriorityLevel) else str(s.priority)
        lines.append(f"### {s.title} (id: `{s.id}`, priority: {prio})")
        lines.append("")
        lines.append(s.description)
        if s.related_assets:
            lines.append(f"- Related assets: {', '.join(s.related_assets)}")
        if s.entry_point:
            lines.append(f"- Entry point: {s.entry_point}")
        if s.attacker_profile:
            lines.append(f"- Attacker profile: {s.attacker_profile}")
        if s.recon_evidence_refs:
            lines.append(f"- Evidence refs: {', '.join(s.recon_evidence_refs)}")
        lines.append("")
    if not artifact.scenarios:
        lines.append("*No scenarios generated.*")
        lines.append("")

    lines.append("## Scenario Prioritization")
    lines.append("")
    for item in artifact.testing_roadmap:
        prio = (
            item.priority.value
            if isinstance(item.priority, PriorityLevel)
            else str(item.priority)
        )
        lines.append(f"- **{item.title}** (scenario: `{item.scenario_id}`, priority: {prio})")
        for action in item.recommended_actions:
            lines.append(f"  - {action}")
    if not artifact.testing_roadmap:
        lines.append("*No roadmap items.*")
    lines.append("")

    unknowns = _get_unknowns_from_ai_results(ai_results)
    if not unknowns:
        for s in artifact.scenarios:
            if s.assumptions:
                unknowns.extend(s.assumptions)
            if s.recommended_next_manual_checks:
                for c in s.recommended_next_manual_checks:
                    unknowns.append(f"[Scenario {s.id}] {c}")

    lines.append("## Unknowns/Evidence Gaps")
    lines.append("")
    if unknowns:
        for u in unknowns[:50]:
            lines.append(f"- {u}")
        if len(unknowns) > 50:
            lines.append(f"- *... and {len(unknowns) - 50} more*")
    else:
        lines.append("*None explicitly listed.*")
    lines.append("")

    lines.append("## Recommended Next Manual Validation")
    lines.append("")
    seen: set[str] = set()
    for s in artifact.scenarios:
        for c in s.recommended_next_manual_checks:
            if c and c not in seen:
                seen.add(c)
                lines.append(f"- {c}")
    for item in artifact.testing_roadmap:
        for a in item.recommended_actions:
            if a and a not in seen:
                seen.add(a)
                lines.append(f"- {a}")
    if not seen:
        lines.append("*Review threat scenarios and testing roadmap for manual checks.*")
    lines.append("")

    return "\n".join(lines)


def generate_trust_boundaries_md(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None = None,
) -> str:
    """Generate trust_boundaries.md — narrative version of trust boundaries."""
    lines: list[str] = []
    lines.append("# Trust Boundaries")
    lines.append("")
    boundaries = _get_trust_boundaries(bundle, ai_results)
    for bid, bname, bdesc, comps in boundaries:
        lines.append(f"## {bname}")
        lines.append("")
        lines.append(f"**ID**: `{bid}`")
        lines.append("")
        if bdesc:
            lines.append(bdesc)
            lines.append("")
        if comps:
            lines.append("**Components within this boundary:**")
            for c in comps:
                lines.append(f"- {c}")
            lines.append("")
    if not boundaries:
        lines.append("*No trust boundaries identified.*")
    return "\n".join(lines)


def generate_application_flows_md(
    bundle: ThreatModelInputBundle,
    ai_results: dict[str, Any] | None = None,
) -> str:
    """Generate application_flows.md — flow descriptions."""
    lines: list[str] = []
    lines.append("# Application Flows")
    lines.append("")
    flows = _get_application_flows(bundle, ai_results)
    for fid, src, sink, dtype, fdesc in flows:
        lines.append(f"## {fid}")
        lines.append("")
        lines.append(f"**Source**: {src}")
        lines.append("")
        lines.append(f"**Sink**: {sink}")
        lines.append("")
        if dtype:
            lines.append(f"**Data type**: {dtype}")
            lines.append("")
        if fdesc:
            lines.append(f"**Description**: {fdesc}")
            lines.append("")
    if not flows:
        lines.append("*No application flows inferred.*")
    return "\n".join(lines)


def generate_testing_priorities_md(
    artifact: ThreatModelArtifact,
) -> str:
    """Generate testing_priorities.md — roadmap from TestingRoadmapItem."""
    lines: list[str] = []
    lines.append("# Testing Priorities")
    lines.append("")
    lines.append("Prioritized testing roadmap derived from threat scenarios.")
    lines.append("")
    for i, item in enumerate(artifact.testing_roadmap, 1):
        prio = (
            item.priority.value
            if isinstance(item.priority, PriorityLevel)
            else str(item.priority)
        )
        lines.append(f"## {i}. {item.title}")
        lines.append("")
        lines.append(f"- **Scenario ID**: `{item.scenario_id}`")
        lines.append(f"- **Priority**: {prio}")
        if item.evidence_refs:
            lines.append(f"- **Evidence refs**: {', '.join(item.evidence_refs)}")
        lines.append("")
        lines.append("**Recommended actions:**")
        for a in item.recommended_actions:
            lines.append(f"- {a}")
        lines.append("")
    if not artifact.testing_roadmap:
        lines.append("*No roadmap items.*")
    return "\n".join(lines)


def generate_evidence_gaps_md(
    artifact: ThreatModelArtifact,
    ai_results: dict[str, Any] | None = None,
) -> str:
    """Generate evidence_gaps.md — unknowns from report_summary or derived from scenarios."""
    lines: list[str] = []
    lines.append("# Evidence Gaps and Unknowns")
    lines.append("")
    unknowns = _get_unknowns_from_ai_results(ai_results)
    if unknowns:
        lines.append("## From Report Summary")
        lines.append("")
        for u in unknowns:
            lines.append(f"- {u}")
        lines.append("")
    lines.append("## From Scenario Assumptions")
    lines.append("")
    for s in artifact.scenarios:
        if s.assumptions:
            lines.append(f"### Scenario: {s.title} (`{s.id}`)")
            for a in s.assumptions:
                lines.append(f"- {a}")
            lines.append("")
    lines.append("## Recommended Manual Validation")
    lines.append("")
    for s in artifact.scenarios:
        if s.recommended_next_manual_checks:
            lines.append(f"### Scenario: {s.title} (`{s.id}`)")
            for c in s.recommended_next_manual_checks:
                lines.append(f"- {c}")
            lines.append("")
    return "\n".join(lines)


# --- JSON generators ---


def _ai_trace_to_dict(t: AIReasoningTrace) -> dict[str, Any]:
    """Serialize AIReasoningTrace to JSON-serializable dict."""
    return {
        "step_id": t.step_id,
        "step_type": t.step_type,
        "description": t.description,
        "input_refs": list(t.input_refs),
        "output_refs": list(t.output_refs),
        "timestamp": _serialize_datetime(t.timestamp),
    }


def _mcp_trace_to_dict(t: MCPInvocationTrace) -> dict[str, Any]:
    """Serialize MCPInvocationTrace to JSON-serializable dict."""
    return {
        "invocation_id": t.invocation_id,
        "tool_name": t.tool_name,
        "input_summary": dict(t.input_summary),
        "output_summary": dict(t.output_summary),
        "timestamp": _serialize_datetime(t.timestamp),
    }


def generate_ai_reasoning_trace_json(
    artifact: ThreatModelArtifact,
    ai_traces: list[AIReasoningTrace] | None = None,
) -> str:
    """Generate ai_reasoning_traces.json — full AI task traces."""
    traces = ai_traces if ai_traces is not None else artifact.ai_reasoning_traces
    payload = {
        "run_id": artifact.run_id,
        "job_id": artifact.job_id,
        "traces": [_ai_trace_to_dict(t) for t in traces],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def generate_stage2_inputs_json(
    bundle: ThreatModelInputBundle,
    *,
    generated_at: str | None = None,
    engagement_id: str | None = None,
    target_id: str | None = None,
    job_id: str | None = None,
    run_id: str | None = None,
) -> str:
    """Generate stage2_inputs.json — traceability copy of input bundle with metadata.

    Returns JSON with metadata (generated_at, engagement_id, target_id, job_id, run_id)
    and full bundle dump for Stage 3 traceability.
    """
    now = datetime.now()
    payload: dict[str, Any] = {
        "metadata": {
            "generated_at": generated_at or now.isoformat(),
            "engagement_id": engagement_id if engagement_id is not None else bundle.engagement_id,
            "target_id": target_id if target_id is not None else bundle.target_id,
            "job_id": job_id,
            "run_id": run_id,
        },
        "bundle": bundle.model_dump(mode="json"),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def generate_threat_model_json(
    bundle: ThreatModelInputBundle,
    prior_outputs: dict[str, Any],
    run_id: str,
    job_id: str,
) -> str:
    """Generate threat_model.json — ThreatModelUnified JSON (TM2-003).

    Parses prior_outputs via stage2_parsers into Stage3 models and outputs
    unified threat model JSON. run_id/job_id included in metadata if needed.
    """
    critical_assets = parse_critical_assets_to_stage3(prior_outputs, bundle)
    trust_boundaries = parse_trust_boundaries_to_stage3(prior_outputs, bundle)
    entry_points = parse_entry_points_to_stage3(prior_outputs, bundle)
    threat_scenarios = parse_threat_scenarios_to_stage3(prior_outputs)

    profiles_data = prior_outputs.get("attacker_profiles", {}) or {}
    raw_profiles = (
        profiles_data.get("profiles")
        if isinstance(profiles_data, dict)
        else []
    ) or []
    attacker_profiles: list[AttackerProfile] = []
    for i, p in enumerate(raw_profiles):
        if not isinstance(p, dict):
            continue
        try:
            attacker_profiles.append(
                AttackerProfile(
                    id=str(p.get("id") or f"ap_{i}")[:100],
                    name=str(p.get("name") or "")[:200] or f"profile_{i}",
                    capability_level=str(p.get("capability_level") or "unknown")[:50],
                    description=(str(p.get("description"))[:2000] if p.get("description") else None),
                )
            )
        except Exception:
            pass
    if not attacker_profiles and bundle.attacker_profiles:
        attacker_profiles = list(bundle.attacker_profiles[:50])

    unified = ThreatModelUnified(
        critical_assets=critical_assets,
        trust_boundaries=trust_boundaries,
        entry_points=entry_points,
        attacker_profiles=attacker_profiles,
        threat_scenarios=threat_scenarios,
    )
    payload: dict[str, Any] = {
        "run_id": run_id,
        "job_id": job_id,
        **unified.model_dump(mode="json"),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def generate_priority_hypotheses_json(
    bundle: ThreatModelInputBundle,
    prior_outputs: dict[str, Any],
) -> str:
    """Generate ai_tm_priority_hypotheses.json — AiTmPriorityHypotheses JSON (TM2-004)."""
    hypotheses = parse_priority_hypotheses(bundle, prior_outputs)
    return json.dumps(
        hypotheses.model_dump(mode="json"),
        indent=2,
        ensure_ascii=False,
        default=str,
    )


def generate_application_flows_json(
    prior_outputs: dict[str, Any],
    bundle: ThreatModelInputBundle,
) -> str:
    """Generate ai_tm_application_flows.json — normalized Stage3ApplicationFlow list JSON (TM2-005)."""
    flows = parse_application_flows_to_stage3(prior_outputs, bundle)
    return json.dumps(
        [f.model_dump(mode="json") for f in flows],
        indent=2,
        ensure_ascii=False,
        default=str,
    )


def generate_mcp_trace_json(
    artifact: ThreatModelArtifact,
    mcp_traces: list[MCPInvocationTrace] | list[dict[str, Any]] | None = None,
) -> str:
    """Generate mcp_trace.json — MCP invocation traces."""
    if mcp_traces is not None:
        if mcp_traces and isinstance(mcp_traces[0], MCPInvocationTrace):
            payload = {
                "run_id": artifact.run_id,
                "job_id": artifact.job_id,
                "invocations": [_mcp_trace_to_dict(t) for t in mcp_traces],
            }
        else:
            payload = {
                "run_id": artifact.run_id,
                "job_id": artifact.job_id,
                "invocations": list(mcp_traces),
            }
    else:
        payload = {
            "run_id": artifact.run_id,
            "job_id": artifact.job_id,
            "invocations": [
                _mcp_trace_to_dict(t) for t in artifact.mcp_invocation_traces
            ],
        }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


# --- Orchestration ---


def generate_all_artifacts(
    bundle: ThreatModelInputBundle,
    artifact: ThreatModelArtifact,
    ai_results: dict[str, Any] | None = None,
    mcp_traces: list[MCPInvocationTrace] | list[dict[str, Any]] | None = None,
    prior_outputs: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Generate all artifact types including TM2-003/004/005. Returns dict mapping filename -> content."""
    result: dict[str, str] = {}
    result["stage2_inputs.json"] = generate_stage2_inputs_json(
        bundle,
        job_id=artifact.job_id,
        run_id=artifact.run_id,
    )
    result["threat_model.md"] = generate_threat_model_md(bundle, artifact, ai_results)
    result["critical_assets.csv"] = generate_critical_assets_csv(bundle, ai_results)
    result["entry_points.csv"] = generate_entry_points_csv(bundle, ai_results)
    result["attacker_profiles.csv"] = generate_attacker_profiles_csv(bundle, ai_results)
    result["trust_boundaries.csv"] = generate_trust_boundaries_csv(bundle, ai_results)
    result["trust_boundaries.md"] = generate_trust_boundaries_md(bundle, ai_results)
    result["application_flows.md"] = generate_application_flows_md(bundle, ai_results)
    result["threat_scenarios.csv"] = generate_threat_scenarios_csv(artifact)
    result["testing_priorities.md"] = generate_testing_priorities_md(artifact)
    result["evidence_gaps.md"] = generate_evidence_gaps_md(artifact, ai_results)
    result["ai_reasoning_traces.json"] = generate_ai_reasoning_trace_json(artifact)
    result["mcp_trace.json"] = generate_mcp_trace_json(artifact, mcp_traces)

    if prior_outputs is not None:
        result["threat_model.json"] = generate_threat_model_json(
            bundle, prior_outputs, artifact.run_id, artifact.job_id
        )
        result["ai_tm_priority_hypotheses.json"] = generate_priority_hypotheses_json(
            bundle, prior_outputs
        )
        result["ai_tm_application_flows.json"] = generate_application_flows_json(
            prior_outputs, bundle
        )

    return result
