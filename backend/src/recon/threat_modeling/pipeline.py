"""Threat modeling orchestration pipeline — TM-006.

Executes full threat model run: dependency check → load bundle → MCP enrichment →
9 AI tasks → persist traces → artifact generation → save to storage.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.prompts.threat_modeling_prompts import get_threat_modeling_prompt
from app.schemas.ai.common import PriorityLevel, ThreatModelingAiTask, build_tm_task_metadata
from app.schemas.threat_modeling.schemas import (
    AIReasoningTrace,
    MCPInvocationTrace,
    TestingRoadmapItem,
    ThreatModelArtifact,
    ThreatModelInputBundle,
    ThreatModelRun,
    ThreatScenario,
)
from pydantic import BaseModel

from src.core.llm_config import get_llm_client, has_any_llm_key
from src.recon.threat_modeling.ai_task_registry import (
    THREAT_MODELING_AI_TASKS,
    validate_threat_modeling_ai_payload,
)
from src.recon.threat_modeling.artifacts import generate_all_artifacts
from src.recon.threat_modeling.dependency_check import (
    BLOCKED_MISSING_RECON,
    check_stage1_readiness,
)
from src.recon.threat_modeling.input_loader import (
    load_threat_model_input_bundle,
    load_threat_model_input_bundle_from_artifacts,
)
from src.recon.stage2_storage import upload_stage2_artifacts
from src.recon.threat_modeling.mcp_enrichment import enrich_with_mcp

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Stage for threat model artifacts in recon storage
TM_STAGE = 18  # 18_reporting

# 11 artifacts: 9 normalized outputs + ai_reasoning_traces + mcp_trace
TM_ARTIFACT_FILENAMES: tuple[str, ...] = (
    *(f"ai_tm_{t}_normalized.json" for t in THREAT_MODELING_AI_TASKS),
    "ai_reasoning_traces.json",
    "mcp_trace.json",
)


class ThreatModelPipelineError(Exception):
    """Raised when pipeline is blocked or fails."""

    def __init__(self, message: str, blocking_reason: str | None = None) -> None:
        super().__init__(message)
        self.blocking_reason = blocking_reason


def _extract_json_from_llm_response(text: str) -> dict[str, Any] | None:
    """Extract JSON object from LLM response (may be wrapped in markdown)."""
    if not text or not text.strip():
        return None
    text = text.strip()
    # Try raw parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try to extract from ```json ... ``` block
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass
    # Try to find first { ... } block
    start = text.find("{")
    if start >= 0:
        depth = 0
        for i, c in enumerate(text[start:], start=start):
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
    return None


def _build_fallback_output(
    task_name: str,
    bundle: ThreatModelInputBundle,
    prior_outputs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build rule-based fallback output when LLM is unavailable."""
    hypothesis = {"statement_type": "hypothesis", "evidence_refs": []}

    if task_name == "critical_assets":
        assets = [
            {
                "id": f"ca_{i}",
                "name": a.name,
                "asset_type": a.asset_type,
                "description": a.description or "",
                **hypothesis,
            }
            for i, a in enumerate(bundle.critical_assets[:50])
        ]
        if not assets:
            assets = [
                {
                    "id": "ca_default",
                    "name": "Recon target",
                    "asset_type": "target",
                    "description": "Inferred from recon bundle",
                    **hypothesis,
                }
            ]
        return {"assets": assets}

    if task_name == "trust_boundaries":
        boundaries = [
            {
                "id": f"tb_{i}",
                "name": b.name,
                "description": b.description or "",
                "components": b.components or [],
                **hypothesis,
            }
            for i, b in enumerate(bundle.trust_boundaries[:50])
        ]
        if not boundaries:
            boundaries = [
                {
                    "id": "tb_default",
                    "name": "External boundary",
                    "description": "Inferred from recon",
                    "components": [],
                    **hypothesis,
                }
            ]
        return {"boundaries": boundaries}

    if task_name == "attacker_profiles":
        profiles = [
            {
                "id": f"ap_{i}",
                "name": p.name,
                "capability_level": p.capability_level,
                "description": p.description or "",
                **hypothesis,
            }
            for i, p in enumerate(bundle.attacker_profiles[:20])
        ]
        if not profiles:
            profiles = [
                {
                    "id": "ap_default",
                    "name": "External attacker",
                    "capability_level": "script_kiddie",
                    "description": "Assumed from recon context",
                    **hypothesis,
                }
            ]
        return {"profiles": profiles}

    if task_name == "entry_points":
        entry_points = [
            {
                "id": f"ep_{i}",
                "name": e.name,
                "entry_type": e.entry_type,
                "host_or_component": e.host_or_component,
                "description": e.description or "",
                **hypothesis,
            }
            for i, e in enumerate(bundle.entry_points[:100])
        ]
        if not entry_points and bundle.endpoint_inventory:
            for i, row in enumerate(bundle.endpoint_inventory[:50]):
                url = row.get("url") or row.get("path") or str(i)
                entry_points.append(
                    {
                        "id": f"ep_{i}",
                        "name": url[:200],
                        "entry_type": "endpoint",
                        "host_or_component": url[:500],
                        "description": "From endpoint inventory",
                        **hypothesis,
                    }
                )
        if not entry_points:
            entry_points = [
                {
                    "id": "ep_default",
                    "name": "API surface",
                    "entry_type": "api",
                    "host_or_component": None,
                    "description": "Inferred from recon",
                    **hypothesis,
                }
            ]
        return {"entry_points": entry_points}

    if task_name == "application_flows":
        flows = []
        if bundle.api_surface:
            for i, row in enumerate(bundle.api_surface[:30]):
                src = row.get("source") or "client"
                sink = row.get("sink") or row.get("path") or "server"
                flows.append(
                    {
                        "id": f"flow_{i}",
                        "source": str(src)[:500],
                        "sink": str(sink)[:500],
                        "data_type": "request",
                        "description": "From API surface",
                        **hypothesis,
                    }
                )
        if not flows:
            flows = [
                {
                    "id": "flow_default",
                    "source": "external",
                    "sink": "target",
                    "data_type": "request",
                    "description": "Inferred from recon",
                    **hypothesis,
                }
            ]
        return {"flows": flows}

    if task_name == "threat_scenarios":
        assets_out = prior_outputs.get("critical_assets", {}).get("assets", [])
        boundaries_out = prior_outputs.get("trust_boundaries", {}).get("boundaries", [])
        profiles_out = prior_outputs.get("attacker_profiles", {}).get("profiles", [])
        entry_points_out = prior_outputs.get("entry_points", {}).get("entry_points", [])

        scenarios = []
        for i, ep in enumerate(entry_points_out[:10]):
            scenarios.append(
                {
                    "id": f"ts_{i}",
                    "title": f"Threat via {ep.get('name', 'entry')[:100]}",
                    "related_assets": [a.get("id", "") for a in assets_out[:3]],
                    "host_component": ep.get("host_or_component"),
                    "entry_point": ep.get("id"),
                    "attacker_profile": profiles_out[0].get("id") if profiles_out else None,
                    "trust_boundary": boundaries_out[0].get("id") if boundaries_out else None,
                    "description": "Inferred from recon and prior analysis",
                    "likelihood": 0.5,
                    "impact": 0.5,
                    "priority": "medium",
                    "assumptions": ["LLM fallback mode"],
                    "recommended_next_manual_checks": ["Verify with manual testing"],
                    **hypothesis,
                }
            )
        if not scenarios:
            scenarios = [
                {
                    "id": "ts_default",
                    "title": "Generic reconnaissance threat",
                    "related_assets": [],
                    "host_component": None,
                    "entry_point": None,
                    "attacker_profile": None,
                    "trust_boundary": None,
                    "description": "Fallback scenario when LLM unavailable",
                    "likelihood": 0.5,
                    "impact": 0.5,
                    "priority": "medium",
                    "assumptions": ["LLM fallback mode"],
                    "recommended_next_manual_checks": ["Run full TM with LLM"],
                    **hypothesis,
                }
            ]
        return {"scenarios": scenarios}

    if task_name == "scenario_scoring":
        scenarios_out = prior_outputs.get("threat_scenarios", {}).get("scenarios", [])
        scores = [
            {
                "scenario_id": s.get("id", f"ts_{i}"),
                "likelihood": s.get("likelihood", 0.5),
                "impact": s.get("impact", 0.5),
                "risk_score": s.get("likelihood", 0.5) * s.get("impact", 0.5),
                **hypothesis,
            }
            for i, s in enumerate(scenarios_out)
        ]
        return {"scores": scores}

    if task_name == "testing_roadmap":
        scenarios_out = prior_outputs.get("threat_scenarios", {}).get("scenarios", [])
        scores_out = prior_outputs.get("scenario_scoring", {}).get("scores", [])
        score_by_id = {s.get("scenario_id"): s for s in scores_out}

        items = []
        for s in scenarios_out[:20]:
            sid = s.get("id", "")
            sc = score_by_id.get(sid, {})
            risk = sc.get("risk_score", 0.5)
            priority = "high" if risk >= 0.7 else "medium" if risk >= 0.4 else "low"
            items.append(
                {
                    "scenario_id": sid,
                    "title": s.get("title", "Scenario")[:500],
                    "priority": priority,
                    "recommended_actions": s.get("recommended_next_manual_checks", ["Manual verification"]),
                    **hypothesis,
                }
            )
        if not items:
            items = [
                {
                    "scenario_id": "ts_default",
                    "title": "Run full threat model with LLM",
                    "priority": "high",
                    "recommended_actions": ["Configure LLM and re-run pipeline"],
                    **hypothesis,
                }
            ]
        return {"items": items}

    if task_name == "report_summary":
        summary = (
            "Threat model generated in fallback mode (no LLM). "
            "Critical assets and scenarios were inferred from recon bundle. "
            "Configure an LLM provider for full AI-powered analysis."
        )
        return {"executive_summary": summary}

    return {}


def _build_task_input(
    task_name: str,
    bundle: ThreatModelInputBundle,
    prior_outputs: dict[str, dict[str, Any]],
    run_id: str,
    job_id: str,
) -> dict[str, Any]:
    """Build input payload for an AI task."""
    task_enum = ThreatModelingAiTask(task_name)
    meta = build_tm_task_metadata(task_enum, run_id, job_id)

    if task_name == "critical_assets":
        return {"meta": meta.model_dump(), "bundle": bundle.model_dump(mode="json")}

    if task_name == "trust_boundaries":
        return {"meta": meta.model_dump(), "bundle": bundle.model_dump(mode="json")}

    if task_name == "attacker_profiles":
        return {"meta": meta.model_dump(), "bundle": bundle.model_dump(mode="json")}

    if task_name == "entry_points":
        return {"meta": meta.model_dump(), "bundle": bundle.model_dump(mode="json")}

    if task_name == "application_flows":
        return {"meta": meta.model_dump(), "bundle": bundle.model_dump(mode="json")}

    if task_name == "threat_scenarios":
        assets = prior_outputs.get("critical_assets", {}).get("assets", [])
        boundaries = prior_outputs.get("trust_boundaries", {}).get("boundaries", [])
        profiles = prior_outputs.get("attacker_profiles", {}).get("profiles", [])
        entry_points = prior_outputs.get("entry_points", {}).get("entry_points", [])
        flows = prior_outputs.get("application_flows", {}).get("flows", [])

        def to_asset(a: dict) -> dict:
            return {"id": a["id"], "name": a["name"], "asset_type": a["asset_type"], "description": a.get("description")}

        def to_boundary(b: dict) -> dict:
            return {"id": b["id"], "name": b["name"], "description": b.get("description"), "components": b.get("components", [])}

        def to_profile(p: dict) -> dict:
            return {"id": p["id"], "name": p["name"], "capability_level": p["capability_level"], "description": p.get("description")}

        def to_entry(e: dict) -> dict:
            return {
                "id": e["id"],
                "name": e["name"],
                "entry_type": e["entry_type"],
                "host_or_component": e.get("host_or_component"),
                "description": e.get("description"),
            }

        def to_flow(f: dict) -> dict:
            return {
                "id": f["id"],
                "source": f["source"],
                "sink": f["sink"],
                "data_type": f.get("data_type"),
                "description": f.get("description"),
            }

        return {
            "meta": meta.model_dump(),
            "bundle": bundle.model_dump(mode="json"),
            "assets": [to_asset(a) for a in assets],
            "boundaries": [to_boundary(b) for b in boundaries],
            "profiles": [to_profile(p) for p in profiles],
            "entry_points": [to_entry(e) for e in entry_points],
            "flows": [to_flow(f) for f in flows],
        }

    if task_name == "scenario_scoring":
        scenarios = prior_outputs.get("threat_scenarios", {}).get("scenarios", [])
        return {"meta": meta.model_dump(), "scenarios": scenarios}

    if task_name == "testing_roadmap":
        scenarios = prior_outputs.get("threat_scenarios", {}).get("scenarios", [])
        scores = prior_outputs.get("scenario_scoring", {}).get("scores", [])
        return {"meta": meta.model_dump(), "scenarios": scenarios, "scores": scores}

    if task_name == "report_summary":
        full_model = {k: v for k, v in prior_outputs.items() if not k.startswith("_")}
        return {"meta": meta.model_dump(), "full_model": full_model}

    return {"meta": meta.model_dump()}


def _run_ai_task(
    task_name: str,
    bundle: ThreatModelInputBundle,
    prior_outputs: dict[str, dict[str, Any]],
    run_id: str,
    job_id: str,
    call_llm: Callable[[str, dict], str] | None,
    use_fallback_on_llm_error: bool = True,
) -> tuple[dict[str, Any], str | None]:
    """Execute single AI task. Returns (output_dict, error_message)."""
    prior_outputs["_run_id"] = run_id
    prior_outputs["_job_id"] = job_id
    prior_outputs["_trace_id"] = f"{run_id}:{job_id}:{task_name}"

    input_payload = _build_task_input(task_name, bundle, prior_outputs, run_id, job_id)
    prompt_template = get_threat_modeling_prompt(task_name)

    # Build prompt with bundle context
    bundle_json = json.dumps(bundle.model_dump(mode="json"), indent=2, ensure_ascii=False)[:15000]
    if task_name == "report_summary":
        full_model_json = json.dumps(input_payload.get("full_model", {}), indent=2, ensure_ascii=False)[:20000]
        prompt = f"{prompt_template}\n\nFull model data:\n{full_model_json}\n\nOutput valid JSON only."
    else:
        prompt = f"{prompt_template}\n\nRecon bundle (excerpt):\n{bundle_json}\n\nOutput valid JSON only."

    if call_llm:
        try:
            raw = call_llm(prompt, {"task": task_name})
            parsed = _extract_json_from_llm_response(raw)
            if parsed:
                validation = validate_threat_modeling_ai_payload(task_name, input_payload, parsed)
                if validation["output"]["is_valid"]:
                    return (parsed, None)
                if use_fallback_on_llm_error:
                    logger.warning(
                        "LLM output validation failed, using fallback",
                        extra={"task": task_name, "errors": validation["output"]["errors"]},
                    )
            elif use_fallback_on_llm_error:
                logger.warning("LLM returned invalid JSON, using fallback", extra={"task": task_name})
        except Exception as e:
            logger.warning(
                "LLM call failed",
                extra={"task": task_name, "error_type": type(e).__name__},
            )
            if use_fallback_on_llm_error:
                pass
            else:
                return ({}, str(e))

    # Fallback
    output = _build_fallback_output(task_name, bundle, prior_outputs)
    return (output, None)


def _save_artifact_file(recon_dir: Path, filename: str, data: bytes) -> None:
    """Write artifact to recon_dir."""
    path = recon_dir / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _traces_to_json(traces: list[BaseModel]) -> bytes:
    """Serialize trace list to JSON bytes."""
    return json.dumps(
        [t.model_dump(mode="json") for t in traces],
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")


def _dict_to_obj(d: dict[str, Any]) -> Any:
    """Convert dict to object with attribute access for artifact ai_results compatibility."""

    class _Obj:
        def __init__(self, data: dict[str, Any]) -> None:
            for k, v in data.items():
                if isinstance(v, dict):
                    setattr(self, k, _dict_to_obj(v))
                elif isinstance(v, list):
                    setattr(
                        self,
                        k,
                        [_dict_to_obj(x) if isinstance(x, dict) else x for x in v],
                    )
                else:
                    setattr(self, k, v)

    return _Obj(d)


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


def _build_threat_model_artifact(
    run_id: str,
    job_id: str,
    prior_outputs: dict[str, dict[str, Any]],
    ai_reasoning_traces: list[AIReasoningTrace],
    mcp_traces: list[MCPInvocationTrace],
) -> ThreatModelArtifact:
    """Build ThreatModelArtifact from prior_outputs for artifact generation."""
    scenarios: list[ThreatScenario] = []
    for s in prior_outputs.get("threat_scenarios", {}).get("scenarios", []):
        try:
            priority = _parse_priority(s.get("priority", "medium"))
            scenarios.append(
                ThreatScenario(
                    id=str(s.get("id", "")) or "unknown",
                    title=str(s.get("title", "")) or "Untitled",
                    related_assets=list(s.get("related_assets") or []),
                    host_component=s.get("host_component"),
                    entry_point=s.get("entry_point"),
                    attacker_profile=s.get("attacker_profile"),
                    trust_boundary=s.get("trust_boundary"),
                    description=str(s.get("description", "")) or "No description",
                    likelihood=float(s.get("likelihood", 0.5)),
                    impact=float(s.get("impact", 0.5)),
                    priority=priority,
                    recon_evidence_refs=[],
                    assumptions=list(s.get("assumptions") or []),
                    recommended_next_manual_checks=list(
                        s.get("recommended_next_manual_checks") or []
                    ),
                )
            )
        except (ValueError, TypeError, KeyError):
            logger.debug("Skipping invalid scenario", extra={"raw": s})
            continue

    roadmap: list[TestingRoadmapItem] = []
    for item in prior_outputs.get("testing_roadmap", {}).get("items", []):
        try:
            priority = _parse_priority(item.get("priority", "medium"))
            roadmap.append(
                TestingRoadmapItem(
                    scenario_id=str(item.get("scenario_id", "")) or "unknown",
                    title=str(item.get("title", "")) or "Untitled",
                    priority=priority,
                    evidence_refs=[],
                    recommended_actions=list(item.get("recommended_actions") or []),
                )
            )
        except (ValueError, TypeError, KeyError):
            logger.debug("Skipping invalid roadmap item", extra={"raw": item})
            continue

    return ThreatModelArtifact(
        run_id=run_id,
        job_id=job_id,
        scenarios=scenarios,
        testing_roadmap=roadmap,
        ai_reasoning_traces=ai_reasoning_traces,
        mcp_invocation_traces=mcp_traces,
    )


async def execute_threat_modeling_run(
    engagement_id: str,
    run_id: str,
    job_id: str,
    *,
    target_id: str | None = None,
    recon_dir: Path | str | None = None,
    artifacts_base: Path | str | None = None,
    db: AsyncSession | None = None,
    existing_run_id: str | None = None,
    llm_callable: Callable[[str, dict], str] | None = None,
    mcp_tools: list[str] | None = None,
    use_llm_fallback: bool = True,
) -> ThreatModelRun:
    """Execute full threat modeling pipeline.

    Flow:
    1. Dependency check (TM-001) — fail fast if blocked
    2. Load input bundle (TM-003)
    3. MCP enrichment (TM-004) — optional
    4. Execute 9 AI tasks in order
    5. Persist AI reasoning traces
    6. Persist MCP trace
    7. Generate and save 11 artifacts
    8. Update ThreatModelRun status

    Args:
        engagement_id: Engagement ID.
        run_id: Run identifier.
        job_id: Job identifier.
        target_id: Optional target ID for DB path.
        recon_dir: Path to recon directory (file-based). When None, uses DB.
        artifacts_base: Optional base path for artifacts/stage2/{job_id}/ layout (TM2-009).
                       When provided with recon_dir, writes to artifacts_base/stage2/{job_id}/.
                       When omitted, writes to recon_dir.
        db: AsyncSession for DB operations. Required for DB path.
        llm_callable: Optional LLM callable for testing. If None, uses get_llm_client when keys present.
        mcp_tools: MCP tools for enrichment (e.g. ["fetch", "read_file"]). Empty/None skips.
        use_llm_fallback: When True, use rule-based fallback if LLM unavailable.

    Returns:
        ThreatModelRun with status and artifact_refs.

    Raises:
        ThreatModelPipelineError: When blocked by dependency check or critical failure.
    """
    started_at = datetime.now(UTC)
    input_bundle_ref = f"engagement:{engagement_id}:run:{run_id}:job:{job_id}"
    artifact_refs: list[str] = []

    # Resolve LLM
    call_llm: Callable[[str, dict], str] | None = llm_callable
    if call_llm is None and has_any_llm_key():
        try:
            call_llm = get_llm_client()
        except Exception as e:
            logger.warning("LLM client init failed", extra={"error_type": type(e).__name__})
            if not use_llm_fallback:
                raise ThreatModelPipelineError(
                    "LLM required but not configured. Set API key or use_llm_fallback=True.",
                    blocking_reason="llm_unavailable",
                ) from e

    if call_llm is None and not use_llm_fallback:
        raise ThreatModelPipelineError(
            "No LLM configured and use_llm_fallback=False.",
            blocking_reason="llm_unavailable",
        )

    # 1. Dependency check
    readiness = await check_stage1_readiness(
        engagement_id,
        target_id=target_id,
        recon_dir=Path(recon_dir) if recon_dir else None,
        db=db,
    )
    if not readiness.ready:
        reason = readiness.blocking_reason or BLOCKED_MISSING_RECON
        raise ThreatModelPipelineError(
            f"Stage 1 not ready: {reason}. Missing: {readiness.missing_artifacts}",
            blocking_reason=reason,
        )

    # Create or reuse ThreatModelRun DB record at start (when db provided)
    run_record = None
    if db is not None:
        from sqlalchemy import select

        from src.db.models_recon import Engagement
        from src.db.models_recon import ThreatModelRun as ThreatModelRunModel

        result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
        engagement = result.scalar_one_or_none()
        if not engagement:
            raise ThreatModelPipelineError(
                f"Engagement {engagement_id} not found",
                blocking_reason="engagement_not_found",
            )
        if existing_run_id:
            run_result = await db.execute(
                select(ThreatModelRunModel).where(
                    ThreatModelRunModel.id == existing_run_id,
                    ThreatModelRunModel.engagement_id == engagement_id,
                )
            )
            run_record = run_result.scalar_one_or_none()
            if run_record:
                run_record.status = "running"
                run_record.started_at = started_at
                run_record.completed_at = None
                await db.flush()
        if run_record is None:
            run_record = ThreatModelRunModel(
                tenant_id=engagement.tenant_id,
                engagement_id=engagement_id,
                target_id=target_id,
                status="running",
                started_at=started_at,
                completed_at=None,
                input_bundle_ref=input_bundle_ref,
                artifact_refs=[],
                job_id=job_id,
                run_id=run_id,
            )
            db.add(run_record)
            await db.flush()

    try:
        # 2. Load bundle
        if recon_dir is not None:
            base = Path(recon_dir)
            bundle = load_threat_model_input_bundle(base, engagement_id, target_id)
            # TM2-009: resolve artifacts dir — artifacts_base/stage2/{job_id}/ or base
            if artifacts_base is not None:
                artifacts_base_path = Path(artifacts_base)
                save_to_dir = artifacts_base_path / "stage2" / job_id
                save_to_dir.mkdir(parents=True, exist_ok=True)
            else:
                save_to_dir = base
        elif db is not None:
            bundle = await load_threat_model_input_bundle_from_artifacts(db, engagement_id, target_id)
            save_to_dir = None
        else:
            raise ThreatModelPipelineError(
                "Either recon_dir or db must be provided.",
                blocking_reason=BLOCKED_MISSING_RECON,
            )

        # 3. MCP enrichment (optional)
        mcp_tools_list = mcp_tools or []
        mcp_traces: list[MCPInvocationTrace] = []
        if mcp_tools_list and save_to_dir:
            mcp_traces = enrich_with_mcp(
                bundle,
                mcp_tools_list,
                run_id,
                job_id,
                recon_dir=save_to_dir,
            )

        # 4. Execute 9 AI tasks
        prior_outputs: dict[str, dict[str, Any]] = {}
        ai_reasoning_traces: list[AIReasoningTrace] = []

        for task_name in THREAT_MODELING_AI_TASKS:
            output, err = _run_ai_task(
                task_name,
                bundle,
                prior_outputs,
                run_id,
                job_id,
                call_llm,
                use_fallback_on_llm_error=use_llm_fallback,
            )
            if err and not use_llm_fallback:
                logger.error(
                    "AI task failed",
                    extra={"task": task_name, "error": err},
                )
                raise ThreatModelPipelineError(
                    "AI task failed",
                    blocking_reason="ai_task_failed",
                ) from None

            prior_outputs[task_name] = output

            ai_reasoning_traces.append(
                AIReasoningTrace(
                    step_id=f"{run_id}:{job_id}:{task_name}",
                    step_type="ai_task",
                    description=f"Executed {task_name}",
                    input_refs=[f"bundle:{engagement_id}"],
                    output_refs=[f"ai_tm_{task_name}_normalized.json"],
                    timestamp=datetime.now(UTC),
                )
            )

        # 5–6. Persist traces (in-memory, written with artifacts)
        # 7–8. Save artifacts
        def _persist_artifact(filename: str, content: bytes) -> None:
            if filename not in artifact_refs:
                artifact_refs.append(filename)
            if save_to_dir:
                _save_artifact_file(save_to_dir, filename, content)

        for task_name in THREAT_MODELING_AI_TASKS:
            out = prior_outputs.get(task_name, {})
            data = json.dumps(out, indent=2, ensure_ascii=False).encode("utf-8")
            _persist_artifact(f"ai_tm_{task_name}_normalized.json", data)

        mcp_trace_data = _traces_to_json(mcp_traces)
        _persist_artifact("mcp_trace.json", mcp_trace_data)

        # 9. Generate and persist report artifacts via generate_all_artifacts
        tm_artifact = _build_threat_model_artifact(
            run_id, job_id, prior_outputs, ai_reasoning_traces, mcp_traces
        )
        ai_results = {
            k: _dict_to_obj(v) if isinstance(v, dict) else v
            for k, v in prior_outputs.items()
            if not k.startswith("_")
        }
        generated = generate_all_artifacts(
            bundle,
            tm_artifact,
            ai_results=ai_results,
            mcp_traces=mcp_traces,
            prior_outputs=prior_outputs,
        )
        for filename, content in generated.items():
            data = content.encode("utf-8")
            _persist_artifact(filename, data)

        # TM2-008: upload Stage 2 artifacts to MinIO when available on disk
        if save_to_dir:
            upload_stage2_artifacts(
                artifacts_dir=save_to_dir,
                scan_id=job_id,
                run_id=run_id,
                job_id=job_id,
            )

        # DB path: upload to storage via artifact_service
        if db is not None and not save_to_dir:
            from sqlalchemy import select

            from src.db.models_recon import Engagement
            from src.recon.services.artifact_service import create_artifact

            result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
            engagement = result.scalar_one_or_none()
            if not engagement:
                raise ThreatModelPipelineError(
                    f"Engagement {engagement_id} not found",
                    blocking_reason="engagement_not_found",
                )

            tenant_id = engagement.tenant_id
            j_id = job_id

            for task_name in THREAT_MODELING_AI_TASKS:
                out = prior_outputs.get(task_name, {})
                data = json.dumps(out, indent=2, ensure_ascii=False).encode("utf-8")
                await create_artifact(
                    db,
                    tenant_id=tenant_id,
                    engagement_id=engagement_id,
                    target_id=target_id,
                    job_id=j_id,
                    stage=TM_STAGE,
                    filename=f"ai_tm_{task_name}_normalized.json",
                    data=data,
                    content_type="application/json",
                    artifact_type="threat_model",
                )

            await create_artifact(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                target_id=target_id,
                job_id=j_id,
                stage=TM_STAGE,
                filename="mcp_trace.json",
                data=mcp_trace_data,
                content_type="application/json",
                artifact_type="threat_model",
            )

            for filename, content in generated.items():
                data = content.encode("utf-8")
                content_type = (
                    "text/markdown"
                    if filename.endswith(".md")
                    else "text/csv"
                    if filename.endswith(".csv")
                    else "application/json"
                )
                await create_artifact(
                    db,
                    tenant_id=tenant_id,
                    engagement_id=engagement_id,
                    target_id=target_id,
                    job_id=j_id,
                    stage=TM_STAGE,
                    filename=filename,
                    data=data,
                    content_type=content_type,
                    artifact_type="threat_model",
                )

        completed_at = datetime.now(UTC)

        # 9. Update ThreatModelRun record on completion
        if run_record is not None:
            run_record.status = "completed"
            run_record.completed_at = completed_at
            run_record.artifact_refs = artifact_refs
            await db.flush()

        return ThreatModelRun(
            engagement_id=engagement_id,
            target_id=target_id,
            status="completed",
            started_at=started_at,
            completed_at=completed_at,
            input_bundle_ref=input_bundle_ref,
            artifact_refs=artifact_refs,
            job_id=job_id,
            run_id=run_id,
        )
    except Exception:
        if run_record is not None and db is not None:
            run_record.status = "failed"
            run_record.completed_at = datetime.now(UTC)
            await db.flush()
        raise
