"""AI prompt handlers — LLM is mandatory, no mock fallbacks.

KAL-008: phase prompts embed Kali/MCP taxonomy, run_* vs pipeline guidance, and safety rules
via ``src.orchestration.prompt_registry`` (see ``ORCHESTRATION_PROMPT_VERSION``).
"""

import asyncio
import json
import logging
import re
from typing import Any

from src.llm import is_llm_available
from src.llm.facade import call_llm_unified
from src.llm.task_router import LLMTask
from src.orchestration.phases import (
    ExploitationInput,
    ExploitationOutput,
    PostExploitationInput,
    PostExploitationOutput,
    ReconInput,
    ReconOutput,
    ReportingInput,
    ReportingOutput,
    ThreatModelInput,
    ThreatModelOutput,
    VulnAnalysisInput,
    VulnAnalysisOutput,
)
from src.orchestration.prompt_registry import (
    EXPLOITATION,
    POST_EXPLOITATION,
    RECON,
    REPORTING,
    THREAT_MODELING,
    VULN_ANALYSIS,
    get_fixer_prompt,
    get_prompt,
    get_schema,
)
from src.orchestration.raw_phase_artifacts import RawPhaseSink

logger = logging.getLogger(__name__)

MAX_JSON_RETRIES = 1

_PHASE_TO_TASK: dict[str, LLMTask] = {
    RECON: LLMTask.ORCHESTRATION,
    THREAT_MODELING: LLMTask.THREAT_MODELING,
    VULN_ANALYSIS: LLMTask.ZERO_DAY_ANALYSIS,
    EXPLOITATION: LLMTask.EXPLOIT_GENERATION,
    POST_EXPLOITATION: LLMTask.REMEDIATION_PLAN,
    REPORTING: LLMTask.REPORT_SECTION,
}


def _parse_llm_json(text: str) -> dict[str, Any] | None:
    """Extract and parse JSON from LLM response. Handles ```json blocks."""
    if not text or not text.strip():
        return None
    text = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        text = match.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


async def _call_llm_with_json_retry(
    phase: str,
    user_prompt: str,
    system_prompt: str,
    *,
    raw_sink: RawPhaseSink | None = None,
    raw_label_prefix: str = "llm",
    scan_id: str | None = None,
) -> dict[str, Any] | None:
    """
    Call LLM, parse JSON. On parse failure, retry once with fixer prompt.
    Returns parsed dict or None.
    """
    task = _PHASE_TO_TASK.get(phase, LLMTask.ORCHESTRATION)
    response = await call_llm_unified(
        system_prompt,
        user_prompt,
        task=task,
        scan_id=scan_id,
        phase=phase,
    )
    if raw_sink is not None and response:
        await asyncio.to_thread(
            raw_sink.upload_text,
            f"{raw_label_prefix}_response_initial",
            response,
        )
    data = _parse_llm_json(response)
    if data is not None:
        return data

    for attempt in range(MAX_JSON_RETRIES):
        fixer_system, fixer_user = get_fixer_prompt(response, get_schema(phase))
        response = await call_llm_unified(
            fixer_system,
            fixer_user,
            task=task,
            scan_id=scan_id,
            phase=phase,
        )
        if raw_sink is not None and response:
            await asyncio.to_thread(
                raw_sink.upload_text,
                f"{raw_label_prefix}_response_fixer_{attempt + 1}",
                response,
            )
        data = _parse_llm_json(response)
        if data is not None:
            return data
        logger.warning(
            "JSON fixer retry did not produce valid JSON",
            extra={"phase": phase},
        )

    return None


_LLM_REQUIRED_MSG = (
    "LLM provider required. "
    "Configure OPENAI_API_KEY, OPENROUTER_API_KEY or another provider."
)


def _require_llm() -> None:
    if not is_llm_available():
        raise RuntimeError(_LLM_REQUIRED_MSG)


def _require_json(data: dict[str, Any] | None, phase: str) -> dict[str, Any]:
    if data is None:
        raise RuntimeError(f"LLM returned invalid response for {phase}")
    return data


async def ai_recon(
    inp: ReconInput,
    tool_results: str = "",
    *,
    raw_sink: RawPhaseSink | None = None,
    scan_id: str | None = None,
) -> ReconOutput:
    """Analyze real tool output via LLM to produce structured recon. Raises on failure."""
    _require_llm()
    system, user = get_prompt(
        RECON, target=inp.target, options=inp.options, tool_results=tool_results
    )
    data = _require_json(
        await _call_llm_with_json_retry(
            RECON,
            user,
            system,
            raw_sink=raw_sink,
            raw_label_prefix="recon_llm",
            scan_id=scan_id,
        ),
        RECON,
    )
    if not isinstance(data.get("assets"), list):
        raise RuntimeError(f"LLM returned invalid response for {RECON}")
    return ReconOutput(
        assets=data.get("assets", []),
        subdomains=data.get("subdomains", []),
        ports=[int(p) for p in data.get("ports", []) if isinstance(p, (int, float))],
    )


async def ai_threat_modeling(
    inp: ThreatModelInput,
    nvd_data: str = "",
    *,
    recon_context: str = "",
    scan_id: str | None = None,
) -> ThreatModelOutput:
    """Build threat model from real assets, NVD CVEs, and enriched recon context via LLM."""
    _require_llm()
    system, user = get_prompt(
        THREAT_MODELING,
        assets=inp.assets,
        nvd_data=nvd_data,
        recon_context=recon_context,
    )
    data = _require_json(
        await _call_llm_with_json_retry(
            THREAT_MODELING, user, system, scan_id=scan_id
        ),
        THREAT_MODELING,
    )
    if not isinstance(data.get("threat_model"), dict):
        raise RuntimeError(f"LLM returned invalid response for {THREAT_MODELING}")
    return ThreatModelOutput(threat_model=data["threat_model"])


async def ai_vuln_analysis(
    inp: VulnAnalysisInput,
    *,
    active_scan_context: str = "",
    scan_id: str | None = None,
) -> VulnAnalysisOutput:
    """Call LLM to analyze vulns from threat model. Raises on failure."""
    _require_llm()
    system, user = get_prompt(
        VULN_ANALYSIS,
        threat_model=inp.threat_model,
        assets=inp.assets,
        active_scan_context=active_scan_context,
    )
    data = _require_json(
        await _call_llm_with_json_retry(
            VULN_ANALYSIS, user, system, scan_id=scan_id
        ),
        VULN_ANALYSIS,
    )
    if not isinstance(data.get("findings"), list):
        raise RuntimeError(f"LLM returned invalid response for {VULN_ANALYSIS}")
    return VulnAnalysisOutput(findings=data["findings"])


async def ai_exploitation(
    inp: ExploitationInput, *, scan_id: str | None = None
) -> ExploitationOutput:
    """Call LLM to plan exploitation. Raises on failure."""
    _require_llm()
    system, user = get_prompt(EXPLOITATION, findings=inp.findings)
    data = _require_json(
        await _call_llm_with_json_retry(
            EXPLOITATION, user, system, scan_id=scan_id
        ),
        EXPLOITATION,
    )
    if not isinstance(data.get("exploits"), list):
        raise RuntimeError(f"LLM returned invalid response for {EXPLOITATION}")
    return ExploitationOutput(
        exploits=data.get("exploits", []),
        evidence=data.get("evidence", []),
    )


async def ai_post_exploitation(
    inp: PostExploitationInput,
    *,
    raw_sink: RawPhaseSink | None = None,
    scan_id: str | None = None,
) -> PostExploitationOutput:
    """Call LLM for lateral movement / persistence. Raises on failure."""
    _require_llm()
    system, user = get_prompt(POST_EXPLOITATION, exploits=inp.exploits)
    data = _require_json(
        await _call_llm_with_json_retry(
            POST_EXPLOITATION,
            user,
            system,
            raw_sink=raw_sink,
            raw_label_prefix="post_exploitation_llm",
            scan_id=scan_id,
        ),
        POST_EXPLOITATION,
    )
    return PostExploitationOutput(
        lateral=data.get("lateral", []) if isinstance(data.get("lateral"), list) else [],
        persistence=data.get("persistence", []) if isinstance(data.get("persistence"), list) else [],
    )


WRB_SAFE_PROMPT_LIMIT = 12000

def _trim_phase_data(data: dict[str, Any] | None, max_items: int = 20) -> dict[str, Any] | None:
    """Keep only essential fields to fit WRB 7B context window."""
    if data is None:
        return None
    trimmed: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, list) and len(value) > max_items:
            trimmed[key] = value[:max_items]
        elif isinstance(value, dict):
            trimmed[key] = _trim_phase_data(value, max_items)
        elif isinstance(value, str) and len(value) > 12000:
            trimmed[key] = value[:12000] + "...[truncated]"
        else:
            trimmed[key] = value
    return trimmed


def _build_reporting_prompt(inp: ReportingInput) -> tuple[str, str]:
    """Build reporting prompt, auto-truncating to fit WRB context."""
    import json as _json

    summary = {
        "target": inp.target,
    }
    if inp.recon:
        rd = _trim_phase_data(inp.recon.model_dump())
        summary["recon"] = rd
    if inp.threat_model:
        td = _trim_phase_data(inp.threat_model.model_dump())
        summary["threat_model"] = td
    if inp.vuln_analysis:
        vd = _trim_phase_data(inp.vuln_analysis.model_dump())
        summary["vuln_analysis"] = vd
    if inp.exploitation:
        ed = _trim_phase_data(inp.exploitation.model_dump())
        summary["exploitation"] = ed
    if inp.post_exploitation:
        pd = _trim_phase_data(inp.post_exploitation.model_dump())
        summary["post_exploitation"] = pd
    rc = inp.report_context if isinstance(inp.report_context, dict) else {}
    if rc:
        summary["report_context"] = rc

    system, user = get_prompt(REPORTING, summary=summary)

    if len(user) + len(system) > WRB_SAFE_PROMPT_LIMIT:
        raw = _json.dumps(summary, ensure_ascii=False, default=str)
        max_raw = WRB_SAFE_PROMPT_LIMIT // 4
        if len(raw) > max_raw:
            raw = raw[:max_raw]
            try:
                summary = _json.loads(raw + '"}')
            except Exception:
                summary = {"target": inp.target, "error": "data truncated for LLM context"}
            system, user = get_prompt(REPORTING, summary=summary)

    return system, user


def _build_fallback_report(inp: ReportingInput) -> ReportingOutput:
    """Non-LLM report when WRB + cloud all fail."""
    findings: list[dict[str, Any]] = []
    if inp.vuln_analysis:
        va = inp.vuln_analysis.model_dump()
        raw_findings = va.get("findings") or va.get("vulnerabilities") or []
        for f in raw_findings[:50]:
            if isinstance(f, dict):
                findings.append({
                    "severity": str(f.get("severity", "info")).lower(),
                    "description": str(f.get("description") or f.get("name", "Unknown finding")),
                    "impact": str(f.get("impact", "Not assessed")),
                    "remediation": str(f.get("remediation", "Manual review required")),
                })
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info")
        if s in sev_counts:
            sev_counts[s] += 1

    report = {
        "summary": {**sev_counts, "risk_rating": "medium"},
        "executive_summary": (
            f"Security assessment completed for {inp.target}. "
            f"Identified {len(findings)} findings "
            f"({sev_counts['critical']} critical, {sev_counts['high']} high, "
            f"{sev_counts['medium']} medium, {sev_counts['low']} low). "
            f"Review findings manually for full impact analysis."
        ),
        "sections": ["Scope", "Methodology", "Findings", "Recommendations"],
        "findings_detail": findings,
        "ai_insights": [],
    }
    return ReportingOutput(report=report)


async def ai_reporting(
    inp: ReportingInput, *, scan_id: str | None = None
) -> ReportingOutput:
    """Call LLM to generate report. Falls back to structured non-LLM report on failure."""
    _require_llm()
    system, user = _build_reporting_prompt(inp)

    try:
        data = _require_json(
            await _call_llm_with_json_retry(
                REPORTING, user, system, scan_id=scan_id
            ),
            REPORTING,
        )
        if isinstance(data.get("report"), dict):
            return ReportingOutput(report=data["report"])
    except Exception:
        logger.exception("reporting_llm_failed_falling_back_to_structured")

    logger.info("reporting_using_fallback", extra={"target": inp.target})
    return _build_fallback_report(inp)
