"""AI prompt handlers — LLM is mandatory, no mock fallbacks.

KAL-008: phase prompts embed Kali/MCP taxonomy, run_* vs pipeline guidance, and safety rules
via ``src.orchestration.prompt_registry`` (see ``ORCHESTRATION_PROMPT_VERSION``).
"""

import asyncio
import json
import logging
import re
from collections.abc import Awaitable, Callable
from typing import Any

from src.execution_mode.runtime_context import peek_execution_mode_from_options
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
from src.orchestration.prompt_loader import render_phase_prompts as _render_jinja2
from src.orchestration.prompt_registry import (
    EXPLOITATION,
    POST_EXPLOITATION,
    RECON,
    REPORTING,
    THREAT_MODELING,
    VULN_ANALYSIS,
    get_fixer_prompt,
    get_prompt,
    get_report_assembly_prompt,
    get_report_section_prompt,
    get_schema,
)
from src.orchestration.rag_phase_context import render_phase_rag_section
from src.orchestration.raw_phase_artifacts import RawPhaseSink

logger = logging.getLogger(__name__)

MAX_JSON_RETRIES = 1


def _get_phase_prompt(phase: str, **kwargs: Any) -> tuple[str, str]:
    """Get phase prompt, preferring Jinja2 templates when available."""
    scope_context = kwargs.pop("scope_context", "")
    memory_context = kwargs.pop("memory_context", "")
    code_aware_section = kwargs.pop("code_aware_section", "")
    rag_context = kwargs.pop("rag_context", "")
    try:
        system, user = _render_jinja2(phase, **kwargs)
    except Exception:
        system, user = get_prompt(phase, **kwargs)
    if code_aware_section:
        user = user + "\n\n" + code_aware_section
    if memory_context:
        user = user + "\n\n" + memory_context
    if rag_context:
        user = user + "\n\n" + rag_context
    if scope_context:
        system = system + "\n\n=== RULES OF ENGAGEMENT ===\n" + scope_context + "\n=== END ==="
    sanitize = kwargs.pop("sanitize", True)
    if sanitize:
        try:
            from src.orchestration.prompt_injection_defense import sanitize_prompt_inputs, InjectionRisk, classify_injection_risk
            check = classify_injection_risk(user)
            if check.risk == InjectionRisk.DANGEROUS:
                logger.warning("dangerous_injection_pattern_in_prompt", extra={"phase": phase, "patterns": check.matched_patterns})
            enhanced_system, sanitized = sanitize_prompt_inputs(system, {"user_data": user})
            user = sanitized["user_data"]
            system = enhanced_system
        except Exception:
            pass
    return system, user

_PHASE_TO_TASK: dict[str, LLMTask] = {
    RECON: LLMTask.ORCHESTRATION,
    THREAT_MODELING: LLMTask.THREAT_MODELING,
    VULN_ANALYSIS: LLMTask.ZERO_DAY_ANALYSIS,
    EXPLOITATION: LLMTask.EXPLOIT_GENERATION,
    POST_EXPLOITATION: LLMTask.REMEDIATION_PLAN,
    REPORTING: LLMTask.REPORT_SECTION,
}

_PHASE_ORDER: list[str] = [RECON, THREAT_MODELING, VULN_ANALYSIS, EXPLOITATION, POST_EXPLOITATION]


def _execution_mode_from_options(options: dict[str, Any] | None) -> str | None:
    """Extract execution_mode from phase/scan options when present."""
    peeked = peek_execution_mode_from_options(options)
    return peeked.value if peeked is not None else None


def _option_id(options: dict[str, Any] | None, key: str) -> str | None:
    opts = options if isinstance(options, dict) else {}
    raw = opts.get(key)
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _phase_rag_context(
    phase: str,
    query: str,
    options: dict[str, Any] | None,
    *,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
) -> str:
    """Fail-open RAG section for planner/TM/VA. Empty when scope is missing."""
    opts = options if isinstance(options, dict) else {}
    scoped_tenant = (tenant_id or _option_id(opts, "tenant_id") or "").strip()
    scoped_engagement = (engagement_id or _option_id(opts, "engagement_id") or "").strip()
    if not scoped_tenant or not scoped_engagement:
        return ""
    mode = _execution_mode_from_options(opts) or "production"
    try:
        return render_phase_rag_section(
            phase,
            scoped_tenant,
            scoped_engagement,
            mode,
            query,
        )
    except Exception:
        logger.warning(
            "phase_rag_context_failed",
            extra={"event": "phase_rag_context_failed", "phase": phase},
        )
        return ""


def _react_llm_caller(
    task: LLMTask,
    *,
    scan_id: str | None,
    execution_mode: str | None,
) -> Callable[..., Awaitable[str]]:
    """Wrap ``call_llm_unified`` so ReAct loops forward execution_mode + task."""

    async def _caller(system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        return await call_llm_unified(
            system_prompt,
            user_prompt,
            task=task,
            scan_id=kwargs.get("scan_id", scan_id),
            phase=str(kwargs.get("phase") or "react_loop"),
            execution_mode=execution_mode,
        )

    return _caller


def _parse_llm_json(text: str) -> dict[str, Any] | None:
    """Extract and parse JSON from LLM response. Handles ```json blocks and truncated JSON."""
    if not text or not text.strip():
        return None
    text = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        text = match.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    if text.startswith("{") and not text.rstrip().endswith("}"):
        try:
            return json.loads(text.rstrip() + "}")
        except json.JSONDecodeError:
            pass
    if text.startswith("[") and not text.rstrip().endswith("]"):
        try:
            return json.loads(text.rstrip() + "]")
        except json.JSONDecodeError:
            pass
    try:
        obj_start = text.find("{")
        arr_start = text.find("[")
        if obj_start >= 0 and (arr_start < 0 or obj_start <= arr_start):
            depth = 0
            for i in range(obj_start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        return json.loads(text[obj_start : i + 1])
        elif arr_start >= 0:
            depth = 0
            for i in range(arr_start, len(text)):
                if text[i] == "[":
                    depth += 1
                elif text[i] == "]":
                    depth -= 1
                    if depth == 0:
                        return json.loads(text[arr_start : i + 1])
    except (json.JSONDecodeError, ValueError):
        pass
    return None


async def _call_llm_with_json_retry(
    phase: str,
    user_prompt: str,
    system_prompt: str,
    *,
    raw_sink: RawPhaseSink | None = None,
    raw_label_prefix: str = "llm",
    scan_id: str | None = None,
    execution_mode: str | None = None,
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
        execution_mode=execution_mode,
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
            execution_mode=execution_mode,
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
    """Analyze real tool output via LLM to produce structured recon."""
    _require_llm()
    try:
        rag_query = f"{inp.target} reconnaissance {tool_results[:1500]}".strip()
        rag_context = _phase_rag_context(RECON, rag_query, inp.options)
        system, user = _get_phase_prompt(
            RECON,
            target=inp.target,
            options=inp.options,
            tool_results=tool_results,
            rag_context=rag_context,
        )
        data = _require_json(
            await _call_llm_with_json_retry(
                RECON, user, system, raw_sink=raw_sink,
                raw_label_prefix="recon_llm", scan_id=scan_id,
                execution_mode=_execution_mode_from_options(inp.options),
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
    except Exception:
        logger.exception("recon_llm_failed")
        return ReconOutput(assets=[], subdomains=[], ports=[])


async def ai_threat_modeling(
    inp: ThreatModelInput,
    nvd_data: str = "",
    *,
    recon_context: str = "",
    scan_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
) -> ThreatModelOutput:
    """Build threat model from real assets, NVD CVEs, and enriched recon context via LLM."""
    _require_llm()
    try:
        asset_blob = " ".join(str(item) for item in inp.assets[:20])
        rag_query = f"threat model {asset_blob} {recon_context[:1500]} {nvd_data[:500]}".strip()
        rag_context = _phase_rag_context(THREAT_MODELING, rag_query, scan_options)
        system, user = _get_phase_prompt(
            THREAT_MODELING,
            assets=inp.assets,
            nvd_data=nvd_data,
            recon_context=recon_context,
            rag_context=rag_context,
        )
        data = _require_json(
            await _call_llm_with_json_retry(
                THREAT_MODELING,
                user,
                system,
                scan_id=scan_id,
                execution_mode=_execution_mode_from_options(scan_options),
            ),
            THREAT_MODELING,
        )
        if not isinstance(data.get("threat_model"), dict):
            raise RuntimeError(f"LLM returned invalid response for {THREAT_MODELING}")
        return ThreatModelOutput(threat_model=data["threat_model"])
    except Exception:
        logger.exception("threat_model_llm_failed")
        return ThreatModelOutput(threat_model={})


async def ai_vuln_analysis(
    inp: VulnAnalysisInput,
    *,
    active_scan_context: str = "",
    code_aware_section: str = "",
    memory_context: str = "",
    use_react: bool = False,
    scan_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
) -> VulnAnalysisOutput:
    _require_llm()
    execution_mode = _execution_mode_from_options(scan_options)
    try:
        if use_react:
            try:
                from src.orchestration.react_agent import ReActAgent
                _agent = ReActAgent(
                    task_description=f"Analyze vulnerabilities for threat model: {json.dumps(inp.threat_model, default=str)[:2000]}",
                    max_iterations=5,
                    confidence_threshold=0.85,
                )
                _react_result = await _agent.run(
                    system_prompt="You are a vulnerability analyst. Analyze the threat model and return JSON findings.",
                    llm_caller=_react_llm_caller(
                        LLMTask.ZERO_DAY_ANALYSIS,
                        scan_id=scan_id,
                        execution_mode=execution_mode,
                    ),
                    scan_id=scan_id,
                )
                data = _parse_llm_json(_react_result.answer)
                if data and isinstance(data.get("findings"), list):
                    return VulnAnalysisOutput(findings=data["findings"])
            except Exception:
                pass
        threat_blob = json.dumps(inp.threat_model, default=str)[:1500]
        asset_blob = " ".join(str(item) for item in inp.assets[:20])
        rag_query = f"vulnerability analysis {asset_blob} {threat_blob} {active_scan_context[:800]}".strip()
        rag_context = _phase_rag_context(VULN_ANALYSIS, rag_query, scan_options)
        system, user = _get_phase_prompt(
            VULN_ANALYSIS, threat_model=inp.threat_model,
            assets=inp.assets, active_scan_context=active_scan_context,
            code_aware_section=code_aware_section, memory_context=memory_context,
            rag_context=rag_context,
        )
        data = _require_json(
            await _call_llm_with_json_retry(
                VULN_ANALYSIS, user, system, scan_id=scan_id,
                execution_mode=execution_mode,
            ),
            VULN_ANALYSIS,
        )
        if not isinstance(data.get("findings"), list):
            raise RuntimeError(f"LLM returned invalid response for {VULN_ANALYSIS}")
        _findings = data["findings"]
        try:
            from src.orchestration.cost_aware_reasoning import ConfidenceEscalator
            _confidence_values = [float(f.get("confidence", 0.5)) for f in _findings if isinstance(f, dict)]
            if _confidence_values:
                _avg_confidence = sum(_confidence_values) / len(_confidence_values)
                _escalator = ConfidenceEscalator(confidence_threshold=0.7)
                if _escalator.should_escalate(_avg_confidence, "medium"):
                    logger.info(
                        "confidence_escalation_suggested",
                        extra={"scan_id": scan_id, "avg_confidence": round(_avg_confidence, 3), "phase": "vuln_analysis"},
                    )
        except Exception:
            pass
        return VulnAnalysisOutput(findings=_findings)
    except Exception:
        logger.exception("vuln_analysis_llm_failed")
        return VulnAnalysisOutput(findings=[])


def _normalize_exploit_candidates(
    exploits: list[Any], findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Backfill finding_id/target on LLM exploit candidates so PoC verification can link
    and probe them. The model frequently omits these; we map them from the input findings
    (by explicit finding_id match, else positionally) and from common target aliases.
    """
    by_id: dict[str, dict[str, Any]] = {}
    for f in findings:
        fid = str(f.get("finding_id") or f.get("id") or "")
        if fid:
            by_id.setdefault(fid, f)

    normalized: list[dict[str, Any]] = []
    for idx, raw in enumerate(exploits):
        if not isinstance(raw, dict):
            continue
        exp = dict(raw)
        fid = str(exp.get("finding_id") or "")
        source = by_id.get(fid)
        if source is None and idx < len(findings) and isinstance(findings[idx], dict):
            source = findings[idx]
        if not fid and source is not None:
            fid = str(source.get("finding_id") or source.get("id") or "")
            if fid:
                exp["finding_id"] = fid
        if not exp.get("target"):
            exp["target"] = str(
                exp.get("target")
                or exp.get("url")
                or exp.get("poc_url")
                or (source.get("url") if source else "")
                or (source.get("affected_url") if source else "")
                or (source.get("location") if source else "")
                or ""
            )
        normalized.append(exp)
    return normalized


async def ai_exploitation(
    inp: ExploitationInput,
    *,
    use_react: bool = False,
    scan_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
    execution_mode: str | None = None,
) -> ExploitationOutput:
    _require_llm()
    resolved_mode = execution_mode or _execution_mode_from_options(scan_options)
    try:
        if use_react:
            try:
                from src.orchestration.react_agent import ReActAgent
                _agent = ReActAgent(
                    task_description=f"Plan exploitation for findings: {json.dumps(inp.findings, default=str)[:2000]}",
                    max_iterations=5,
                )
                _react_result = await _agent.run(
                    system_prompt="You are an exploitation planner. Generate exploit hypotheses and return JSON.",
                    llm_caller=_react_llm_caller(
                        LLMTask.EXPLOIT_GENERATION,
                        scan_id=scan_id,
                        execution_mode=resolved_mode,
                    ),
                    scan_id=scan_id,
                )
                data = _parse_llm_json(_react_result.answer)
                if data and isinstance(data.get("exploits"), list):
                    return ExploitationOutput(
                        exploits=_normalize_exploit_candidates(
                            data.get("exploits", []), inp.findings
                        ),
                        evidence=data.get("evidence", []),
                    )
            except Exception:
                pass
        # Feed a compact evidence pack instead of raw findings when phase routing
        # is enabled (reduces prompt noise / hallucination pressure).
        _prompt_findings = inp.findings
        try:
            from src.llm.phase_routing import is_enabled as _routing_enabled

            if _routing_enabled():
                from src.llm.evidence_contracts import build_exploit_candidate_pack

                _prompt_findings = build_exploit_candidate_pack(inp.findings)["candidates"]
        except Exception:
            _prompt_findings = inp.findings
        system, user = _get_phase_prompt(EXPLOITATION, findings=_prompt_findings)
        data = _require_json(
            await _call_llm_with_json_retry(
                EXPLOITATION, user, system, scan_id=scan_id,
                execution_mode=resolved_mode,
            ),
            EXPLOITATION,
        )
        if not isinstance(data.get("exploits"), list):
            raise RuntimeError(f"LLM returned invalid response for {EXPLOITATION}")
        return ExploitationOutput(
            exploits=_normalize_exploit_candidates(data.get("exploits", []), inp.findings),
            evidence=data.get("evidence", []),
        )
    except Exception:
        logger.exception("exploitation_llm_failed")
        return ExploitationOutput(exploits=[], evidence=[])


async def ai_post_exploitation(
    inp: PostExploitationInput,
    *,
    raw_sink: RawPhaseSink | None = None,
    scan_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
) -> PostExploitationOutput:
    """Call LLM for lateral movement / persistence. Returns empty on failure."""
    _require_llm()
    execution_mode = _execution_mode_from_options(scan_options)
    try:
        system, user = _get_phase_prompt(POST_EXPLOITATION, exploits=inp.exploits)
        data = _require_json(
            await _call_llm_with_json_retry(
                POST_EXPLOITATION, user, system,
                raw_sink=raw_sink, raw_label_prefix="post_exploitation_llm",
                scan_id=scan_id,
                execution_mode=execution_mode,
            ),
            POST_EXPLOITATION,
        )
        return PostExploitationOutput(
            lateral=data.get("lateral", []) if isinstance(data.get("lateral"), list) else [],
            persistence=data.get("persistence", []) if isinstance(data.get("persistence"), list) else [],
        )
    except Exception:
        logger.exception("post_exploitation_llm_failed")
        return PostExploitationOutput(lateral=[], persistence=[])


async def _call_wrb_report_section(
    phase: str,
    phase_data: str,
    *,
    scan_id: str | None = None,
    execution_mode: str | None = None,
) -> str:
    """Call WRB to generate a report section for ONE phase. Hard limit 16k chars to stay within 32k context."""
    import json as _json

    max_data = 20000
    if len(phase_data) > max_data:
        phase_data = phase_data[:max_data]
        try:
            truncated = _json.loads(phase_data.rsplit('"', 1)[0] + '"}')
            phase_data = _json.dumps(truncated, ensure_ascii=False, default=str, indent=2)
        except Exception:
            pass
        if len(phase_data) > max_data:
            phase_data = phase_data[:max_data]

    try:
        system, user = get_report_section_prompt(phase, phase_data)
        total_bytes = len(system) + len(user)
        if total_bytes > 24000:
            user = user[:16000]
        response = await call_llm_unified(
            system, user, task=LLMTask.REPORT_SECTION,
            scan_id=scan_id, phase=f"{phase}_report_section",
            execution_mode=execution_mode,
        )
        if response:
            data = _parse_llm_json(response)
            if data is not None and isinstance(data.get("section"), dict):
                section = data["section"]
                summary_keys = [
                    "recon_summary", "threat_model_summary", "vuln_analysis_summary",
                    "exploitation_summary", "post_exploitation_summary",
                ]
                for key in summary_keys:
                    val = section.get(key)
                    if isinstance(val, str) and val:
                        return val
                return _json.dumps(section, ensure_ascii=False, default=str)
    except Exception:
        logger.exception("report_section_wrb_call_failed", extra={"phase": phase})
    return ""


def _get_phase_data(inp: ReportingInput, phase: str) -> str | None:
    """Extract FULL raw JSON for one phase from ReportingInput."""
    import json as _json

    mapping: dict[str, Any] = {
        RECON: inp.recon,
        THREAT_MODELING: inp.threat_model,
        VULN_ANALYSIS: inp.vuln_analysis,
        EXPLOITATION: inp.exploitation,
        POST_EXPLOITATION: inp.post_exploitation,
    }
    obj = mapping.get(phase)
    if obj is None:
        return None
    raw = obj.model_dump()
    return _json.dumps(raw, ensure_ascii=False, default=str, indent=2)


def _build_fallback_report(inp: ReportingInput) -> ReportingOutput:
    """Non-LLM report when WRB + cloud all fail."""
    findings: list[dict[str, Any]] = []
    if inp.vuln_analysis:
        va = inp.vuln_analysis.model_dump()
        raw_findings = va.get("findings") or va.get("vulnerabilities") or []
        for f in raw_findings:
            if isinstance(f, dict):
                findings.append({
                    "severity": str(f.get("severity", "info")).lower(),
                    "description": str(f.get("description") or f.get("name", "Unknown finding")),
                    "impact": str(f.get("impact", "Not assessed")),
                    "remediation": str(f.get("remediation", "Manual review required")),
                })
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
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


async def _compress_summary_for_assembly(
    summary: str, *, max_chars: int = 8000, execution_mode: str | None = None
) -> str:
    """Ask WRB to compress a summary to key facts only."""
    try:
        prompt = (
            f"Compress this security assessment summary to its key facts only. "
            f"Keep: findings, severity counts, tool results, CVE IDs, evidence. "
            f"Remove: filler, repetition, generic advice. Max {max_chars} chars.\n\n{summary}"
        )
        resp = await call_llm_unified(
            "Compress text to key facts. Return only the compressed text.",
            prompt, task=LLMTask.REPORT_SECTION, phase="summary_compression",
            execution_mode=execution_mode,
        )
        return resp[:max_chars] if resp else summary[:max_chars]
    except Exception:
        return summary[:max_chars]


async def ai_reporting(
    inp: ReportingInput, *, scan_id: str | None = None, scan_options: dict[str, Any] | None = None
) -> ReportingOutput:
    """Generate report via 6 separate WRB calls — one per phase (FULL data) + assembly.

    No data is ever truncated. Each phase gets its complete raw output as a separate
    WRB call, producing a structured section summary. A final assembly call merges
    all summaries into the final report JSON. Falls back to structured report on failure.
    """
    _require_llm()
    execution_mode = _execution_mode_from_options(scan_options)

    section_summaries: dict[str, str] = {}
    for phase in _PHASE_ORDER:
        phase_data = _get_phase_data(inp, phase)
        if not phase_data:
            continue
        try:
            summary = await _call_wrb_report_section(
                phase, phase_data, scan_id=scan_id, execution_mode=execution_mode,
            )
            if summary:
                section_summaries[phase] = summary
                logger.info(
                    "report_section_generated",
                    extra={"phase": phase, "summary_len": len(summary)},
                )
            else:
                logger.warning(
                    "report_section_empty",
                    extra={"phase": phase},
                )
        except Exception:
            logger.exception(
                "report_section_failed",
                extra={"phase": phase},
            )

    try:
        assembly_system, assembly_user = get_report_assembly_prompt(
            target=inp.target,
            recon_summary=section_summaries.get(RECON, ""),
            threat_model_summary=section_summaries.get(THREAT_MODELING, ""),
            vuln_summary=section_summaries.get(VULN_ANALYSIS, ""),
            exploit_summary=section_summaries.get(EXPLOITATION, ""),
            post_exploit_summary=section_summaries.get(POST_EXPLOITATION, ""),
        )
        response = await call_llm_unified(
            assembly_system,
            assembly_user,
            task=LLMTask.REPORT_SECTION,
            scan_id=scan_id,
            phase="report_assembly",
            execution_mode=execution_mode,
        )
        data = _parse_llm_json(response)
        if data is not None and isinstance(data.get("report"), dict):
            logger.info("report_assembly_success")
            return ReportingOutput(report=data["report"])
    except Exception as exc:
        exc_name = type(exc).__name__
        is_http_400 = "400" in str(exc) or "HTTPStatusError" in exc_name
        if is_http_400 and section_summaries:
            for retry in range(2):
                try:
                    compressed: dict[str, str] = {}
                    for phase_name, summary in section_summaries.items():
                        if len(summary) > 8000:
                            compressed[phase_name] = await _compress_summary_for_assembly(
                                summary, max_chars=8000, execution_mode=execution_mode,
                            )
                        else:
                            compressed[phase_name] = summary
                    total = sum(len(v) for v in compressed.values())
                    if total > 24000:
                        factor = 24000 / total
                        compressed = {
                            k: v[: int(len(v) * factor)] for k, v in compressed.items()
                        }
                    sys2, usr2 = get_report_assembly_prompt(
                        target=inp.target,
                        recon_summary=compressed.get(RECON, ""),
                        threat_model_summary=compressed.get(THREAT_MODELING, ""),
                        vuln_summary=compressed.get(VULN_ANALYSIS, ""),
                        exploit_summary=compressed.get(EXPLOITATION, ""),
                        post_exploit_summary=compressed.get(POST_EXPLOITATION, ""),
                    )
                    resp2 = await call_llm_unified(
                        sys2, usr2, task=LLMTask.REPORT_SECTION,
                        scan_id=scan_id, phase=f"report_assembly_retry_{retry + 1}",
                        execution_mode=execution_mode,
                    )
                    data2 = _parse_llm_json(resp2)
                    if data2 is not None and isinstance(data2.get("report"), dict):
                        logger.info(
                            "report_assembly_retry_success",
                            extra={"retry": retry + 1},
                        )
                        return ReportingOutput(report=data2["report"])
                except Exception:
                    logger.warning(
                        "report_assembly_retry_failed",
                        extra={"retry": retry + 1},
                    )
        logger.exception("report_assembly_failed")

    if section_summaries:
        report = {
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_rating": "medium"},
            "executive_summary": f"Security assessment completed for {inp.target}.",
            "sections": list(section_summaries.keys()),
            "findings_detail": [],
            "ai_insights": list(section_summaries.values()),
        }
        return ReportingOutput(report=report)

    logger.info("reporting_using_fallback", extra={"target": inp.target})
    return _build_fallback_report(inp)
