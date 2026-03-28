"""AI prompt handlers — LLM is mandatory, no mock fallbacks.

KAL-008: phase prompts embed Kali/MCP taxonomy, run_* vs pipeline guidance, and safety rules
via ``src.orchestration.prompt_registry`` (see ``ORCHESTRATION_PROMPT_VERSION``).
"""

import asyncio
import json
import logging
import re
from typing import Any

from src.llm import call_llm, is_llm_available
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
) -> dict[str, Any] | None:
    """
    Call LLM, parse JSON. On parse failure, retry once with fixer prompt.
    Returns parsed dict or None.
    """
    response = await call_llm(user_prompt, system_prompt=system_prompt)
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
        response = await call_llm(fixer_user, system_prompt=fixer_system)
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


async def ai_threat_modeling(inp: ThreatModelInput, nvd_data: str = "") -> ThreatModelOutput:
    """Build threat model from real assets and NVD CVEs via LLM. Raises on failure."""
    _require_llm()
    system, user = get_prompt(THREAT_MODELING, assets=inp.assets, nvd_data=nvd_data)
    data = _require_json(
        await _call_llm_with_json_retry(THREAT_MODELING, user, system),
        THREAT_MODELING,
    )
    if not isinstance(data.get("threat_model"), dict):
        raise RuntimeError(f"LLM returned invalid response for {THREAT_MODELING}")
    return ThreatModelOutput(threat_model=data["threat_model"])


async def ai_vuln_analysis(
    inp: VulnAnalysisInput,
    *,
    active_scan_context: str = "",
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
        await _call_llm_with_json_retry(VULN_ANALYSIS, user, system),
        VULN_ANALYSIS,
    )
    if not isinstance(data.get("findings"), list):
        raise RuntimeError(f"LLM returned invalid response for {VULN_ANALYSIS}")
    return VulnAnalysisOutput(findings=data["findings"])


async def ai_exploitation(inp: ExploitationInput) -> ExploitationOutput:
    """Call LLM to plan exploitation. Raises on failure."""
    _require_llm()
    system, user = get_prompt(EXPLOITATION, findings=inp.findings)
    data = _require_json(
        await _call_llm_with_json_retry(EXPLOITATION, user, system),
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
        ),
        POST_EXPLOITATION,
    )
    return PostExploitationOutput(
        lateral=data.get("lateral", []) if isinstance(data.get("lateral"), list) else [],
        persistence=data.get("persistence", []) if isinstance(data.get("persistence"), list) else [],
    )


async def ai_reporting(inp: ReportingInput) -> ReportingOutput:
    """Call LLM to generate report. Raises on failure."""
    _require_llm()
    summary = {
        "target": inp.target,
        "recon": inp.recon.model_dump() if inp.recon else None,
        "threat_model": inp.threat_model.model_dump() if inp.threat_model else None,
        "vuln_analysis": inp.vuln_analysis.model_dump() if inp.vuln_analysis else None,
        "exploitation": inp.exploitation.model_dump() if inp.exploitation else None,
        "post_exploitation": inp.post_exploitation.model_dump() if inp.post_exploitation else None,
    }
    rc = inp.report_context if isinstance(inp.report_context, dict) else {}
    if rc:
        summary["report_context"] = rc
    system, user = get_prompt(REPORTING, summary=summary)
    data = _require_json(
        await _call_llm_with_json_retry(REPORTING, user, system), REPORTING
    )
    if not isinstance(data.get("report"), dict):
        raise RuntimeError(f"LLM returned invalid response for {REPORTING}")
    return ReportingOutput(report=data["report"])
