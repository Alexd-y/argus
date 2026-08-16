"""Contextual Vulnerability Discovery worker v1 — repo-aware semantic SAST via WhiteRabbitNeo.

Finds: authz bypass, injection families, SSRF, path traversal, insecure deserialization,
race conditions, insecure crypto, secret exposure, logic flaws.

Works on full repo AND per-PR diff. Uses code property graph for context — not rule-only.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from src.analysis.cpg import CodePropertyGraph, NodeType
from src.llm.facade import call_llm_unified
from src.llm.task_router import LLMTask

logger = logging.getLogger(__name__)


@dataclass
class VulnFinding:
    id: str = ""
    title: str = ""
    severity: str = ""  # critical | high | medium | low | info
    cwe: str = ""
    cvss: float | None = None
    description: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    code_snippet: str = ""
    confidence: str = ""  # confirmed | likely | possible | advisory
    exploitability: str = ""  # high | medium | low | unknown
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    owasp_category: str = ""


@dataclass
class VulnDiscoveryResult:
    findings: list[VulnFinding] = field(default_factory=list)
    total_files_scanned: int = 0
    total_functions_analysed: int = 0
    false_positive_estimate: int = 0
    scan_duration_seconds: float = 0.0


def _prompt_vuln_discovery(
    cpg: CodePropertyGraph,
    threat_model: dict[str, Any],
    target_name: str,
    mode: str = "full_repo",
) -> str:
    """Build WRB prompt for semantic vulnerability discovery."""
    entry_points = [n for n in cpg.nodes if n.node_type == NodeType.ENTRY_POINT]
    sinks = [n for n in cpg.nodes if n.node_type == NodeType.SENSITIVE_SINK]
    functions = [n for n in cpg.nodes if n.node_type in (NodeType.FUNCTION, NodeType.METHOD)]
    files = list({n.file_path for n in cpg.nodes if n.file_path})

    ep_summary = "\n".join(f"  - {n.name} @ {n.file_path}:{n.line_start}" for n in entry_points[:30])
    sink_summary = "\n".join(f"  - {n.name} @ {n.file_path}:{n.line_start}" for n in sinks[:30])
    fn_summary = "\n".join(f"  - {n.name} @ {n.file_path}:{n.line_start}" for n in functions[:50])

    return f"""Perform contextual vulnerability discovery for: {target_name}

=== MODE ===
{mode}

=== FILES ANALYSED ===
{', '.join(files[:100]) or 'none'}

=== ENTRY POINTS (user input, uploads, auth flows) ===
{ep_summary or 'none detected'}

=== SENSITIVE SINKS (DB queries, file ops, exec calls, …) ===
{sink_summary or 'none detected'}

=== FUNCTIONS / METHODS ===
{fn_summary or 'none detected'}

=== KNOWN THREAT MODEL ===
{json.dumps(threat_model, indent=2, default=str)[:4000] if threat_model else 'No threat model available'}

=== TASK ===
Find concrete security vulnerabilities by tracing paths from entry points to sensitive sinks.
For each finding provide:

1. title — concise description
2. severity — critical | high | medium | low | info
3. cwe — CWE identifier when applicable
4. cvss — estimated CVSS v3.1 score
5. description — what makes this exploitable, attack vector, preconditions
6. file_path + line_start — exact location in code
7. code_snippet — the relevant code (1-3 lines)
8. confidence — how certain you are: confirmed | likely | possible | advisory
9. exploitability — high | medium | low | unknown
10. remediation — concrete fix suggestion
11. owasp_category — OWASP Top 10 2021 mapping

Look for: authz bypass, SQL/NoSQL/Command injection, XSS, SSRF, path traversal, LFI/RFI,
insecure deserialization, race conditions, insecure crypto (weak ciphers, hardcoded keys),
secret exposure in code, logic flaws in auth flows.

Respond ONLY with valid JSON array. No markdown, no explanations."""


async def run_vuln_discovery(
    repo_name: str,
    cpg: CodePropertyGraph,
    threat_model: dict[str, Any] | None = None,
    *,
    mode: str = "full_repo",
    changed_files: list[str] | None = None,
    execution_mode: str | None = None,
    scan_options: dict[str, Any] | None = None,
) -> VulnDiscoveryResult:
    """Run contextual vulnerability discovery via WhiteRabbitNeo.

    Args:
        repo_name: Repository name.
        cpg: Code property graph for the target.
        threat_model: Previously built threat model (optional, enriches context).
        mode: "full_repo" or "pr_diff".
        changed_files: List of changed file paths (for PR mode).
        execution_mode: Optional ``production`` / ``lab_unrestricted`` forwarded
            to the unified LLM gateway.

    Returns:
        VulnDiscoveryResult with findings, file/function counts, FP estimate.
    """
    start = time.monotonic()

    if mode == "pr_diff" and changed_files:
        cpg = CodePropertyGraph(
            language=cpg.language,
            nodes=[n for n in cpg.nodes if n.file_path in changed_files],
            edges=[e for e in cpg.edges if any(
                n.file_path in changed_files for n in cpg.nodes if n.id in (e.source_id, e.target_id)
            )],
        )

    prompt = _prompt_vuln_discovery(
        cpg,
        threat_model or {},
        repo_name,
        mode=mode,
    )

    system_prompt = (
        "You are an expert application security researcher performing semantic code review. "
        "You trace data flows from entry points to sensitive sinks to identify REAL vulnerabilities "
        "— not pattern-matching, but context-aware analysis. "
        "For each finding, be precise about file paths, line numbers, and exploitation conditions. "
        "Respond ONLY with a valid JSON array of finding objects."
    )

    response_text = await call_llm_unified(
        system_prompt,
        prompt,
        task=LLMTask.ZERO_DAY_ANALYSIS,
        phase="vuln_discovery",
        execution_mode=execution_mode,
        scan_options=scan_options,
    )

    try:
        findings_raw = json.loads(response_text)
    except json.JSONDecodeError:
        import re
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response_text)
        if match:
            findings_raw = json.loads(match.group(1))
        else:
            logger.error("Failed to parse vuln discovery JSON")
            findings_raw = []

    if not isinstance(findings_raw, list):
        findings_raw = [findings_raw]

    findings = []
    for f in findings_raw:
        if not isinstance(f, dict):
            continue
        findings.append(VulnFinding(
            title=str(f.get("title", "Untitled finding"))[:500],
            severity=str(f.get("severity", "info")).lower(),
            cwe=str(f.get("cwe", ""))[:20],
            cvss=float(f["cvss"]) if f.get("cvss") is not None else None,
            description=str(f.get("description", ""))[:5000],
            file_path=str(f.get("file_path", "")),
            line_start=int(f.get("line_start", 0) or 0),
            line_end=int(f.get("line_end", 0) or 0),
            code_snippet=str(f.get("code_snippet", ""))[:2000],
            confidence=str(f.get("confidence", "advisory")).lower(),
            exploitability=str(f.get("exploitability", "unknown")).lower(),
            remediation=str(f.get("remediation", ""))[:3000],
            owasp_category=str(f.get("owasp_category", "")),
        ))

    elapsed = time.monotonic() - start
    total_functions = sum(1 for n in cpg.nodes if n.node_type in (NodeType.FUNCTION, NodeType.METHOD))
    total_files = len({n.file_path for n in cpg.nodes})

    return VulnDiscoveryResult(
        findings=findings,
        total_files_scanned=total_files,
        total_functions_analysed=total_functions,
        scan_duration_seconds=round(elapsed, 2),
    )


async def run_vuln_discovery_on_pr(
    repo_name: str,
    cpg: CodePropertyGraph,
    pr_diff: str,
    changed_files: list[str],
    threat_model: dict[str, Any] | None = None,
    *,
    execution_mode: str | None = None,
    scan_options: dict[str, Any] | None = None,
) -> VulnDiscoveryResult:
    """Run vulnerability discovery focused on a pull request diff.

    Analyses only changed files and the diff context for introduced vulnerabilities.
    Returns findings formatted as inline PR review comments.
    """
    prompt = f"""Review this pull request diff for security vulnerabilities.

=== REPOSITORY ===
{repo_name}

=== CHANGED FILES ===
{json.dumps(changed_files)}

=== PR DIFF ===
{pr_diff[:8000]}

=== THREAT MODEL CONTEXT ===
{json.dumps(threat_model, indent=2)[:2000] if threat_model else 'None'}

=== TASK ===
Find security issues introduced by this PR. For each:
- file + line in the NEW code
- severity and CWE
- why it's exploitable
- suggested fix

Respond ONLY with JSON array."""

    system_prompt = (
        "You are a security reviewer. Analyse this PR diff for vulnerabilities. "
        "Respond ONLY with valid JSON array."
    )

    response_text = await call_llm_unified(
        system_prompt, prompt,
        task=LLMTask.ZERO_DAY_ANALYSIS,
        phase="pr_review",
        execution_mode=execution_mode,
        scan_options=scan_options,
    )

    try:
        findings_raw = json.loads(response_text)
        if isinstance(findings_raw, dict):
            findings_raw = [findings_raw]
    except json.JSONDecodeError:
        findings_raw = []

    findings = []
    for f in (findings_raw or []):
        if not isinstance(f, dict):
            continue
        findings.append(VulnFinding(
            title=str(f.get("title", ""))[:500],
            severity=str(f.get("severity", "info")).lower(),
            cwe=str(f.get("cwe", ""))[:20],
            description=str(f.get("description", ""))[:5000],
            file_path=str(f.get("file_path", "")),
            line_start=int(f.get("line_start", 0) or 0),
            code_snippet=str(f.get("code_snippet", ""))[:2000],
            remediation=str(f.get("remediation", ""))[:3000],
        ))

    return VulnDiscoveryResult(findings=findings)
