"""Stage-specific MCP policy for Recon Stage 1 (fail-closed).

RECON_STAGE1_HTML_JS parsing allowlist (REC-002):
- Safe operations: fetch, read_file, parse — no payload generation.
- MCP fetch used only for safe reads when crawl/HTTP probe returns empty.
- Denied: exploit, bruteforce, payload, sqli, xss, and similar patterns.

RECON_STAGE1 allowlist for HTML/JS parsing:
- fetch: HTTP(S) URL retrieval for endpoint discovery, route extraction.
- read_file: Local artifact read for parse/html_extraction/js_extraction.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)

RECON_STAGE1_POLICY_ID = "recon_stage1_safe_ops_v1"

RECON_STAGE1_ALLOWED_TOOLS = {"fetch", "read_file", "mcp-server-fetch.fetch"}

RECON_STAGE1_HTML_JS_ALLOWED_OPERATIONS = frozenset({
    "fetch",
    "read_file",
    "parse",
    "html_extraction",
    "form_extraction",
    "link_extraction",
    "js_extraction",
    "route_extraction",
    "endpoint_extraction",
    "route_endpoint_extraction",
})
"""Safe operations for HTML/JS parsing in Stage 1. No payload generation allowed."""

# Stage 2 Threat Modeling
THREAT_MODELING_POLICY_ID = "threat_modeling_safe_ops_v1"
THREAT_MODELING_ALLOWED_TOOLS = {"fetch", "read_file", "mcp-server-fetch.fetch"}
THREAT_MODELING_ALLOWED_OPERATIONS = {
    "correlation",
    "enrichment",
    "parse",
    "endpoint_extraction",
}

# Stage 3 Vulnerability Analysis (VA3UP-009)
# Allow: artifact parsing, evidence correlation, route/API/form/param linkage,
# host behavior comparison, contradiction detection, duplicate grouping,
# finding-to-scenario/asset mapping, evidence bundle transformation, report generation.
# Deny: exploit, brute force, auth attack, destructive, evasion, persistence, payload.
VULNERABILITY_ANALYSIS_POLICY_ID = "vulnerability_analysis_safe_ops_v1"
VULNERABILITY_ANALYSIS_ALLOWED_TOOLS = {"fetch", "read_file", "mcp-server-fetch.fetch"}
VULNERABILITY_ANALYSIS_ALLOWED_OPERATIONS = frozenset({
    "parse",
    "correlation",
    "enrichment",
    "normalize",
    "route_form_param_correlation",
    "api_correlation",
    "metadata_comparison",
    "security_control_comparison",
    "host_clustering",
    "anomaly_correlation",
    "boundary_mapping",
    "finding_deduplication",
    "report_transform",
    # VA3UP-009: extended for Stage 3 evidence-driven workflow
    "artifact_parsing",
    "evidence_correlation",
    "route_form_param_linkage",
    "api_form_param_linkage",
    "host_behavior_comparison",
    "contradiction_detection",
    "duplicate_finding_grouping",
    "finding_to_scenario_mapping",
    "finding_to_asset_mapping",
    "evidence_bundle_transformation",
    "report_artifact_generation",
})

# VA active scan / MCP sandbox tools (OWASP-001, OWASP2-001): separate fail-closed branch from
# VULNERABILITY_ANALYSIS_ALLOWED_TOOLS (fetch/read_file). Callers that run sandbox
# scanners must use evaluate_va_active_scan_tool_policy — not widening Stage 3 safe MCP.
VA_ACTIVE_SCAN_POLICY_ID = "va_active_scan_sandbox_tools_v1"
# Canonical tool ids after normalization (lowercase, underscores/hyphens stripped).
VA_ACTIVE_SCAN_ALLOWED_TOOLS = frozenset({
    "dalfox",
    "xsstrike",
    "ffuf",
    # sqlmap: runner MUST enforce non-interactive --batch, target URL only from
    # validate_target_for_tool / engagement scope (guardrails), and MUST NOT pass
    # dangerous defaults (--os-pwn, --os-shell, --file-read, unrestricted --risk/--level)
    # unless explicitly enabled by a separate policy flag (executor fail-closed).
    "sqlmap",
    "nuclei",
    "gobuster",
    # OWASP2-001: wfuzz (fuzzing), commix (command injection) — same executor scope rules as sqlmap/ffuf.
    "wfuzz",
    "commix",
    # KAL-004 — recon / fingerprint hooks (sandbox + MinIO artifacts)
    "whatweb",
    "nikto",
    "testssl",
    "sslscan",
    # KAL-005 — feroxbuster (content discovery); password-audit + capture tools (gated in runner)
    "feroxbuster",
    "hydra",
    "medusa",
    "mitmdump",
    "tcpdump",
    # VDF-005 / VDF-008 — optional OSINT / shallow crawl (gated by settings + runner)
    "theharvester",
    "gospider",
    "parsero",
})

# VA-006 — MCP / internal enqueue operation ids (Celery task names mirror these with argus.va.*)
VA_ACTIVE_SCAN_MCP_OPERATIONS = frozenset({
    "run_dalfox",
    "run_xsstrike",
    "run_ffuf",
    "run_sqlmap",
    "run_nuclei",
    "run_whatweb",
    "run_nikto",
    "run_testssl",
})


def is_va_active_scan_mcp_operation(operation: str) -> bool:
    """True if *operation* is a registered VA sandbox MCP enqueue / task id (VA-006)."""
    n = str(operation or "").strip().lower().replace("-", "_")
    return n in VA_ACTIVE_SCAN_MCP_OPERATIONS


def _normalize_va_active_scan_tool_identifier(raw: str) -> str:
    """Normalize MCP/sandbox tool alias: case, underscores, hyphens, dots (fail-closed match)."""
    s = str(raw or "").strip().lower().replace("_", "").replace("-", "").replace(".", "")
    return s


# testssl.sh binary normalizes to testsslsh → canonical testssl
_VA_ACTIVE_SCAN_TOOL_ALIASES: dict[str, str] = {
    "testsslsh": "testssl",
}


def resolve_va_active_scan_tool_canonical(tool_name: str) -> str | None:
    """Return canonical tool id if allowlisted; unknown or empty => None (fail-closed)."""
    normalized = _normalize_va_active_scan_tool_identifier(tool_name)
    if not normalized:
        return None
    normalized = _VA_ACTIVE_SCAN_TOOL_ALIASES.get(normalized, normalized)
    if normalized in VA_ACTIVE_SCAN_ALLOWED_TOOLS:
        return normalized
    return None


def evaluate_va_active_scan_tool_policy(*, tool_name: str) -> McpPolicyDecision:
    """Fail-closed allowlist for VA sandbox active-scan tool names only.

    Does not replace evaluate_vulnerability_analysis_policy for fetch/read_file MCP.
    """
    canonical = resolve_va_active_scan_tool_canonical(tool_name)
    if canonical is None:
        return McpPolicyDecision(
            allowed=False,
            reason="active_scan_tool_not_allowlisted",
            policy_id=VA_ACTIVE_SCAN_POLICY_ID,
        )
    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=VA_ACTIVE_SCAN_POLICY_ID,
    )


# WEB-006 — per-tool approval policy for destructive active-scan tools
TOOL_APPROVAL_POLICY_ID = "tool_approval_policy_v1"


def evaluate_tool_approval_policy(
    tool_name: str,
    *,
    scan_approval_flags: dict[str, bool] | None = None,
) -> McpPolicyDecision:
    """Per-tool approval: base allowlist + explicit approval for destructive tools.

    Backward compatible: when *scan_approval_flags* is ``None``, destructive
    tools are allowed if they pass the base VA active-scan allowlist (existing
    behaviour preserved).
    """
    from src.core.config import settings

    base_decision = evaluate_va_active_scan_tool_policy(tool_name=tool_name)
    canonical = resolve_va_active_scan_tool_canonical(tool_name)
    is_destructive = (canonical in settings.destructive_tools) if canonical else False

    if not base_decision.allowed:
        decision = McpPolicyDecision(
            allowed=False,
            reason=base_decision.reason,
            policy_id=TOOL_APPROVAL_POLICY_ID,
        )
    elif (
        is_destructive
        and scan_approval_flags is not None
        and not scan_approval_flags.get(canonical or tool_name, False)
    ):
        decision = McpPolicyDecision(
            allowed=False,
            reason="requires_approval",
            policy_id=TOOL_APPROVAL_POLICY_ID,
        )
    else:
        decision = McpPolicyDecision(
            allowed=True,
            reason="allowed",
            policy_id=TOOL_APPROVAL_POLICY_ID,
        )

    logger.info(
        "policy_decision",
        extra={
            "tool": tool_name,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "approval_required": is_destructive,
        },
    )
    return decision


# Stage 4 Exploitation
EXPLOITATION_POLICY_ID = "exploitation_stage4_policy_v1"
EXPLOITATION_ALLOWED_TOOLS = frozenset({
    "metasploit", "sqlmap", "nuclei", "hydra", "medusa", "nmap",
    "custom_script", "curl", "wget", "python3", "bash",
})
EXPLOITATION_ALLOWED_OPERATIONS = frozenset({
    "exploit_execution",
    "credential_bruteforce",
    "vulnerability_verification",
    "payload_generation",
    "session_management",
    "data_extraction",
    "evidence_collection",
    "log_capture",
})
EXPLOITATION_BLOCKED_PATTERNS = (
    "--drop",
    "--delete",
    "rm -rf",
    "format ",
    "mkfs",
    "DROP TABLE",
    "DELETE FROM",
    "TRUNCATE",
    "ALTER TABLE",
    "--os-pwn",
    "--os-bof",
)

RECON_STAGE1_ALLOWED_OPERATIONS = {
    "html_extraction",
    "form_extraction",
    "link_extraction",
    "js_extraction",
    "route_extraction",
    "endpoint_extraction",
    "route_endpoint_extraction",
    "hashing",
    "similarity_analysis",
    "clustering",
    "redirect_comparison",
    "tls_parse",
    "header_normalize",
    "correlation",
    "csv_transform",
    "json_transform",
    "md_transform",
}

RECON_STAGE1_DENY_PATTERNS = (
    "exploit",
    "bruteforce",
    "brute_force",
    "auth_attack",
    "destructive",
    "evasion",
    "persistence",
    "payload",
    "rce",
    "sqli",
    "xss",
)

_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|token|secret|api[_-]?key|authorization|cookie|session|auth|code|key)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._\-+/=]{8,}|"
    r"(password|passwd|token|secret|api[_-]?key|authorization|cookie|session|auth|code|key)\s*[:=]\s*[^,\s;&]+)"
)


def _is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(str(key)))


def _sanitize_url_string(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return value
    if not parsed.query:
        return value

    redacted_pairs: list[tuple[str, str]] = []
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_sensitive_key(key) or bool(_SENSITIVE_VALUE_RE.search(val)):
            redacted_pairs.append((key, "[REDACTED]"))
        else:
            redacted_pairs.append((key, val))
    redacted_query = urlencode(redacted_pairs, doseq=True)
    return urlunparse(parsed._replace(query=redacted_query))


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value.strip())
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def _sanitize_string(value: str) -> str:
    sanitized = _sanitize_url_string(value) if _is_http_url(value) else value
    if not _is_http_url(value) and _SENSITIVE_VALUE_RE.search(sanitized):
        return "[REDACTED]"
    if len(sanitized) > 500:
        return f"{sanitized[:500]}...[TRUNCATED]"
    return sanitized


@dataclass(frozen=True, slots=True)
class McpPolicyDecision:
    allowed: bool
    reason: str
    policy_id: str = RECON_STAGE1_POLICY_ID


def sanitize_args(args: dict[str, Any]) -> dict[str, Any]:
    """Sanitize MCP args before audit logging."""
    return _sanitize_value(args)


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, inner in value.items():
            if _is_sensitive_key(str(key)):
                sanitized[str(key)] = "[REDACTED]"
            else:
                sanitized[str(key)] = _sanitize_value(inner)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value[:100]]
    if isinstance(value, str):
        return _sanitize_string(value)
    return value


def evaluate_recon_stage1_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """Evaluate Stage 1 MCP policy. Unknown operation/tool => denied."""
    normalized_tool = str(tool_name or "").strip().lower()
    normalized_operation = str(operation or "").strip().lower()

    if normalized_tool not in RECON_STAGE1_ALLOWED_TOOLS:
        return McpPolicyDecision(allowed=False, reason="tool_not_allowlisted")
    if normalized_operation not in RECON_STAGE1_ALLOWED_OPERATIONS:
        return McpPolicyDecision(allowed=False, reason="operation_not_allowlisted")

    searchable_blob = " ".join(
        [
            normalized_operation,
            json.dumps(sanitize_args(args), ensure_ascii=True, default=str).lower(),
        ]
    )
    for marker in RECON_STAGE1_DENY_PATTERNS:
        if marker in searchable_blob:
            return McpPolicyDecision(allowed=False, reason=f"denylist_keyword:{marker}")

    if normalized_tool in ("fetch", "mcp-server-fetch.fetch"):
        url = str(args.get("url", "") or "").strip()
        if not url:
            return McpPolicyDecision(allowed=False, reason="missing_url_argument")
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return McpPolicyDecision(allowed=False, reason="unsupported_url_scheme")
        if not parsed.netloc:
            return McpPolicyDecision(allowed=False, reason="invalid_url")
    elif normalized_tool == "read_file":
        path = str(args.get("path", args.get("uri", "") or "") or "").strip()
        if not path:
            return McpPolicyDecision(allowed=False, reason="missing_path_argument")
        if ".." in path or path.startswith("/") or "\\" in path:
            return McpPolicyDecision(allowed=False, reason="path_traversal_forbidden")
        if not re.match(r"^[\w.\-/]+$", path):
            return McpPolicyDecision(allowed=False, reason="invalid_path_characters")

    return McpPolicyDecision(allowed=True, reason="allowed")


def evaluate_threat_modeling_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """Evaluate Stage 2 Threat Modeling MCP policy. Unknown tool/operation => denied."""
    normalized_tool = str(tool_name or "").strip().lower()
    normalized_operation = str(operation or "").strip().lower()

    if normalized_tool not in THREAT_MODELING_ALLOWED_TOOLS:
        return McpPolicyDecision(
            allowed=False,
            reason="tool_not_allowlisted",
            policy_id=THREAT_MODELING_POLICY_ID,
        )
    if normalized_operation not in THREAT_MODELING_ALLOWED_OPERATIONS:
        return McpPolicyDecision(
            allowed=False,
            reason="operation_not_allowlisted",
            policy_id=THREAT_MODELING_POLICY_ID,
        )

    searchable_blob = " ".join(
        [
            normalized_operation,
            json.dumps(sanitize_args(args), ensure_ascii=True, default=str).lower(),
        ]
    )
    for marker in RECON_STAGE1_DENY_PATTERNS:
        if marker in searchable_blob:
            return McpPolicyDecision(
                allowed=False,
                reason=f"denylist_keyword:{marker}",
                policy_id=THREAT_MODELING_POLICY_ID,
            )

    if normalized_tool in ("fetch", "mcp-server-fetch.fetch"):
        url = str(args.get("url", "") or "").strip()
        if not url:
            return McpPolicyDecision(
                allowed=False,
                reason="missing_url_argument",
                policy_id=THREAT_MODELING_POLICY_ID,
            )
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return McpPolicyDecision(
                allowed=False,
                reason="unsupported_url_scheme",
                policy_id=THREAT_MODELING_POLICY_ID,
            )
        if not parsed.netloc:
            return McpPolicyDecision(
                allowed=False,
                reason="invalid_url",
                policy_id=THREAT_MODELING_POLICY_ID,
            )

    if normalized_tool == "read_file":
        path = str(args.get("path", args.get("uri", "") or "") or "").strip()
        if not path:
            return McpPolicyDecision(
                allowed=False,
                reason="missing_path_argument",
                policy_id=THREAT_MODELING_POLICY_ID,
            )
        if ".." in path or path.startswith("/") or "\\" in path:
            return McpPolicyDecision(
                allowed=False,
                reason="path_traversal_forbidden",
                policy_id=THREAT_MODELING_POLICY_ID,
            )
        if not re.match(r"^[\w.\-/]+$", path):
            return McpPolicyDecision(
                allowed=False,
                reason="invalid_path_characters",
                policy_id=THREAT_MODELING_POLICY_ID,
            )

    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=THREAT_MODELING_POLICY_ID,
    )


def evaluate_vulnerability_analysis_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """Evaluate Stage 3 Vulnerability Analysis MCP policy. Unknown tool/operation => denied.

    Allow: artifact parsing, HTML/JS/JSON/CSV/Markdown normalization, route/form/param
    correlation, API correlation, response metadata comparison, security-control comparison,
    host behavior clustering, anomaly correlation, trust-boundary mapping, finding
    deduplication/grouping, report artifact transformation.

    Deny: exploit tools, brute force tools, auth attack tools, destructive scanners,
    evasion tools, persistence tools, payload generators (same denylist as TM).
    """
    normalized_tool = str(tool_name or "").strip().lower()
    normalized_operation = str(operation or "").strip().lower()

    if normalized_tool not in VULNERABILITY_ANALYSIS_ALLOWED_TOOLS:
        return McpPolicyDecision(
            allowed=False,
            reason="tool_not_allowlisted",
            policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
        )
    if normalized_operation not in VULNERABILITY_ANALYSIS_ALLOWED_OPERATIONS:
        return McpPolicyDecision(
            allowed=False,
            reason="operation_not_allowlisted",
            policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
        )

    searchable_blob = " ".join(
        [
            normalized_operation,
            json.dumps(sanitize_args(args), ensure_ascii=True, default=str).lower(),
        ]
    )
    for marker in RECON_STAGE1_DENY_PATTERNS:
        if marker in searchable_blob:
            return McpPolicyDecision(
                allowed=False,
                reason=f"denylist_keyword:{marker}",
                policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
            )

    if normalized_tool in ("fetch", "mcp-server-fetch.fetch"):
        url = str(args.get("url", "") or "").strip()
        if not url:
            return McpPolicyDecision(
                allowed=False,
                reason="missing_url_argument",
                policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
            )
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return McpPolicyDecision(
                allowed=False,
                reason="unsupported_url_scheme",
                policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
            )
        if not parsed.netloc:
            return McpPolicyDecision(
                allowed=False,
                reason="invalid_url",
                policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
            )

    if normalized_tool == "read_file":
        path = str(args.get("path", args.get("uri", "") or "") or "").strip()
        if not path:
            return McpPolicyDecision(
                allowed=False,
                reason="missing_path_argument",
                policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
            )
        if ".." in path or path.startswith("/") or "\\" in path:
            return McpPolicyDecision(
                allowed=False,
                reason="path_traversal_forbidden",
                policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
            )
        if not re.match(r"^[\w.\-/]+$", path):
            return McpPolicyDecision(
                allowed=False,
                reason="invalid_path_characters",
                policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
            )

    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
    )


def evaluate_exploitation_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """Evaluate Stage 4 Exploitation MCP policy.

    Allows exploitation tools (metasploit, sqlmap, nuclei, hydra, etc.).
    Blocks destructive patterns (DROP TABLE, rm -rf, etc.).
    """
    normalized_tool = str(tool_name or "").strip().lower()
    normalized_operation = str(operation or "").strip().lower()

    if normalized_tool not in EXPLOITATION_ALLOWED_TOOLS:
        return McpPolicyDecision(
            allowed=False,
            reason="tool_not_allowlisted",
            policy_id=EXPLOITATION_POLICY_ID,
        )
    if normalized_operation not in EXPLOITATION_ALLOWED_OPERATIONS:
        return McpPolicyDecision(
            allowed=False,
            reason="operation_not_allowlisted",
            policy_id=EXPLOITATION_POLICY_ID,
        )

    searchable_blob = " ".join(
        [
            normalized_operation,
            json.dumps(sanitize_args(args), ensure_ascii=True, default=str).lower(),
        ]
    )
    for marker in EXPLOITATION_BLOCKED_PATTERNS:
        if marker.lower() in searchable_blob:
            return McpPolicyDecision(
                allowed=False,
                reason=f"denylist_keyword:{marker}",
                policy_id=EXPLOITATION_POLICY_ID,
            )

    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=EXPLOITATION_POLICY_ID,
    )


# ---------------------------------------------------------------------------
# KAL-002 — MCP gated scanner categories (fail-closed argv allowlist per category)
# ---------------------------------------------------------------------------

KAL_MCP_POLICY_ID = "kal_mcp_gated_tools_v1"

# KAL-006/007 — bounded Exploit-DB CLI from recon (argv policy via evaluate_kal_mcp_policy)
KAL_CATEGORY_VULN_INTEL = "vuln_intel"

KAL_OPERATION_CATEGORIES = frozenset({
    "network_scanning",
    "web_fingerprinting",
    "api_testing",
    "bruteforce_testing",
    "ssl_analysis",
    "dns_enumeration",
    "password_audit",
    KAL_CATEGORY_VULN_INTEL,
})

KAL_CATEGORY_ALLOWED_BINARIES: dict[str, frozenset[str]] = {
    "network_scanning": frozenset({"nmap", "rustscan", "masscan"}),
    "web_fingerprinting": frozenset({"httpx", "whatweb", "wpscan", "nikto"}),
    "api_testing": frozenset({"httpx", "nuclei", "curl"}),
    "bruteforce_testing": frozenset({
        "gobuster",
        "feroxbuster",
        "dirsearch",
        "ffuf",
        "wfuzz",
        "dirb",
    }),
    "ssl_analysis": frozenset({"openssl", "testssl.sh"}),
    "dns_enumeration": frozenset({
        "dig",
        "subfinder",
        "amass",
        "dnsx",
        "host",
        "nslookup",
        "dnsrecon",
        "fierce",
    }),
    "password_audit": frozenset({"hydra", "medusa"}),
    KAL_CATEGORY_VULN_INTEL: frozenset({"searchsploit"}),
}

KAL_OPENSSL_ALLOWED_SUBCOMMANDS = frozenset({"s_client", "s_time", "version", "ciphers"})

# KAL-005 — amass: only vetted subcommands (fail-closed)
KAL_AMASS_ALLOWED_SUBCOMMANDS = frozenset({"enum"})

_KAL_ARGV_INJECTION_PATTERN = re.compile(
    r"[`$]|\$\(|;\s*|\|\s*|&&\s*|\n|\r|<\(|>\("
)


def normalize_kal_binary(argv0: str) -> str:
    """First argv segment basename, lowercase; testssl.sh kept distinct."""
    raw = str(argv0 or "").strip()
    if not raw:
        return ""
    base = raw.rsplit("/", 1)[-1].strip().lower()
    if base == "testssl.sh" or base.startswith("testssl"):
        return "testssl.sh"
    return base


def kal_argv_has_injection_risk(argv: list[str]) -> bool:
    """True if any argument looks like shell metacharacters (list execution; no shell)."""
    for a in argv:
        s = str(a)
        if _KAL_ARGV_INJECTION_PATTERN.search(s):
            return True
    return False


def evaluate_kal_mcp_policy(
    *,
    category: str,
    argv: list[str],
    password_audit_opt_in: bool,
    server_password_audit_enabled: bool,
) -> McpPolicyDecision:
    """Fail-closed: category must map to tool; hydra/medusa only for password_audit + double opt-in."""
    cat = str(category or "").strip().lower().replace("-", "_")
    if cat not in KAL_OPERATION_CATEGORIES:
        return McpPolicyDecision(
            allowed=False,
            reason="unknown_category",
            policy_id=KAL_MCP_POLICY_ID,
        )
    if not argv or not isinstance(argv, list):
        return McpPolicyDecision(
            allowed=False,
            reason="empty_argv",
            policy_id=KAL_MCP_POLICY_ID,
        )
    if kal_argv_has_injection_risk(argv):
        return McpPolicyDecision(
            allowed=False,
            reason="argv_injection_pattern",
            policy_id=KAL_MCP_POLICY_ID,
        )

    binary = normalize_kal_binary(argv[0])
    if not binary:
        return McpPolicyDecision(
            allowed=False,
            reason="missing_binary",
            policy_id=KAL_MCP_POLICY_ID,
        )

    allowed_for_cat = KAL_CATEGORY_ALLOWED_BINARIES.get(cat, frozenset())
    if binary not in allowed_for_cat:
        return McpPolicyDecision(
            allowed=False,
            reason="tool_not_allowed_for_category",
            policy_id=KAL_MCP_POLICY_ID,
        )

    if binary in ("hydra", "medusa"):
        if cat != "password_audit":
            return McpPolicyDecision(
                allowed=False,
                reason="password_tools_only_in_password_audit_category",
                policy_id=KAL_MCP_POLICY_ID,
            )
        if not password_audit_opt_in or not server_password_audit_enabled:
            return McpPolicyDecision(
                allowed=False,
                reason="password_audit_opt_in_required",
                policy_id=KAL_MCP_POLICY_ID,
            )

    if binary == "openssl":
        if len(argv) < 2:
            return McpPolicyDecision(
                allowed=False,
                reason="openssl_missing_subcommand",
                policy_id=KAL_MCP_POLICY_ID,
            )
        sub = str(argv[1]).strip().lower()
        if sub not in KAL_OPENSSL_ALLOWED_SUBCOMMANDS:
            return McpPolicyDecision(
                allowed=False,
                reason="openssl_subcommand_not_allowed",
                policy_id=KAL_MCP_POLICY_ID,
            )

    if binary == "amass":
        if len(argv) < 2:
            return McpPolicyDecision(
                allowed=False,
                reason="amass_missing_subcommand",
                policy_id=KAL_MCP_POLICY_ID,
            )
        sub_amass = str(argv[1]).strip().lower()
        if sub_amass not in KAL_AMASS_ALLOWED_SUBCOMMANDS:
            return McpPolicyDecision(
                allowed=False,
                reason="amass_subcommand_not_allowed",
                policy_id=KAL_MCP_POLICY_ID,
            )

    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=KAL_MCP_POLICY_ID,
    )
