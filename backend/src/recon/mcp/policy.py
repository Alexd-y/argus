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
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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
