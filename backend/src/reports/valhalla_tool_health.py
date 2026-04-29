"""Valhalla customer-facing tool status: capability mapping and string sanitization (VH-004).

Strips host paths, Docker socket references, and verbose stderr from strings shown in PDF/HTML.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

_DOCKER_NOISE = re.compile(
    r"docker|containerd|/var/run/docker|docker\.sock|com\.docker|moby|"
    r"\\\.docker|daemon\.json|Error response from daemon",
    re.IGNORECASE,
)
_WIN_UNIX_PATH = re.compile(
    r"(?:[A-Za-z]:\\|/)(?:usr|var|opt|tmp|home|root|AppData|Program Files)[^\s,;|]{0,200}",
)
_MINIO_S3 = re.compile(
    r"minio|s3://|amazonaws\.com/[^\s]+|presigned|X-Amz-",
    re.IGNORECASE,
)
_JSON_BLOB = re.compile(r"\{[^{}]{20,800}\}")

CapabilityId = Literal[
    "dns_asn",
    "url_history",
    "port_discovery",
    "tls_assessment",
    "security_headers",
    "email_osint",
    "sca_dependencies",
    "technology_fingerprinting",
    "web_server_scan",
    "vuln_active_scan",
    "other",
]

_CAP_ALIASES: dict[str, tuple[CapabilityId, str]] = {
    "amass": ("dns_asn", "DNS / surface / ASN (recon)"),
    "subfinder": ("dns_asn", "DNS / surface / ASN (recon)"),
    "sublist3r": ("dns_asn", "DNS / surface / ASN (recon)"),
    "theharvester": ("email_osint", "Email / OSINT"),
    "the_harvester": ("email_osint", "Email / OSINT"),
    "harvester": ("email_osint", "Email / OSINT"),
    "httpx": ("url_history", "URL / live host discovery"),
    "httprobe": ("url_history", "URL / live host discovery"),
    "gau": ("url_history", "URL / history (passive)"),
    "nmap": ("port_discovery", "Port & service mapping"),
    "naabu": ("port_discovery", "Port & service mapping"),
    "masscan": ("port_discovery", "Port & service mapping"),
    "testssl": ("tls_assessment", "TLS / SSL configuration"),
    "testssl.sh": ("tls_assessment", "TLS / SSL configuration"),
    "sslscan": ("tls_assessment", "TLS / SSL configuration"),
    "sslyze": ("tls_assessment", "TLS / SSL configuration"),
    "tlsx": ("tls_assessment", "TLS / SSL configuration"),
    "nikto": ("web_server_scan", "Web server / misconfiguration scan"),
    "whatweb": ("technology_fingerprinting", "Technology fingerprinting"),
    "nuclei": ("vuln_active_scan", "Active pattern / template scanning"),
    "trivy": ("sca_dependencies", "SCA / dependency & image scanning"),
    "safety": ("sca_dependencies", "SCA / dependency (Python)"),
    "pip-audit": ("sca_dependencies", "SCA / dependency (Python)"),
    "npm": ("sca_dependencies", "SCA / dependency (npm)"),
}

_TOOL_DISPLAY_NAMES: dict[str, str] = {
    "amass": "Amass",
    "subfinder": "Subfinder",
    "sublist3r": "Sublist3r",
    "theharvester": "theHarvester",
    "the_harvester": "theHarvester",
    "harvester": "theHarvester",
    "httpx": "httpx",
    "httprobe": "httprobe",
    "gau": "gau",
    "wayback": "waybackurls",
    "katana": "Katana",
    "nmap": "Nmap",
    "naabu": "Naabu",
    "masscan": "Masscan",
    "testssl": "testssl.sh",
    "sslscan": "sslscan",
    "sslyze": "SSLyze",
    "tlsx": "tlsx",
    "nikto": "Nikto",
    "whatweb": "WhatWeb",
    "nuclei": "Nuclei",
    "trivy": "Trivy",
    "safety": "Safety",
    "pipaudit": "pip-audit",
    "npm": "npm audit",
}


def row_has_docker_or_infra_noise(row: dict[str, str] | None) -> bool:
    if not row:
        return False
    blob = " ".join(
        str(row.get(k) or "")
        for k in ("tool", "status", "note")
    )
    return bool(_DOCKER_NOISE.search(blob))


def sanitize_customer_tool_text(text: str, *, max_len: int = 320) -> str:
    """Remove paths, MinIO/S3 references, and JSON blobs; collapse whitespace."""
    s = (text or "").strip()
    if not s:
        return ""
    s = _WIN_UNIX_PATH.sub("[path]", s)
    s = _MINIO_S3.sub("[storage]", s)
    s = _JSON_BLOB.sub("[structured output omitted]", s)
    s = s.replace("\\\\", "/")
    # Residual long hex / base64-like tokens (common in stderr)
    s = re.sub(r"\b[0-9a-fA-F]{32,}\b", "[token]", s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s


def _norm_tool_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def _capability_for_tool(tool: str) -> tuple[CapabilityId, str]:
    key = _norm_tool_name(tool)
    for alias, (cid, label) in _CAP_ALIASES.items():
        if alias in key or key in alias:
            return cid, label
    return "other", "Tool execution (general)"


def _display_tool_name(tool: str) -> str:
    key = _norm_tool_name(tool)
    for alias, label in _TOOL_DISPLAY_NAMES.items():
        if alias in key or key in alias:
            return label
    cleaned = re.sub(r"(?i)(?:^|_)(?:scan|tool|va|web_surface|stdout|stderr).*$", "", tool or "")
    cleaned = re.sub(r"[_-]{2,}", "_", cleaned).strip("_- ")
    return sanitize_customer_tool_text(cleaned or tool, max_len=80)


ToolHealthState = Literal[
    "ok",
    "ok_fallback",
    "degraded",
    "parser_error",
    "not_assessed",
    "not_run",
    "skipped",
]

_CAPABILITY_MANDATORY_SECTIONS: dict[CapabilityId, tuple[str, ...]] = {
    "port_discovery": ("port_exposure",),
    "tls_assessment": ("ssl_tls_analysis",),
    "security_headers": ("security_headers_analysis",),
    "email_osint": ("leaked_emails",),
    "sca_dependencies": ("outdated_components",),
    "technology_fingerprinting": ("tech_stack_structured",),
    "web_server_scan": ("security_headers_analysis", "tech_stack_structured"),
}

_SECTION_DISPLAY: dict[str, str] = {
    "tech_stack_structured": "technology stack",
    "ssl_tls_analysis": "TLS assessment",
    "security_headers_analysis": "security headers",
    "leaked_emails": "email exposure",
    "port_exposure": "port exposure",
    "outdated_components": "dependency/SCA",
}

_STATUS_FAILED = frozenset({"failed", "error", "timeout", "cancelled", "canceled", "aborted", "no_output"})
_STATUS_OK = frozenset(
    {
        "success",
        "succeeded",
        "completed",
        "complete",
        "ok",
        "finished",
        "done",
    }
)


@dataclass(frozen=True, slots=True)
class ToolHealthCapabilityRow:
    capability: str
    capability_id: str
    representative_tools: str
    state: ToolHealthState
    customer_summary: str


def build_tool_health_summary_rows(
    *,
    tool_run_summaries: list[tuple[str, str]] | None,
    appendix_tool_names: list[str] | None,
    raw_error_rows: list[dict[str, str]] | None,
    mandatory_section_status: dict[str, str] | None = None,
) -> list[ToolHealthCapabilityRow]:
    """Build one row per capability from tool names + run statuses; customer-safe text only."""
    by_cap: dict[CapabilityId, dict[str, Any]] = {}

    def ensure(cid: CapabilityId, label: str) -> dict[str, Any]:
        if cid not in by_cap:
            by_cap[cid] = {
                "label": label,
                "tools": set(),
                "any_ok": False,
                "any_fail": False,
                "any_fallback": False,
            }
        return by_cap[cid]

    name_to_status: dict[str, str] = {}
    if tool_run_summaries:
        for name, st in tool_run_summaries:
            n = (name or "").strip()
            if n:
                name_to_status[n.lower()] = (st or "").strip().lower()

    names: list[str] = list(appendix_tool_names or [])
    for n, _ in (tool_run_summaries or []):
        if n and n.strip():
            names.append(n.strip())
    # Unique preserve order
    seen_n: set[str] = set()
    ordered: list[str] = []
    for n in names:
        k = n.lower()
        if k in seen_n:
            continue
        seen_n.add(k)
        ordered.append(n)

    err_by_tool: dict[str, str] = {}
    for row in raw_error_rows or []:
        t = str(row.get("tool") or "").strip()
        if t:
            err_by_tool[t.lower()] = sanitize_customer_tool_text(
                f"{row.get('status', '')} {row.get('note', '')}"
            )
            cid, label = _capability_for_tool(t)
            bucket = ensure(cid, label)
            bucket["tools"].add(_display_tool_name(t))
            bucket["any_fail"] = True

    for tool in ordered:
        cid, label = _capability_for_tool(tool)
        bucket = ensure(cid, label)
        bucket["tools"].add(_display_tool_name(tool))
        st = name_to_status.get(tool.lower(), "")
        st_low = (st or "").lower()
        if st_low in _STATUS_OK or (st_low and st_low not in _STATUS_FAILED and "fail" not in st_low):
            bucket["any_ok"] = True
        if st_low in _STATUS_FAILED or "fail" in st_low:
            bucket["any_fail"] = True
        note = err_by_tool.get(tool.lower(), "")
        if note and "stderr" in note.lower() and "empty" in note.lower():
            bucket["any_fallback"] = True

    rows: list[ToolHealthCapabilityRow] = []
    mandatory = {str(k): str(v or "").strip().lower() for k, v in (mandatory_section_status or {}).items()}
    for cid, data in sorted(by_cap.items(), key=lambda x: (x[1]["label"] or "").lower()):
        label = str(data["label"])
        tools_str = ", ".join(sorted(data["tools"]))[:500]
        if data["any_fail"] and data["any_ok"]:
            state: ToolHealthState = "degraded"
            summary = "Mixed results: at least one tool in this group completed; others failed or returned no data."
        elif data["any_fallback"]:
            state = "ok_fallback"
            summary = "Completed with fallback: output may be partial (stderr only or exit code non-zero while partial data was recovered)."
        elif data["any_fail"] and not data["any_ok"]:
            state = "degraded"
            summary = "Execution did not complete successfully for this capability group; treat related sections as not fully assessed."
        else:
            state = "ok"
            summary = "Tool output available for this capability where applicable; see technical sections for parsed results."

        mapped_sections = _CAPABILITY_MANDATORY_SECTIONS.get(cid, ())
        mapped_statuses = {section: mandatory.get(section, "") for section in mapped_sections}
        if any(status in {"completed_with_fallback", "parsed_from_fallback"} for status in mapped_statuses.values()):
            if state == "ok":
                state = "ok_fallback"
            summary = "Completed with parsed fallback data; see related technical section for evidence and limitations."
        if any(status == "no_observed_items_after_parsing" for status in mapped_statuses.values()):
            if state == "ok":
                summary = "Completed: artifacts were parsed and no relevant observed items were found."
        if any(status in {"not_assessed", "no_data"} for status in mapped_statuses.values()):
            names = ", ".join(
                _SECTION_DISPLAY.get(section, section)
                for section, status in mapped_statuses.items()
                if status in {"not_assessed", "no_data"}
            )
            if data["any_ok"]:
                state = "degraded"
                summary = (
                    "Tool execution metadata indicates completion, but no parsed customer-facing data was "
                    f"produced for {names or 'this capability'}; treat this as inconclusive."
                )
            else:
                state = "not_assessed"
                summary = (
                    "No conclusion can be drawn because the parsed report section"
                    f" for {names or 'this capability'} is not assessed."
                )
        elif any(status == "parser_error" for status in mapped_statuses.values()):
            state = "parser_error"
            summary = "Parser output for this capability is empty or inconsistent despite related artifacts; treat as inconclusive."
        elif any(status == "partial" for status in mapped_statuses.values()):
            state = "degraded"
            summary = "Parsed evidence for this capability is partial; no full-domain conclusion can be drawn."
        elif mapped_statuses and all(status == "not_executed" for status in mapped_statuses.values()):
            state = "not_run"
            summary = "The related assessment domain was not executed for this run."

        rows.append(
            ToolHealthCapabilityRow(
                capability=label,
                capability_id=cid,
                representative_tools=tools_str,
                state=state,
                customer_summary=sanitize_customer_tool_text(summary, max_len=400),
            )
        )

    if not rows and (appendix_tool_names or tool_run_summaries):
        rows.append(
            ToolHealthCapabilityRow(
                capability="Tool execution (general)",
                capability_id="other",
                representative_tools="—",
                state="not_run",
                customer_summary="No capability mapping recorded for this run.",
            )
        )
    return rows


def tool_health_rows_to_jinja(
    rows: list[ToolHealthCapabilityRow] | None,
) -> list[dict[str, Any]]:
    if not rows:
        return []
    out: list[dict[str, Any]] = []
    for r in rows:
        state = r.state
        display = {
            "ok": "Completed",
            "ok_fallback": "Completed with fallback",
            "degraded": "Partial / inconclusive",
            "parser_error": "Parser error / inconclusive",
            "not_assessed": "Not assessed",
            "not_run": "Not run",
            "skipped": "Skipped",
        }.get(state, state)
        out.append(
            {
                "capability": r.capability,
                "capability_id": r.capability_id,
                "tools": r.representative_tools,
                "state": state,
                "state_label": display,
                "summary": r.customer_summary,
            }
        )
    return out


def any_docker_setup_noise_in_tool_rows(rows: list[dict[str, str]] | None) -> bool:
    for row in rows or []:
        if row_has_docker_or_infra_noise(row):
            return True
    return False


def summarize_tool_error_rows_for_internal(rows: list[dict[str, str]] | None) -> list[dict[str, str]]:
    """Copy of rows with sanitized `note` for any customer surface (legacy)."""
    out: list[dict[str, str]] = []
    for row in rows or []:
        out.append(
            {
                "tool": str(row.get("tool") or "")[:200],
                "status": str(row.get("status") or "")[:80],
                "note": sanitize_customer_tool_text(str(row.get("note") or ""), max_len=240),
            }
        )
    return out
