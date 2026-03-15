"""Professional HTML report builder for ARGUS Stage 1 recon.

Generates a single HTML file with 18 sections (REC-010): executive summary,
scope/methodology, DNS findings, subdomain classification, DNS validation,
live hosts, tech profile, JS/frontend, parameters, API surface, headers/TLS,
content similarity, anomaly validation, Stage 2 preparation, Tools & AI,
Intel/OSINT, Stage 3 readiness, route classification.

All major findings have Evidence/Observation/Inference/Hypothesis badges.
Reads all generated artifacts from recon_dir. Output: embedded CSS, print-friendly.
"""

import csv
import html
import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path

from src.recon.parsers import parse_cname, parse_resolved

logger = logging.getLogger(__name__)

# CSS for professional, print-friendly report
_REPORT_CSS = """
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1.5rem; line-height: 1.6; color: #1a1a2e; }
h1 { color: #0d47a1; font-size: 1.75rem; margin-bottom: 0.25rem; border-bottom: 2px solid #1976d2; padding-bottom: 0.5rem; }
h2 { color: #1565c0; font-size: 1.25rem; margin-top: 2rem; margin-bottom: 0.75rem; }
h3 { color: #1976d2; font-size: 1.1rem; margin-top: 1.25rem; }
.meta { color: #546e7a; font-size: 0.9rem; margin-bottom: 2rem; padding: 1rem; background: #eceff1; border-radius: 6px; }
.section { margin-top: 1.5rem; padding: 1.25rem; background: #fafafa; border: 1px solid #e0e0e0; border-radius: 6px; break-inside: avoid; }
.section h2 { margin-top: 0; }
table { width: 100%; border-collapse: collapse; margin: 0.75rem 0; font-size: 0.9rem; }
th, td { border: 1px solid #bdbdbd; padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; }
th { background: #e3f2fd; font-weight: 600; color: #0d47a1; }
tr:nth-child(even) { background: #f5f5f5; }
pre, code { background: #eceff1; padding: 0.15rem 0.4rem; font-family: 'Consolas', 'Monaco', monospace; font-size: 0.85em; border-radius: 3px; }
pre { padding: 1rem; overflow-x: auto; white-space: pre-wrap; margin: 0.5rem 0; }
ul { margin: 0.5rem 0 0 1.25rem; }
.evidence { border-left: 4px solid #4caf50; padding-left: 1rem; margin: 0.5rem 0; }
.observation { border-left: 4px solid #9c27b0; padding-left: 1rem; margin: 0.5rem 0; }
.inference { border-left: 4px solid #2196f3; padding-left: 1rem; margin: 0.5rem 0; }
.hypothesis { border-left: 4px solid #ff9800; padding-left: 1rem; margin: 0.5rem 0; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
.badge-high { background: #ffebee; color: #c62828; }
.badge-medium { background: #fff3e0; color: #e65100; }
.badge-low { background: #e8f5e9; color: #2e7d32; }
.badge-evidence { background: #e8f5e9; color: #2e7d32; margin-bottom: 0.25rem; }
.badge-observation { background: #f3e5f5; color: #7b1fa2; margin-bottom: 0.25rem; }
.badge-inference { background: #e3f2fd; color: #1565c0; margin-bottom: 0.25rem; }
.badge-hypothesis { background: #fff3e0; color: #e65100; margin-bottom: 0.25rem; }
.source-citation { font-size: 0.85rem; color: #546e7a; margin-top: 0.75rem; font-style: italic; }
@media print { body { max-width: none; } .section { break-inside: avoid; box-shadow: none; } .evidence, .observation, .inference, .hypothesis, .badge-evidence, .badge-observation, .badge-inference, .badge-hypothesis { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
"""


def _escape(s: str) -> str:
    """Escape HTML entities for safe output."""
    return html.escape(str(s), quote=True)


_ALLOWED_TAXONOMY_TYPES = {"evidence", "observation", "inference", "hypothesis"}
_ALLOWED_PRIORITIES = {"high", "medium", "low"}


def _normalize_taxonomy_type(value: str | None, default: str = "observation") -> str:
    """Return safe taxonomy type for CSS class usage."""
    normalized_default = str(default).strip().lower()
    if normalized_default not in _ALLOWED_TAXONOMY_TYPES:
        normalized_default = "observation"
    candidate = str(value or "").strip().lower()
    if candidate in _ALLOWED_TAXONOMY_TYPES:
        return candidate
    return normalized_default


def _normalize_priority(value: str | None, default: str = "low") -> str:
    """Return safe priority for CSS class usage."""
    normalized_default = str(default).strip().lower()
    if normalized_default not in _ALLOWED_PRIORITIES:
        normalized_default = "low"
    candidate = str(value or "").strip().lower()
    if candidate in _ALLOWED_PRIORITIES:
        return candidate
    return normalized_default


def _source_block(sources: str | list[str]) -> str:
    """Render source citation block. Returns <p class="source-citation">Source: path(s)</p>."""
    text = ", ".join(sources) if isinstance(sources, list) else sources
    if not text:
        return ""
    return f'<p class="source-citation">Source: {_escape(text)}</p>'


def _read_text(path: Path, default: str = "") -> str:
    """Read text file. Returns default if missing."""
    if not path.exists():
        return default
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError as e:
        logger.warning("Failed to read file", extra={"path": str(path), "error": str(e)})
        return default


def _load_csv(path: Path) -> list[dict]:
    """Load CSV into list of dicts."""
    if not path.exists():
        return []
    try:
        with path.open(encoding="utf-8", errors="replace", newline="") as f:
            return list(csv.DictReader(f))
    except (OSError, csv.Error) as e:
        logger.warning("Failed to load CSV", extra={"path": str(path), "error": str(e)})
        return []


def _load_anomalies_structured(path: Path) -> dict | None:
    """Load anomalies_structured.json. Returns None if missing or invalid."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Failed to load anomalies_structured", extra={"path": str(path), "error": str(e)})
        return None


def _load_stage2_structured(path: Path) -> dict | None:
    """Load stage2_structured.json. Returns None if missing or invalid."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Failed to load stage2_structured", extra={"path": str(path), "error": str(e)})
        return None


def _load_intel_findings(path: Path) -> dict | None:
    """Load intel_findings.json. Returns None if missing or invalid."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Failed to load intel_findings", extra={"path": str(path), "error": str(e)})
        return None


def _load_stage3_readiness(path: Path) -> dict | None:
    """Load stage3_readiness.json. Returns None if missing or invalid."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Failed to load stage3_readiness", extra={"path": str(path), "error": str(e)})
        return None


def _render_stage2_from_structured(structured: dict) -> str:
    """Render Stage 2 recommendations from structured JSON with type and source citations.

    Each subsection is wrapped in its own block with correct type (hypothesis/inference/observation).
    """
    out: list[str] = []

    def _render_section(
        title: str,
        items: list,
        block_type: str,
        code_items: bool = False,
    ) -> None:
        normalized_block_type = _normalize_taxonomy_type(block_type)
        out.append(f'<div class="{normalized_block_type}">')
        out.append(f'<span class="badge badge-{normalized_block_type}">{_escape(normalized_block_type)}</span>')
        out.append(f"<h3>{_escape(title)}</h3>")
        if not items:
            out.append("<p><em>No items.</em></p>")
            out.append("</div>")
            return
        out.append("<ul>")
        for item in items:
            i_type = _normalize_taxonomy_type(item.get("type"), default=normalized_block_type)
            source = item.get("source", "")
            text = item.get("text", "")
            priority = item.get("priority", "")
            out.append(f'<li class="{i_type}">')
            out.append(f'<span class="badge badge-{i_type}">{_escape(i_type)}</span>')
            if source:
                out.append(f'<span class="badge" style="background:#e0e0e0;color:#424242;">{_escape(source)}</span> ')
            if priority:
                safe_priority = _normalize_priority(priority)
                out.append(f'<span class="badge badge-{safe_priority}">{_escape(safe_priority)}</span> ')
            if code_items:
                out.append(f"<code>{_escape(text)}</code>")
            else:
                out.append(_escape(text))
            out.append("</li>")
        out.append("</ul>")
        out.append("</div>")

    _render_section("Priority Hypotheses", structured.get("priority_hypotheses", []), "hypothesis")
    _render_section("Candidate Trust Boundaries", structured.get("trust_boundaries", []), "inference")
    _render_section("Candidate Critical Assets", structured.get("critical_assets", []), "observation", code_items=True)
    _render_section("Candidate Entry Points", structured.get("entry_points", []), "hypothesis", code_items=True)

    return "\n".join(out)


def _render_anomalies_from_structured(structured: dict) -> str:
    """Render anomalies section from structured JSON with taxonomy labels and citations."""
    anomalies = structured.get("anomalies", [])
    hypotheses = structured.get("hypotheses", [])

    out: list[str] = []
    out.append("<h3>Detected Anomalies</h3>")
    if not anomalies:
        out.append("<p><em>No anomalies detected.</em></p>")
    else:
        for a in anomalies:
            a_type = _normalize_taxonomy_type(a.get("type"), default="observation")
            source = a.get("source", "")
            out.append(f'<div class="{a_type}">')
            out.append(f'<span class="badge badge-{a_type}">{_escape(a_type)}</span>')
            if source:
                out.append(f'<span class="badge" style="background:#e0e0e0;color:#424242;">{_escape(source)}</span>')
            out.append("<ul>")
            for key in ("host", "status", "server", "description"):
                val = a.get(key)
                if val is not None and val != "":
                    out.append(f"<li><strong>{key}:</strong> {_escape(str(val))}</li>")
            out.append("</ul>")
            out.append("</div>")

    out.append("<h3>Hypotheses for Threat Modeling</h3>")
    if not hypotheses:
        out.append("<p><em>No hypotheses.</em></p>")
    else:
        out.append("<ul>")
        for h in hypotheses:
            h_type = _normalize_taxonomy_type(h.get("type"), default="hypothesis")
            source = h.get("source", "")
            text = h.get("text", "")
            out.append('<li class="hypothesis">')
            out.append(f'<span class="badge badge-{h_type}">{_escape(h_type)}</span>')
            if source:
                out.append(f'<span class="badge" style="background:#e0e0e0;color:#424242;">{_escape(source)}</span> ')
            out.append(_escape(text))
            out.append("</li>")
        out.append("</ul>")

    return "\n".join(out)


def _split_dns_summary_by_taxonomy(text: str) -> dict[str, str]:
    """Split dns_summary.md into Evidence, Observation, Inference blocks.

    Evidence: raw A/MX/TXT/CAA/NS records, Nameservers, Resolved list, WHOIS.
    Observation: SPF/DKIM/DMARC, Resolved vs Unresolved counts, Third-Party Infrastructure.
    Inference: Wildcard DNS, Dangling CNAME candidates.
    """
    if not text:
        return {"evidence": "", "observation": "", "inference": ""}

    sections = re.split(r"\n(?=## )", text)
    evidence_parts: list[str] = []
    observation_parts: list[str] = []
    inference_parts: list[str] = []

    for block in sections:
        block = block.strip()
        if not block:
            continue
        first_line = block.split("\n")[0]
        if "## Record Summary" in first_line or "## Nameservers" in first_line:
            evidence_parts.append(block)
        elif "## SPF / DKIM / DMARC" in first_line:
            observation_parts.append(block)
        elif "## Resolved vs Unresolved" in first_line:
            idx_resolved = block.find("### Resolved")
            if idx_resolved >= 0:
                obs_part = block[:idx_resolved].strip()
                ev_part = block[idx_resolved:].strip()
                if obs_part:
                    observation_parts.append(obs_part)
                if ev_part:
                    evidence_parts.append(ev_part)
            else:
                observation_parts.append(block)
        elif "## Wildcard DNS" in first_line:
            inference_parts.append(block)
        elif "## Third-Party Infrastructure" in first_line:
            observation_parts.append(block)
        elif "## Suspicious / Dangling CNAME" in first_line or "## Dangling CNAME" in first_line:
            inference_parts.append(block)
        elif "## WHOIS" in first_line:
            evidence_parts.append(block)

    return {
        "evidence": "\n\n".join(evidence_parts),
        "observation": "\n\n".join(observation_parts),
        "inference": "\n\n".join(inference_parts),
    }


def _md_to_html(text: str) -> str:
    """Convert basic markdown to HTML. Escapes content, handles headers, lists, code, tables."""
    if not text:
        return ""
    lines = text.splitlines()
    out: list[str] = []
    in_list = False
    in_table = False
    table_rows: list[list[str]] = []

    def flush_table() -> None:
        nonlocal table_rows, in_table
        if not table_rows:
            return
        out.append("<table>")
        for i, row in enumerate(table_rows):
            tag = "th" if i == 0 else "td"
            cells = "".join(f"<{tag}>{_escape(c.strip())}</{tag}>" for c in row)
            out.append(f"<tr>{cells}</tr>")
        out.append("</table>")
        table_rows = []
        in_table = False

    for line in lines:
        stripped = line.strip()
        # Table row: | a | b |
        if "|" in stripped and stripped.startswith("|") and stripped.endswith("|"):
            if in_list:
                in_list = False
                out.append("</ul>")
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if cells and any(c.replace("-", "").strip() for c in cells):
                table_rows.append(cells)
                in_table = True
            continue
        elif in_table and table_rows:
            flush_table()

        # Headers
        if stripped.startswith("### "):
            if in_list:
                in_list = False
                out.append("</ul>")
            out.append(f"<h4>{_escape(stripped[4:])}</h4>")
            continue
        if stripped.startswith("## "):
            if in_list:
                in_list = False
                out.append("</ul>")
            out.append(f"<h3>{_escape(stripped[3:])}</h3>")
            continue
        if stripped.startswith("# "):
            if in_list:
                in_list = False
                out.append("</ul>")
            out.append(f"<h2>{_escape(stripped[2:])}</h2>")
            continue

        # List item
        if stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            content = stripped[2:]
            content = re.sub(r"`([^`]+)`", lambda m: f"<code>{_escape(m.group(1))}</code>", content)
            content = re.sub(r"\*\*([^*]+)\*\*", lambda m: f"<strong>{_escape(m.group(1))}</strong>", content)
            placeholders: list[str] = []

            def _protect(m: re.Match[str], _ph: list[str] = placeholders) -> str:
                _ph.append(m.group(0))
                return f"\u0001P{len(_ph) - 1}\u0001"
            content = re.sub(r"<code>[^<]*</code>|<strong>[^<]*</strong>", _protect, content)
            content = _escape(content)
            for i, p in enumerate(placeholders):
                content = content.replace(f"\u0001P{i}\u0001", p)
            out.append(f"<li>{content}</li>")
            continue
        elif in_list:
            in_list = False
            out.append("</ul>")

        # Empty line
        if not stripped:
            out.append("<p></p>")
            continue

        # Paragraph with inline formatting
        content = _escape(stripped)
        content = re.sub(r"`([^`]+)`", r"<code>\1</code>", content)
        content = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", content)
        out.append(f"<p>{content}</p>")

    if in_list:
        out.append("</ul>")
    if in_table and table_rows:
        flush_table()

    return "\n".join(out)


def _derive_target_domain(recon_dir: Path) -> str:
    """Extract target domain from scope.txt, targets.txt, or directory name."""
    scope_path = recon_dir / "00_scope" / "scope.txt"
    text = _read_text(scope_path)
    m = re.search(r"Target:\s*([^\s#\n]+)", text, re.I)
    if m:
        return m.group(1).strip()
    targets_path = recon_dir / "00_scope" / "targets.txt"
    text = _read_text(targets_path)
    m = re.search(r"Primary Domain\s*\n\s*([^\s#\n]+)", text, re.I)
    if m:
        return m.group(1).strip()
    name = recon_dir.name
    if "-stage" in name.lower():
        return name.split("-")[0]
    return name or "unknown"


def _csv_to_html_table(rows: list[dict], columns: list[str] | None = None) -> str:
    """Convert CSV rows to HTML table. Uses first row keys as headers if columns not given."""
    if not rows:
        return "<p><em>No data.</em></p>"
    cols = columns or list(rows[0].keys())
    out = ["<table>", "<thead><tr>" + "".join(f"<th>{_escape(c)}</th>" for c in cols) + "</tr></thead>", "<tbody>"]
    for row in rows:
        cells = [str(row.get(c, ""))[:200] for c in cols]
        out.append("<tr>" + "".join(f"<td>{_escape(c)}</td>" for c in cells) + "</tr>")
    out.append("</tbody></table>")
    return "\n".join(out)


def _build_tools_ai_section(tools_ai_metadata: dict | None, mcp_used: bool) -> str:
    """Build Tools & AI Used section HTML."""
    parts: list[str] = []

    # MCP tools
    mcp_tools: list[str] = []
    if mcp_used:
        mcp_tools.append("mcp-server-fetch: <code>fetch</code> — endpoint discovery (robots.txt, sitemap.xml, security.txt, favicon.ico, manifest.json)")
    mcp_tools.append("ARGUS MCP server (argus-mcp container): available for Cursor/IDE — create_scan, subfinder, httpx, nuclei, etc.")

    parts.append("<h3>MCP Tools</h3>")
    parts.append("<ul>")
    for t in mcp_tools:
        parts.append(f"<li>{_escape(t)}</li>")
    parts.append("</ul>")

    # AI
    if tools_ai_metadata:
        provider = tools_ai_metadata.get("ai_provider", "Unknown")
        model = tools_ai_metadata.get("ai_model", "")
        parts.append("<h3>AI Used</h3>")
        parts.append(f"<p><strong>Provider:</strong> {_escape(provider)}")
        if model:
            parts.append(f" | <strong>Model:</strong> {_escape(model)}")
        parts.append("</p>")

        prompts = tools_ai_metadata.get("prompts_used", [])
        if prompts:
            parts.append("<h4>Prompts</h4>")
            for i, p in enumerate(prompts, 1):
                name = p.get("name", f"Prompt {i}")
                desc = p.get("description", "")
                parts.append(f"<p><strong>{_escape(name)}:</strong></p>")
                parts.append(f"<pre>{_escape(desc[:800])}{'...' if len(desc) > 800 else ''}</pre>")
    else:
        parts.append("<h3>AI Used</h3>")
        parts.append("<p><em>No AI configured (LLM keys not set). Rule-based analysis used.</em></p>")

    return "\n".join(parts)


def build_html_report(
    recon_dir: str | Path,
    output_path: str | Path | None = None,
    mcp_used_for_endpoints: bool = False,
    tools_ai_metadata: dict | None = None,
) -> Path:
    """Build professional HTML report from recon directory artifacts.

    Reads dns_summary.md, subdomain_classification.csv, live_hosts_detailed.csv,
    tech_profile.csv, headers_summary.md, tls_summary.md, endpoint_inventory.csv,
    js_findings.md, anomalies.md, stage2_inputs.md, stage2_structured.json,
    intel_findings.json, resolved.txt, cname_map.csv, and 00_scope files.

    Args:
        recon_dir: Path to recon directory (e.g. .../recon/svalbard-stage1/).
        output_path: Optional output path. Default: recon_dir/stage1_report.html.
        mcp_used_for_endpoints: When True, methodology section states that MCP
                                user-fetch was used for endpoint discovery.
        tools_ai_metadata: Optional dict with ai_provider, ai_model, prompts_used,
                          mcp_tools_used for Tools & AI section.

    Returns:
        Path to generated HTML file.
    """
    base = Path(recon_dir)
    out_path = Path(output_path) if output_path else base / "stage1_report.html"

    target_domain = _derive_target_domain(base)
    report_date = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    scope_dir = base / "00_scope"
    dns_dir = base / "03_dns"

    scope_text = _read_text(scope_dir / "scope.txt")
    roe_text = _read_text(scope_dir / "roe.txt")
    targets_text = _read_text(scope_dir / "targets.txt")

    dns_summary = _read_text(base / "dns_summary.md")
    subdomain_csv = _load_csv(base / "subdomain_classification.csv")
    live_hosts_csv = _load_csv(base / "live_hosts_detailed.csv")
    tech_csv = _load_csv(base / "tech_profile.csv")
    headers_summary = _read_text(base / "headers_summary.md")
    headers_detailed_csv = _load_csv(base / "headers_detailed.csv")
    tls_summary = _read_text(base / "tls_summary.md")
    endpoint_csv = _load_csv(base / "endpoint_inventory.csv")
    js_routes_csv = _load_csv(base / "js_routes.csv")
    js_api_refs_csv = _load_csv(base / "js_api_refs.csv")
    js_integrations_csv = _load_csv(base / "js_integrations.csv")
    js_config_hints_csv = _load_csv(base / "js_config_hints.csv")
    input_surfaces_csv = _load_csv(base / "input_surfaces.csv")
    route_params_map_csv = _load_csv(base / "route_params_map.csv")
    graphql_candidates_csv = _load_csv(base / "graphql_candidates.csv")
    json_endpoint_candidates_csv = _load_csv(base / "json_endpoint_candidates.csv")
    frontend_backend_boundaries = _read_text(base / "frontend_backend_boundaries.md")
    app_flow_hints = _read_text(base / "app_flow_hints.md")
    route_classification_csv = _load_csv(base / "route_classification.csv")
    host_security_posture_csv = _load_csv(base / "host_security_posture.csv")
    control_inconsistencies = _read_text(base / "control_inconsistencies.md")
    response_similarity_csv = _load_csv(base / "response_similarity.csv")
    catch_all_evidence = _read_text(base / "catch_all_evidence.md")
    content_clusters_csv = _load_csv(base / "content_clusters.csv")
    redirect_clusters_csv = _load_csv(base / "redirect_clusters.csv")
    js_findings = _read_text(base / "js_findings.md")
    anomalies_text = _read_text(base / "anomalies.md")
    anomaly_validation = _read_text(base / "anomaly_validation.md")
    anomaly_validation_csv = _load_csv(base / "anomaly_validation.csv")
    hostname_behavior_matrix_csv = _load_csv(base / "hostname_behavior_matrix.csv")
    anomalies_structured = _load_anomalies_structured(base / "anomalies_structured.json")
    stage2_inputs = _read_text(base / "stage2_inputs.md")
    stage2_preparation = _read_text(base / "stage2_preparation.md")
    stage2_structured = _load_stage2_structured(base / "stage2_structured.json")
    intel_findings = _load_intel_findings(base / "intel_findings.json")
    stage3_readiness_json = _load_stage3_readiness(base / "stage3_readiness.json")

    resolved = parse_resolved(dns_dir / "resolved.txt")
    cname_map = parse_cname(dns_dir / "cname_map.csv")

    sections: list[str] = []

    # 1. Executive summary
    sub_count = len(subdomain_csv) if subdomain_csv else len(resolved)
    live_count = len({r.get("host", "") for r in live_hosts_csv if r.get("host")}) if live_hosts_csv else 0
    anom_count = 0
    if anomalies_structured and "anomalies" in anomalies_structured:
        anom_count = len(anomalies_structured["anomalies"])
    if anom_count == 0:
        anom_count = anomalies_text.count("### anom_") or anomalies_text.count("- **Host**:")
    exec_summary = f"""
    <div class="evidence"><span class="badge badge-evidence">Evidence</span>
    <p>Stage 1 reconnaissance for <strong>{_escape(target_domain)}</strong> completed. Discovered <strong>{sub_count}</strong> subdomains,
    <strong>{live_count}</strong> live hosts, and <strong>{anom_count}</strong> anomalies requiring validation.</p>
    </div>
    <div class="observation"><span class="badge badge-observation">Observation</span>
    <p>DNS resolution matrix and CNAME mapping documented; technology fingerprinting identified; headers and TLS observations captured.</p>
    </div>
    <div class="inference"><span class="badge badge-inference">Inference</span>
    <p>Anomalies include service subdomains (cpanel, mail, webmail) returning shared 404 responses — recommend manual validation.</p>
    </div>
    <div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span>
    <p>CNAME takeover assessment and anomaly validation should be prioritized for Stage 2.</p>
    </div>
    """
    exec_source = _source_block(["subdomain_classification.csv", "live_hosts_detailed.csv", "anomalies_structured.json"])
    sections.append(
        f'<section id="section-01-executive-summary" class="section"><h2>1. Executive Summary</h2>{exec_summary}{exec_source}</section>'
    )

    # 2. Scope / methodology
    mcp_methodology = ""
    if mcp_used_for_endpoints:
        mcp_methodology = """
    <h3>Endpoint Discovery (MCP)</h3>
    <p>Endpoint discovery (robots.txt, sitemap.xml, security.txt, favicon.ico, manifest.json) was performed via <strong>MCP user-fetch</strong> for authorized assessment.</p>
    """
    methodology = f"""
    <div class="evidence"><span class="badge badge-evidence">Evidence</span>
    <span class="badge" style="background:#e0e0e0;color:#424242;">Source: 00_scope/scope.txt, roe.txt, targets.txt</span>
    <h3>In-Scope Assets</h3>
    <pre>{_escape(scope_text or "Not available.")}</pre>
    <h3>Rules of Engagement / Scan Constraints</h3>
    <pre>{_escape(roe_text or "Not available.")}</pre>
    <h3>Targets</h3>
    <pre>{_escape(targets_text or "Not available.")}</pre>
    <h3>Methodology</h3>
    <p><strong>Passive vs safe-active:</strong> Passive recon (DNS, OSINT, CT), safe HTTP probing (no port scan, no fuzzing).</p>
    <p><strong>Stages completed:</strong> 0 (Scope Prep), 1 (Domain/DNS), 2 (Subdomain Enum), 3 (DNS Validation), 4 (Live Hosts).</p>
    {mcp_methodology}
    </div>
    """
    sections.append(
        f'<section id="section-02-scope-methodology" class="section"><h2>2. Scope &amp; Methodology</h2>{methodology}</section>'
    )

    # 3. Domain and DNS findings (split: Evidence, Observation, Inference)
    dns_split = _split_dns_summary_by_taxonomy(dns_summary) if dns_summary else {}
    dns_blocks: list[str] = []
    if dns_split.get("evidence"):
        dns_blocks.append(
            f'<div class="evidence"><span class="badge badge-evidence">Evidence</span>'
            f'{_md_to_html(dns_split["evidence"])}</div>'
        )
    if dns_split.get("observation"):
        dns_blocks.append(
            f'<div class="observation"><span class="badge badge-observation">Observation</span>'
            f'{_md_to_html(dns_split["observation"])}</div>'
        )
    if dns_split.get("inference"):
        dns_blocks.append(
            f'<div class="inference"><span class="badge badge-inference">Inference</span>'
            f'{_md_to_html(dns_split["inference"])}</div>'
        )
    if not dns_blocks:
        dns_fallback = _md_to_html(dns_summary) if dns_summary else "<p><em>No DNS summary available.</em></p>"
        dns_blocks.append(
            f'<div class="evidence"><span class="badge badge-evidence">Evidence</span>{dns_fallback}</div>'
        )
    dns_source = _source_block(["01_domains/*.txt", "03_dns/resolved.txt"])
    sections.append(
        f'<section id="section-03-domain-dns-findings" class="section"><h2>3. Domain and DNS Findings</h2>{"".join(dns_blocks)}{dns_source}</section>'
    )

    # 4. Subdomain classification (REC-010: Evidence, Observation, Inference, Hypothesis)
    sub_cols = ["subdomain", "role", "confidence", "priority", "notes"]
    sub_table = _csv_to_html_table(subdomain_csv, sub_cols) if subdomain_csv else "<p><em>No subdomain classification.</em></p>"
    sub_count_val = len(subdomain_csv) if subdomain_csv else 0
    sub_evidence = f'<div class="evidence"><span class="badge badge-evidence">Evidence</span><p>Raw subdomain inventory: <strong>{sub_count_val}</strong> entries from subdomain enumeration.</p></div>'
    sub_observation = f'<div class="observation"><span class="badge badge-observation">Observation</span>{sub_table}</div>'
    sub_inference = '<div class="inference"><span class="badge badge-inference">Inference</span><p>Role classification (api, admin, auth, static, etc.) derived from hostname patterns and probe results.</p></div>'
    sub_hypothesis = '<div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span><p>Prioritize high-confidence admin/auth subdomains for Stage 2 validation; verify unresolved or low-confidence entries.</p></div>'
    sub_source = _source_block(["02_subdomains/subdomains_clean.txt", "subdomain_classification.csv"])
    sections.append(
        f'<section id="section-04-subdomain-classification" class="section"><h2>4. Subdomain Classification</h2>'
        f'{sub_evidence}{sub_observation}{sub_inference}{sub_hypothesis}{sub_source}</section>'
    )

    # 5. DNS validation (resolution matrix, CNAME mapping)
    res_rows: list[dict] = []
    for sub, ips in sorted(resolved.items()):
        res_rows.append({"subdomain": sub, "ips": ", ".join(ips[:5]) + ("..." if len(ips) > 5 else "")})
    res_table = _csv_to_html_table(res_rows, ["subdomain", "ips"]) if res_rows else "<p><em>No resolved data.</em></p>"

    cname_rows = [{"host": r.get("host", ""), "target": r.get("value", ""), "comment": r.get("comment", "")} for r in cname_map]
    cname_table = _csv_to_html_table(cname_rows, ["host", "target", "comment"]) if cname_rows else "<p><em>No CNAME records.</em></p>"

    dns_val_evidence = f"""
    <h3>Resolution Matrix (from resolved.txt)</h3>
    {res_table}
    <h3>CNAME Mapping (from cname_map.csv)</h3>
    {cname_table}
    """
    dns_val_observation = '<div class="observation"><span class="badge badge-observation">Observation</span><p>Resolved vs unresolved counts; CNAME chains indicate delegation and potential takeover candidates.</p></div>'
    dns_val_inference = '<div class="inference"><span class="badge badge-inference">Inference</span><p>CNAME targets pointing to unclaimed or third-party services may be vulnerable to subdomain takeover.</p></div>'
    dns_val_hypothesis = '<div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span><p>Validate dangling CNAMEs and MX records before Stage 2; prioritize hosts with external targets.</p></div>'
    dns_val_source = _source_block(["03_dns/resolved.txt", "03_dns/cname_map.csv"])
    sections.append(
        f'<section id="section-05-dns-validation-results" class="section"><h2>5. DNS Validation Results</h2>'
        f'<div class="evidence"><span class="badge badge-evidence">Evidence</span>{dns_val_evidence}</div>'
        f'{dns_val_observation}{dns_val_inference}{dns_val_hypothesis}{dns_val_source}</section>'
    )

    # 6. Live host analysis (REC-010: Evidence, Observation, Inference, Hypothesis)
    live_cols = ["host", "ip", "cname", "final_url", "status", "title", "server", "notes"]
    live_table = _csv_to_html_table(live_hosts_csv, live_cols) if live_hosts_csv else "<p><em>No live hosts data.</em></p>"
    live_evidence = f'<div class="evidence"><span class="badge badge-evidence">Evidence</span>{live_table}</div>'
    live_observation = '<div class="observation"><span class="badge badge-observation">Observation</span><p>HTTP probe results: status codes, titles, server headers; hosts responding to safe HTTP requests.</p></div>'
    live_inference = '<div class="inference"><span class="badge badge-inference">Inference</span><p>Server headers and redirect chains indicate technology stack and potential admin/auth endpoints.</p></div>'
    live_hypothesis = '<div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span><p>Prioritize hosts with 401/403, login-like titles, or admin paths for Stage 2 authentication testing.</p></div>'
    live_source = _source_block(["04_live_hosts/http_probe.csv", "live_hosts_detailed.csv"])
    sections.append(
        f'<section id="section-06-live-host-analysis" class="section"><h2>6. Live Host Analysis</h2>'
        f'{live_evidence}{live_observation}{live_inference}{live_hypothesis}{live_source}</section>'
    )

    # 7. Technology profile (REC-010: Evidence, Observation, Inference, Hypothesis)
    tech_table = _csv_to_html_table(tech_csv) if tech_csv else "<p><em>No tech profile.</em></p>"
    tech_evidence = f'<div class="evidence"><span class="badge badge-evidence">Evidence</span><h3>Technology Fingerprint</h3>{tech_table}</div>'
    tech_observation = '<div class="observation"><span class="badge badge-observation">Observation</span><p>Technologies inferred from Server, X-Powered-By, and similar headers; Wappalyzer-style fingerprinting.</p></div>'
    tech_inference = '<div class="inference"><span class="badge badge-inference">Inference</span><p>Stack composition suggests attack surface: CMS, frameworks, and APIs may have known vulnerabilities.</p></div>'
    tech_hypothesis = '<div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span><p>Cross-reference tech stack with CVE databases; prioritize outdated or high-risk components for Stage 2.</p></div>'
    tech_source = _source_block(["tech_profile.csv", "04_live_hosts/http_probe.csv"])
    sections.append(
        f'<section id="section-07-technology-profile" class="section"><h2>7. Technology Profile</h2>'
        f'{tech_evidence}{tech_observation}{tech_inference}{tech_hypothesis}{tech_source}</section>'
    )

    # 8. JavaScript / Frontend Analysis
    js_routes_table = _csv_to_html_table(
        js_routes_csv,
        ["route_hint", "evidence_ref"],
    ) if js_routes_csv else "<p><em>No js_routes.csv.</em></p>"
    js_api_refs_table = _csv_to_html_table(
        js_api_refs_csv,
        ["api_ref", "evidence_ref"],
    ) if js_api_refs_csv else "<p><em>No js_api_refs.csv.</em></p>"
    js_integrations_table = _csv_to_html_table(
        js_integrations_csv,
        ["integration_hint", "integration_type", "evidence_ref"],
    ) if js_integrations_csv else "<p><em>No js_integrations.csv.</em></p>"
    js_config_table = _csv_to_html_table(
        js_config_hints_csv,
        ["config_hint", "evidence_ref"],
    ) if js_config_hints_csv else "<p><em>No js_config_hints.csv.</em></p>"
    js_summary_html = _md_to_html(js_findings) if js_findings else "<p><em>No JS findings.</em></p>"
    sections.append(
        f'<section id="section-08-javascript-frontend-analysis" class="section"><h2>8. JavaScript / Frontend Analysis</h2>'
        f'<h3>JS Routes</h3><div class="evidence"><span class="badge badge-evidence">Evidence</span>{js_routes_table}</div>'
        f'<h3>JS API References</h3><div class="evidence"><span class="badge badge-evidence">Evidence</span>{js_api_refs_table}</div>'
        f'<h3>JS Integrations</h3><div class="observation"><span class="badge badge-observation">Observation</span>{js_integrations_table}</div>'
        f'<h3>JS Config Hints</h3><div class="observation"><span class="badge badge-observation">Observation</span>{js_config_table}</div>'
        f'<h3>Interpretation</h3><div class="inference"><span class="badge badge-inference">Inference</span>{js_summary_html}</div>'
        f'{_source_block(["js_routes.csv", "js_api_refs.csv", "js_integrations.csv", "js_config_hints.csv", "js_findings.md"])}</section>'
    )

    # 9. Parameters and Input Surfaces (REC-010: Evidence, Observation, Hypothesis)
    input_surfaces_table = _csv_to_html_table(
        input_surfaces_csv,
        ["surface_type", "surface_name", "context_url", "classification", "evidence_ref"],
    ) if input_surfaces_csv else "<p><em>No input_surfaces.csv.</em></p>"
    route_params_map_table = _csv_to_html_table(
        route_params_map_csv,
        ["context_url", "route_path", "param_names", "sources", "evidence_refs"],
    ) if route_params_map_csv else "<p><em>No route_params_map.csv.</em></p>"
    params_hypothesis = (
        '<div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span>'
        '<p>Prioritize auth-related parameters and form actions for Stage 2 validation; validate IDOR candidates on parameterized routes.</p></div>'
    )
    sections.append(
        f'<section id="section-09-parameters-input-surfaces" class="section"><h2>9. Parameters and Input Surfaces</h2>'
        f'<h3>Input Surfaces</h3><div class="evidence"><span class="badge badge-evidence">Evidence</span>{input_surfaces_table}</div>'
        f'<h3>Route-Parameter Mapping</h3><div class="observation"><span class="badge badge-observation">Observation</span>{route_params_map_table}</div>'
        f'{params_hypothesis}'
        f'{_source_block(["params_inventory.csv", "forms_inventory.csv", "input_surfaces.csv", "route_params_map.csv"])}</section>'
    )

    # 10. API Surface Mapping
    api_table = _csv_to_html_table(
        endpoint_csv,
        ["url", "status", "content_type", "exists", "notes"],
    ) if endpoint_csv else "<p><em>No endpoint inventory.</em></p>"
    api_surface_table = _csv_to_html_table(
        _load_csv(base / "api_surface.csv"),
        ["host", "path", "full_url", "source", "api_type", "method_hint", "auth_boundary_hint", "evidence_ref"],
    )
    graphql_table = _csv_to_html_table(
        graphql_candidates_csv,
        ["host", "path", "full_url", "source", "evidence_ref"],
    ) if graphql_candidates_csv else "<p><em>No graphql_candidates.csv.</em></p>"
    json_candidates_table = _csv_to_html_table(
        json_endpoint_candidates_csv,
        ["host", "path", "full_url", "source", "evidence_ref"],
    ) if json_endpoint_candidates_csv else "<p><em>No json_endpoint_candidates.csv.</em></p>"
    boundaries_html = _md_to_html(frontend_backend_boundaries) if frontend_backend_boundaries else "<p><em>No frontend_backend_boundaries.md.</em></p>"
    app_flow_html = _md_to_html(app_flow_hints) if app_flow_hints else "<p><em>No app_flow_hints.md.</em></p>"
    sections.append(
        f'<section id="section-10-api-surface-mapping" class="section"><h2>10. API Surface Mapping</h2>'
        f'<h3>Endpoint Inventory</h3><div class="evidence"><span class="badge badge-evidence">Evidence</span>{api_table}</div>'
        f'<h3>API Surface</h3><div class="observation"><span class="badge badge-observation">Observation</span>{api_surface_table}</div>'
        f'<h3>GraphQL Candidates</h3><div class="observation"><span class="badge badge-observation">Observation</span>{graphql_table}</div>'
        f'<h3>JSON Endpoint Candidates</h3><div class="observation"><span class="badge badge-observation">Observation</span>{json_candidates_table}</div>'
        f'<h3>Frontend/Backend Boundaries</h3><div class="inference"><span class="badge badge-inference">Inference</span>{boundaries_html}</div>'
        f'<h3>App Flow Hints</h3><div class="inference"><span class="badge badge-inference">Inference</span>{app_flow_html}</div>'
        f'{_source_block(["api_surface.csv", "graphql_candidates.csv", "json_endpoint_candidates.csv", "frontend_backend_boundaries.md", "app_flow_hints.md"])}</section>'
    )

    # 11. Headers / Cookies / TLS Analysis
    headers_html = _md_to_html(headers_summary) if headers_summary else "<p><em>No headers summary.</em></p>"
    headers_detailed_table = (
        _csv_to_html_table(
            headers_detailed_csv,
            [
                "host_url",
                "status_code",
                "security_header_score",
                "cookie_count",
                "cookies_httponly",
                "cookies_secure",
                "cookies_samesite",
            ],
        )
        if headers_detailed_csv
        else "<p><em>No headers_detailed.csv.</em></p>"
    )
    tls_html = _md_to_html(tls_summary) if tls_summary else "<p><em>No TLS summary.</em></p>"
    host_posture_table = _csv_to_html_table(
        host_security_posture_csv,
        ["host", "security_header_score", "cookie_count", "cookies_secure", "cookies_httponly", "cookies_samesite", "evidence_ref"],
    ) if host_security_posture_csv else "<p><em>No host_security_posture.csv.</em></p>"
    control_inconsistencies_html = (
        _md_to_html(control_inconsistencies) if control_inconsistencies else "<p><em>No control_inconsistencies.md.</em></p>"
    )
    headers_source = _source_block(
        ["headers_summary.md", "headers_detailed.csv", "tls_summary.md", "host_security_posture.csv", "control_inconsistencies.md"]
    )
    sections.append(
        f'<section id="section-11-headers-cookies-tls-analysis" class="section"><h2>11. Headers / Cookies / TLS Analysis</h2>'
        f'<div class="evidence"><span class="badge badge-evidence">Evidence</span>{headers_detailed_table}</div>'
        f'<div class="evidence"><span class="badge badge-evidence">Evidence</span>{host_posture_table}</div>'
        f'<div class="observation"><span class="badge badge-observation">Observation</span>{headers_html}</div>'
        f'<div class="observation"><span class="badge badge-observation">Observation</span>{control_inconsistencies_html}</div>'
        f'<div class="inference"><span class="badge badge-inference">Inference</span>{tls_html}</div>'
        f'{headers_source}</section>'
    )

    # 12. Content Similarity and Routing Behavior
    content_cluster_table = (
        _csv_to_html_table(
            content_clusters_csv,
            [
                "cluster_id",
                "host",
                "status",
                "cluster_size",
                "template_hint",
                "suspicious_host",
                "catch_all_hint",
            ],
        )
        if content_clusters_csv
        else "<p><em>No content clusters.</em></p>"
    )
    redirect_cluster_table = (
        _csv_to_html_table(
            redirect_clusters_csv,
            [
                "redirect_cluster_id",
                "host",
                "status",
                "redirect_target",
                "cluster_size",
                "shared_with_root",
                "suspicious_host",
            ],
        )
        if redirect_clusters_csv
        else "<p><em>No redirect clusters.</em></p>"
    )
    response_similarity_table = _csv_to_html_table(
        response_similarity_csv,
        [
            "cluster_id",
            "host",
            "url",
            "similarity_score",
            "template_hint",
            "similarity_type",
            "shared_redirect_target",
            "evidence_ref",
        ],
    ) if response_similarity_csv else "<p><em>No response_similarity.csv.</em></p>"
    hostname_behavior_table = _csv_to_html_table(
        hostname_behavior_matrix_csv,
        [
            "host",
            "behavior_type",
            "related_hosts",
            "content_cluster",
            "template_hint",
            "catch_all_hint",
            "redirect_cluster",
            "shared_with_root",
            "suspicious_host",
            "evidence_refs",
        ],
    ) if hostname_behavior_matrix_csv else "<p><em>No hostname_behavior_matrix.csv.</em></p>"
    catch_all_html = _md_to_html(catch_all_evidence) if catch_all_evidence else "<p><em>No catch_all_evidence.md.</em></p>"
    content_source = _source_block(
        ["content_clusters.csv", "redirect_clusters.csv", "response_similarity.csv", "hostname_behavior_matrix.csv", "catch_all_evidence.md"]
    )
    sections.append(
        f'<section id="section-12-content-similarity-and-routing-behavior" class="section"><h2>12. Content Similarity and Routing Behavior</h2>'
        f'<h3>Content Fingerprint Clusters</h3><div class="observation"><span class="badge badge-observation">Observation</span>{content_cluster_table}</div>'
        f'<h3>Redirect Clusters</h3><div class="observation"><span class="badge badge-observation">Observation</span>{redirect_cluster_table}</div>'
        f'<h3>Response Similarity</h3><div class="evidence"><span class="badge badge-evidence">Evidence</span>{response_similarity_table}</div>'
        f'<h3>Hostname Behavior Matrix</h3><div class="observation"><span class="badge badge-observation">Observation</span>{hostname_behavior_table}</div>'
        f'<h3>Catch-all Evidence</h3><div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span>{catch_all_html}</div>'
        f'{content_source}</section>'
    )

    # 13. Anomaly Validation
    anomaly_validation_table = _csv_to_html_table(
        anomaly_validation_csv,
        ["host", "classification", "confidence", "recommendation", "evidence_refs"],
    ) if anomaly_validation_csv else "<p><em>No anomaly_validation.csv.</em></p>"
    if anomaly_validation:
        anomaly_validation_html = _md_to_html(anomaly_validation)
    elif anomalies_structured:
        anomaly_validation_html = _render_anomalies_from_structured(anomalies_structured)
    else:
        anomaly_validation_html = _md_to_html(anomalies_text) if anomalies_text else "<p><em>No anomalies detected.</em></p>"
    sections.append(
        f'<section id="section-13-anomaly-validation" class="section"><h2>13. Anomaly Validation</h2>'
        f'<div class="evidence"><span class="badge badge-evidence">Evidence</span>{anomaly_validation_table}</div>'
        f'<div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span>{anomaly_validation_html}</div>'
        f'{_source_block(["anomaly_validation.md", "anomaly_validation.csv", "anomalies_structured.json", "anomalies.md"])}</section>'
    )

    # 14. Stage 2 preparation (REC-010: Evidence, Observation, Inference, Hypothesis)
    if stage2_structured:
        rec_html = _render_stage2_from_structured(stage2_structured)
    elif stage2_preparation:
        rec_html = _md_to_html(stage2_preparation)
    elif stage2_inputs:
        rec_html = _md_to_html(stage2_inputs)
    else:
        rec_html = "<p><em>No stage2_inputs. Run stage2_builder.</em></p>"
    stage2_evidence = '<div class="evidence"><span class="badge badge-evidence">Evidence</span><p>Structured inputs from anomaly validation, route inventory, and API surface feed Stage 2 scope.</p></div>'
    stage2_observation = '<div class="observation"><span class="badge badge-observation">Observation</span><p>Trust boundaries, critical assets, and entry points identified from recon artifacts.</p></div>'
    stage2_inference = f'<div class="inference"><span class="badge badge-inference">Inference</span>{rec_html}</div>'
    stage2_hypothesis = '<div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span><p>Priority hypotheses and candidate entry points should be validated manually before penetration testing.</p></div>'
    sections.append(
        f'<section id="section-14-stage-2-preparation" class="section"><h2>14. Stage 2 Preparation</h2>'
        f'{stage2_evidence}{stage2_observation}{stage2_inference}{stage2_hypothesis}'
        f'{_source_block(["stage2_preparation.md", "stage2_inputs.md", "stage2_structured.json", "anomaly_validation.md"])}</section>'
    )

    # 15. Tools & AI Used (REC-010: Evidence badge for tools inventory)
    tools_ai_section = _build_tools_ai_section(tools_ai_metadata, mcp_used_for_endpoints)
    sections.append(
        f'<section id="section-15-tools-and-ai-used" class="section"><h2>15. Tools &amp; AI Used</h2>'
        f'<div class="evidence"><span class="badge badge-evidence">Evidence</span>{tools_ai_section}</div></section>'
    )

    # 16. Intel/OSINT Enrichment (REC-010: badges via intel_builder or Observation fallback)
    if intel_findings:
        from src.recon.reporting.intel_builder import build_intel_section_html

        intel_html = build_intel_section_html(intel_findings)
    else:
        intel_html = (
            '<div class="observation"><span class="badge badge-observation">Observation</span>'
            '<p><em>No intel data. Configure API keys (e.g. SHODAN_API_KEY) and run Stage 1 report.</em></p></div>'
        )
    intel_source = _source_block("intel_findings.json")
    sections.append(
        f'<section id="section-16-intel-osint-enrichment" class="section"><h2>16. Intel/OSINT Enrichment</h2>'
        f'{intel_html}{intel_source}</section>'
    )

    # 17. Stage 3 Readiness (REC-010: Evidence, Observation, Inference, Hypothesis; section 17 from REC-008)
    stage3_readiness_text = _read_text(base / "stage3_readiness.md")
    stage3_readiness_html = _md_to_html(stage3_readiness_text) if stage3_readiness_text else "<p><em>No stage3_readiness.md.</em></p>"
    stage3_evidence_parts: list[str] = []
    if stage3_readiness_json:
        status = stage3_readiness_json.get("status", "unknown")
        scores = stage3_readiness_json.get("coverage_scores") or {}
        route = float(scores.get("route") or 0)
        inp = float(scores.get("input_surface") or 0)
        api = float(scores.get("api_surface") or 0)
        content = float(scores.get("content_anomaly") or 0)
        boundary = float(scores.get("boundary_mapping") or 0)
        stage3_evidence_parts.append(
            f'<p><strong>Status:</strong> {_escape(str(status))}. '
            f'Coverage: route={route:.2f}, input_surface={inp:.2f}, api_surface={api:.2f}, '
            f'content_anomaly={content:.2f}, boundary_mapping={boundary:.2f}.</p>'
        )
    stage3_evidence = (
        f'<div class="evidence"><span class="badge badge-evidence">Evidence</span>{"".join(stage3_evidence_parts) or "<p>No stage3_readiness.json.</p>"}</div>'
    )
    stage3_observation_parts: list[str] = []
    if stage3_readiness_json:
        missing = stage3_readiness_json.get("missing_evidence", [])[:10]
        follow_up = stage3_readiness_json.get("recommended_follow_up", [])[:5]
        if missing:
            stage3_observation_parts.append("<p><strong>Missing evidence:</strong> " + _escape(", ".join(missing)) + "</p>")
        if follow_up:
            stage3_observation_parts.append("<p><strong>Recommended follow-up:</strong> " + _escape("; ".join(follow_up)) + "</p>")
    stage3_observation = (
        f'<div class="observation"><span class="badge badge-observation">Observation</span>'
        f'{"".join(stage3_observation_parts) or "<p>Coverage gaps and recommended actions from readiness assessment.</p>"}</div>'
    )
    stage3_inference = f'<div class="inference"><span class="badge badge-inference">Inference</span>{stage3_readiness_html}</div>'
    stage3_hypothesis = (
        '<div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span>'
        '<p>Prioritize route and API surface coverage before penetration testing; address missing evidence gaps for Stage 3.</p></div>'
    )
    sections.append(
        f'<section id="section-17-stage-3-readiness" class="section"><h2>17. Stage 3 Readiness</h2>'
        f'{stage3_evidence}{stage3_observation}{stage3_inference}{stage3_hypothesis}'
        f'{_source_block(["stage3_readiness.json", "stage3_readiness.md", "ai_stage3_preparation_summary_normalized.json"])}</section>'
    )

    # 18. Route Classification (REC-010: Evidence, Observation, Inference, Hypothesis)
    route_classification_table = (
        _csv_to_html_table(
            route_classification_csv,
            ["route", "host", "classification", "discovery_source", "evidence_ref"],
        )
        if route_classification_csv
        else "<p><em>No route_classification.csv.</em></p>"
    )
    route_evidence = (
        f'<div class="evidence"><span class="badge badge-evidence">Evidence</span>'
        f'<p>Route inventory with classification (login_flow, admin_flow, api, static, etc.) from discovery sources.</p>'
        f'{route_classification_table}</div>'
    )
    route_observation = (
        '<div class="observation"><span class="badge badge-observation">Observation</span>'
        '<p>Classification derived from path patterns and endpoint behavior; used for Stage 3 readiness assessment.</p></div>'
    )
    route_inference = (
        '<div class="inference"><span class="badge badge-inference">Inference</span>'
        '<p>login_flow and admin_flow routes indicate auth boundaries; api routes define backend attack surface.</p></div>'
    )
    route_hypothesis = (
        '<div class="hypothesis"><span class="badge badge-hypothesis">Hypothesis</span>'
        '<p>Prioritize login_flow and admin_flow for auth testing; validate API routes for injection and access control.</p></div>'
    )
    sections.append(
        f'<section id="section-18-route-classification" class="section"><h2>18. Route Classification</h2>'
        f'{route_evidence}{route_observation}{route_inference}{route_hypothesis}'
        f'{_source_block(["route_classification.csv", "route_inventory.csv", "stage3_readiness.json"])}</section>'
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stage 1 Recon Report — {_escape(target_domain)}</title>
    <style>{_REPORT_CSS}</style>
</head>
<body>
    <h1>Stage 1 Intelligence Gathering Report — {_escape(target_domain)}</h1>
    <div class="meta">
        <p><strong>Target:</strong> {_escape(target_domain)}</p>
        <p><strong>Date:</strong> {report_date}</p>
        <p><strong>Methodology:</strong> ARGUS Recon Pipeline — Stages 0–4 (Scope, Domain/DNS, Subdomain Enum, DNS Validation, Live Hosts). Passive + safe HTTP probing.</p>
    </div>

    {"".join(sections)}

    <footer style="margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e0e0e0; color: #757575; font-size: 0.85rem;">
        <p>Generated by ARGUS Recon. Evidence | Observation | Inference | Hypothesis. All data from authorized reconnaissance.</p>
    </footer>
</body>
</html>"""

    out_path.write_text(html_content, encoding="utf-8")
    logger.info("HTML report generated", extra={"path": str(out_path), "target": target_domain})
    return out_path
