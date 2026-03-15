"""Intel builder — produces intel section content from adapter results.

Reads intel_findings.json (aggregated adapter outputs) and builds:
- intel_summary.md (optional markdown)
- HTML section content for Stage 1 report (Intel/OSINT Enrichment).
"""

import html
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def _escape(s: str) -> str:
    """Escape HTML entities for safe output."""
    return html.escape(str(s), quote=True)


def build_intel_summary(intel_findings: dict) -> str:
    """Build markdown summary from intel adapter results.

    Args:
        intel_findings: Aggregated adapter output (target_domain, adapters, etc.).

    Returns:
        Markdown string for intel_summary.md.
    """
    target = intel_findings.get("target_domain", "unknown")
    adapters_data = intel_findings.get("adapters", [])
    fetched_at = intel_findings.get("fetched_at", "")

    lines: list[str] = [
        f"# Intel/OSINT Enrichment — {target}",
        "",
        f"*Fetched: {fetched_at}*",
        "",
    ]

    for ad in adapters_data:
        source = ad.get("source", "unknown")
        findings = ad.get("findings", [])
        skipped = ad.get("skipped", False)
        error = ad.get("error")

        lines.append(f"## {source.upper()}")
        if skipped:
            lines.append("*Skipped (no API key or not configured).*")
        elif error:
            lines.append(f"*Error: {error}*")
        elif not findings:
            lines.append("*No findings.*")
        else:
            for f in findings[:50]:
                f_type = f.get("finding_type", "")
                value = f.get("value", "")
                data = f.get("data", {})
                conf = f.get("confidence", 0)
                lines.append(f"- **{f_type}**: `{value}` (confidence: {conf})")
                if data:
                    extras = {k: v for k, v in data.items() if k not in ("source", "source_tool")}
                    if extras:
                        lines.append(f"  - {extras}")
        lines.append("")

    return "\n".join(lines)


def build_intel_section_html(intel_findings: dict) -> str:
    """Build HTML section content for Intel/OSINT Enrichment.

    Renders findings grouped by source (Shodan, crt.sh, NVD, RDAP, etc.)
    with taxonomy badges and safe HTML escaping.

    Args:
        intel_findings: Aggregated adapter output from intel_findings.json.

    Returns:
        HTML string for the report section.
    """
    adapters_data = intel_findings.get("adapters", [])
    if not adapters_data:
        return '<p><em>No intel adapters were run. Configure API keys (e.g. SHODAN_API_KEY) for enrichment.</em></p>'

    out: list[str] = []

    for ad in adapters_data:
        source = ad.get("source", "unknown")
        findings = ad.get("findings", [])
        skipped = ad.get("skipped", False)
        error = ad.get("error")

        out.append(f'<div class="observation">')
        out.append(f'<span class="badge badge-observation">{_escape(source.upper())}</span>')
        out.append(f"<h3>{_escape(source)}</h3>")

        if skipped:
            out.append("<p><em>Skipped (no API key or not configured).</em></p>")
        elif error:
            out.append(f"<p><em>Error: {_escape(str(error))}</em></p>")
        elif not findings:
            out.append("<p><em>No findings.</em></p>")
        else:
            out.append("<ul>")
            for f in findings[:100]:
                f_type = f.get("finding_type", "osint_entry")
                value = f.get("value", "")
                data = f.get("data", {})
                conf = f.get("confidence", 0)
                out.append(f'<li class="inference">')
                out.append(f'<span class="badge badge-inference">{_escape(f_type)}</span> ')
                out.append(f"<code>{_escape(str(value)[:200])}</code>")
                if conf:
                    out.append(f' <span class="badge" style="background:#e0e0e0;color:#424242;">conf:{conf}</span>')
                if data:
                    extras = {k: v for k, v in data.items() if k not in ("source", "source_tool")}
                    if extras:
                        summary = ", ".join(f"{k}={str(v)[:50]}" for k, v in list(extras.items())[:5])
                        out.append(f" <small>{_escape(summary)}</small>")
                out.append("</li>")
            out.append("</ul>")
        out.append("</div>")

    return "\n".join(out)
