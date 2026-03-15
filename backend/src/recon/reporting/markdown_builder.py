"""Markdown report builders — recon summary, hypotheses, attack surface, priorities."""

import logging
from datetime import UTC, datetime

from src.db.models_recon import Hypothesis, NormalizedFinding

logger = logging.getLogger(__name__)


def build_recon_summary(
    engagement_name: str,
    targets: list[str],
    findings_by_type: dict[str, int],
    total_jobs: int,
    total_artifacts: int,
    hypotheses_count: int,
) -> str:
    """Build recon_summary.md — executive summary of the recon phase."""
    lines = [
        "# Recon Summary",
        "",
        f"**Engagement:** {engagement_name}",
        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Overview",
        "",
        f"- **Targets:** {len(targets)}",
        f"- **Scan jobs executed:** {total_jobs}",
        f"- **Artifacts stored:** {total_artifacts}",
        f"- **Unique findings:** {sum(findings_by_type.values())}",
        f"- **Hypotheses generated:** {hypotheses_count}",
        "",
        "## Targets",
        "",
    ]
    for t in targets:
        lines.append(f"- {t}")

    lines.extend(["", "## Findings by Type", "", "| Type | Count |", "|------|-------|"])
    for ftype, count in sorted(findings_by_type.items(), key=lambda x: -x[1]):
        lines.append(f"| {ftype} | {count} |")

    lines.extend([
        "",
        "## Key Statistics",
        "",
        f"- Subdomains discovered: {findings_by_type.get('subdomain', 0)}",
        f"- Live URLs: {findings_by_type.get('url', 0)}",
        f"- Services detected: {findings_by_type.get('service', 0)}",
        f"- Technologies identified: {findings_by_type.get('technology', 0)}",
        f"- API endpoints: {findings_by_type.get('api_endpoint', 0)}",
        f"- Parameters found: {findings_by_type.get('parameter', 0)}",
        f"- JS findings: {findings_by_type.get('js_finding', 0)}",
        f"- Secret candidates: {findings_by_type.get('secret_candidate', 0)}",
        "",
        "---",
        "",
        "*This report was generated automatically by ARGUS Recon.*",
        "*All findings are from authorized reconnaissance only.*",
    ])
    return "\n".join(lines)


def build_hypotheses_report(hypotheses: list[Hypothesis]) -> str:
    """Build hypotheses.md — grouped by priority."""
    lines = ["# Hypotheses", "", "Hypothesis list for further manual investigation.", ""]

    by_priority: dict[str, list[Hypothesis]] = {}
    for h in hypotheses:
        by_priority.setdefault(h.priority, []).append(h)

    priority_order = ["critical", "high", "medium", "low", "info"]
    for priority in priority_order:
        items = by_priority.get(priority, [])
        if not items:
            continue
        lines.append(f"## {priority.upper()} ({len(items)})")
        lines.append("")
        for h in items:
            lines.append(f"### {h.title}")
            lines.append("")
            if h.description:
                lines.append(h.description)
                lines.append("")
            lines.append(f"- **Category:** {h.category}")
            lines.append(f"- **Status:** {h.status}")
            lines.append("")

    if not hypotheses:
        lines.append("*No hypotheses generated yet.*")

    return "\n".join(lines)


def build_attack_surface_map(
    findings: list[NormalizedFinding],
    hypotheses: list[Hypothesis],
) -> str:
    """Build attack_surface.md — organized by entry point type."""
    lines = ["# Attack Surface Map", ""]

    categories = {
        "Web Applications": [f for f in findings if f.finding_type == "url"],
        "API Endpoints": [f for f in findings if f.finding_type == "api_endpoint"],
        "Subdomains": [f for f in findings if f.finding_type == "subdomain"],
        "Network Services": [f for f in findings if f.finding_type == "service"],
        "Technologies": [f for f in findings if f.finding_type == "technology"],
        "TLS/Crypto": [f for f in findings if f.finding_type == "tls_info"],
        "JavaScript Findings": [f for f in findings if f.finding_type == "js_finding"],
        "Secret Candidates": [f for f in findings if f.finding_type == "secret_candidate"],
    }

    for cat_name, cat_findings in categories.items():
        if not cat_findings:
            continue
        lines.append(f"## {cat_name} ({len(cat_findings)})")
        lines.append("")
        for f in cat_findings[:50]:
            lines.append(f"- `{f.value}` (source: {f.source_tool}, confidence: {f.confidence})")
        if len(cat_findings) > 50:
            lines.append(f"- ... and {len(cat_findings) - 50} more")
        lines.append("")

    if hypotheses:
        lines.append("## Related Hypotheses")
        lines.append("")
        for h in hypotheses:
            lines.append(f"- **[{h.priority.upper()}]** {h.title}")
        lines.append("")

    return "\n".join(lines)


def build_host_groups(findings: list[NormalizedFinding]) -> str:
    """Build host_groups.md — cluster hosts by role/technology."""
    lines = ["# Host Groups", ""]

    groups: dict[str, list[str]] = {
        "API Hosts": [],
        "Admin/Portal": [],
        "Auth/SSO": [],
        "Dev/Staging/Test": [],
        "Legacy/Old": [],
        "CDN/Static": [],
        "Docs/Swagger": [],
        "Other": [],
    }

    keywords_map = {
        "API Hosts": ["api.", "graphql.", "rest."],
        "Admin/Portal": ["admin.", "portal.", "cpanel.", "dashboard."],
        "Auth/SSO": ["auth.", "login.", "sso.", "oauth."],
        "Dev/Staging/Test": ["dev.", "test.", "staging.", "stage.", "uat.", "beta."],
        "Legacy/Old": ["old.", "legacy.", "v1.", "v2."],
        "CDN/Static": ["cdn.", "static.", "assets.", "media.", "files."],
        "Docs/Swagger": ["docs.", "swagger.", "doc.", "help."],
    }

    subdomains = [f for f in findings if f.finding_type == "subdomain"]
    for f in subdomains:
        value = f.value.lower()
        placed = False
        for group_name, keywords in keywords_map.items():
            if any(value.startswith(kw) or f".{kw}" in value for kw in keywords):
                groups[group_name].append(value)
                placed = True
                break
        if not placed:
            groups["Other"].append(value)

    for group_name, hosts in groups.items():
        if not hosts:
            continue
        lines.append(f"## {group_name} ({len(hosts)})")
        lines.append("")
        for h in sorted(hosts)[:100]:
            lines.append(f"- {h}")
        if len(hosts) > 100:
            lines.append(f"- ... and {len(hosts) - 100} more")
        lines.append("")

    return "\n".join(lines)


def build_priorities_report(
    hypotheses: list[Hypothesis],
    _findings_by_type: dict[str, int],
) -> str:
    """Build priorities.md — prioritized next steps."""
    lines = ["# Priorities — Next Steps", ""]

    critical = [h for h in hypotheses if h.priority == "critical"]
    high = [h for h in hypotheses if h.priority == "high"]

    if critical:
        lines.append("## Critical Priority")
        lines.append("")
        for h in critical:
            lines.append(f"1. **{h.title}** — {h.description or h.category}")
        lines.append("")

    if high:
        lines.append("## High Priority")
        lines.append("")
        for h in high:
            lines.append(f"1. **{h.title}** — {h.description or h.category}")
        lines.append("")

    lines.extend([
        "## Recommended Investigation Order",
        "",
        "1. Verify all critical/high hypotheses manually",
        "2. Review exposed API endpoints and auth requirements",
        "3. Analyze secret candidates in JS findings",
        "4. Test admin/portal/staging hosts for misconfigurations",
        "5. Review TLS/security header findings",
        "6. Investigate unusual network services",
        "7. Deep-dive into OSINT leads",
        "",
        "---",
        "",
        "*Generated by ARGUS Recon. All actions must be within authorized scope.*",
    ])
    return "\n".join(lines)
