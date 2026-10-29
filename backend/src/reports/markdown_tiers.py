"""Tier-aware Markdown renderers for the free (Midgard) and first paid (Asgard)
report tiers.

Extracted from ``generators.py`` so the Markdown export is tier-branched exactly
like JSON/XML/CSV/HTML: the free Markdown renders ONLY the ``build_free_payload``
projection (inventory + one safe teaser + target intelligence + exec summary +
upsell) and therefore cannot leak the paid layer (per-finding description,
verification command, AI prose) the way the tier-blind full renderer did; the
paid Markdown renders the full ``build_asgard_payload`` projection so it stays at
content parity with the Asgard JSON/HTML/XML.
"""

from __future__ import annotations

from typing import Any

from src.reports.generators import ReportData


def _clean(value: Any) -> str:
    """ANSI-stripped text (reuses generators._clean_ansi; lazy import avoids a
    module-level import cycle with generators)."""
    from src.reports.generators import _clean_ansi

    return _clean_ansi(str(value if value is not None else ""))


def md_escape(value: Any) -> str:
    """One-line, table-safe markdown cell."""
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def generate_midgard_free_markdown(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Free-tier Markdown — the SAME ``build_free_payload`` projection the other
    free formats use. Never renders per-finding description / remediation /
    verification command / AI prose, so the free Markdown cannot leak the paid
    layer the way the tier-blind full renderer did."""
    from src.reports.midgard_free import build_free_payload
    from src.reports.valhalla_report_context import get_brand

    p = build_free_payload(data, jinja_context)
    brand = get_brand()
    meta = p.get("meta", {}) or {}
    sc = p.get("severity_counts", {}) or {}
    ti = p.get("target_intelligence", {}) or {}
    whois = ti.get("whois", {}) or {}
    dns = ti.get("dns", {}) or {}
    asn = ti.get("asn", {}) or {}
    L: list[str] = [
        f"# {brand.name} — Security Assessment Report",
        "",
        "**Tier:** MIDGARD (Free)  ",
        f"**Target:** {meta.get('target') or data.target or 'N/A'}  ",
        f"**Scan ID:** `{meta.get('scan_id') or data.scan_id or 'N/A'}`  ",
        f"**Generated:** {meta.get('generated_at') or ''}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        _clean(p.get("executive_summary")) or "_Not available._",
        "",
        "## Severity Overview",
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---|---|---|---|---|",
        f"| {sc.get('critical',0)} | {sc.get('high',0)} | {sc.get('medium',0)} "
        f"| {sc.get('low',0)} | {sc.get('info',0)} |",
        "",
        "## Target Intelligence",
        "",
        f"- **WHOIS registrar:** {whois.get('registrar', '')}",
        f"- **WHOIS org:** {whois.get('registrant_org', '')}",
        f"- **DNS NS:** {', '.join(dns.get('ns') or []) or '—'}",
        f"- **DNS MX:** {', '.join(dns.get('mx') or []) or '—'}",
        f"- **ASN:** {asn.get('asn', '')} ({asn.get('org', '')})",
        f"- **Technologies:** {', '.join(str(t) for t in (ti.get('technologies') or [])) or '—'}",
        f"- **Subdomains:** {', '.join(str(s) for s in (ti.get('subdomains') or [])) or '—'}",
        "",
        "## Findings (Inventory)",
        "",
    ]
    inv = p.get("findings") or []
    if inv:
        L.append("| # | Severity | Title | CWE | CVSS |")
        L.append("|---|----------|-------|-----|------|")
        for i, row in enumerate(inv, 1):
            L.append(
                f"| {i} | {md_escape(row.get('severity'))} | {md_escape(row.get('title'))} "
                f"| {md_escape(row.get('cwe'))} | {md_escape(row.get('cvss'))} |"
            )
    else:
        L.append("_No findings._")
    L.append("")
    teaser = p.get("sample_finding") or {}
    if isinstance(teaser, dict) and teaser.get("title"):
        L += ["## Sample Finding", "", f"### {_clean(teaser.get('title'))}", ""]
        for key in ("severity", "cwe", "cvss", "asset", "what", "evidence", "why", "fix"):
            val = teaser.get(key)
            if val:
                L.append(f"- **{key.title()}:** {_clean(val)}")
        L.append("")
    L += ["---", "", str(p.get("upsell") or ""), ""]
    return ("\n".join(L)).encode("utf-8")


def generate_asgard_paid_markdown(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Paid-tier Markdown — the SAME ``build_asgard_payload`` projection as the
    Asgard JSON/HTML (full findings + TLS + headers + dark-web + OWASP + AI
    conclusions), so the paid Markdown stays at content parity with the other
    paid formats instead of falling through to the tier-blind renderer."""
    from src.reports.asgard_paid import build_asgard_payload
    from src.reports.valhalla_report_context import get_brand

    p = build_asgard_payload(data, jinja_context)
    brand = get_brand()
    meta = p.get("meta", {}) or {}
    sc = p.get("severity_counts", {}) or {}
    L: list[str] = [
        f"# {brand.name} — Security Assessment Report",
        "",
        f"**Tier:** {meta.get('tier_label') or 'ASGARD (Paid)'}  ",
        f"**Target:** {meta.get('target') or data.target or 'N/A'}  ",
        f"**Scan ID:** `{meta.get('scan_id') or data.scan_id or 'N/A'}`  ",
        f"**Generated:** {meta.get('generated_at') or ''}  ",
        "",
        "---",
        "",
        "## Severity Overview",
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---|---|---|---|---|",
        f"| {sc.get('critical',0)} | {sc.get('high',0)} | {sc.get('medium',0)} "
        f"| {sc.get('low',0)} | {sc.get('info',0)} |",
        "",
        "## Findings",
        "",
    ]
    for i, f in enumerate(p.get("findings") or [], 1):
        L.append(f"### {i}. {_clean(f.get('title'))}")
        L.append("")
        bits = [
            ("Severity", f.get("severity")),
            ("CWE", f.get("cwe")),
            ("OWASP", f.get("owasp")),
            ("CVSS", f"{f.get('cvss', '')} ({f.get('cvss_vector', '')})".strip()),
            ("Status", f.get("status")),
            ("Confidence", f.get("confidence")),
        ]
        L.append(" · ".join(f"**{k}:** {v}" for k, v in bits if str(v or "").strip() not in ("", "()")))
        if f.get("exploit_demonstrated"):
            L.append("")
            L.append(f"- **Exploitation:** {_clean(f.get('exploit_summary') or 'demonstrated')}")
        for label, key in (
            ("What", "what"),
            ("Why", "why"),
            ("Evidence", "evidence"),
            ("Negative control", "negative_control"),
            ("Validation", "validation"),
        ):
            val = f.get(key)
            if val:
                L.append(f"- **{label}:** {_clean(val)}")
        rem = f.get("remediation") or []
        if rem:
            L.append("- **Remediation:**")
            for step in rem:
                L.append(f"  - {_clean(step)}")
        L.append("")
    tls = p.get("tls_analysis") or {}
    L += ["## TLS & Transport", "", str(tls.get("summary") or "_Not assessed._"), ""]
    hdr = p.get("header_analysis") or {}
    L += ["## HTTP Security Headers", "", str(hdr.get("summary") or "_Not assessed._"), ""]
    dw = p.get("dark_web") or {}
    L += [
        "## Leaked-Credential / Dark-Web Monitoring",
        "",
        str(dw.get("summary") or "_Not collected._"),
        "",
        f"- **Monitored domain:** {dw.get('monitored_domain', '—')}",
        f"- **Sources checked:** {', '.join(str(s) for s in (dw.get('sources_checked') or [])) or '—'}",
        f"- **New exposures:** {dw.get('new_exposures', 0)} | "
        f"**Total tracked:** {dw.get('total_tracked', 0)}",
        "",
    ]
    # OWASP + AI sections render unconditionally (parity with the Asgard HTML/PDF,
    # which always carry sections 07/08 even when empty).
    owasp = p.get("owasp_alignment") or []
    L += ["## OWASP Top 10 Alignment", ""]
    if owasp:
        L += ["| Category | Count |", "|---|---|"]
        for row in owasp:
            L.append(f"| {md_escape(row.get('category'))} | {md_escape(row.get('count'))} |")
    else:
        L.append("_No OWASP Top 10 categories mapped._")
    L.append("")
    ai = p.get("ai_conclusions") or {}
    L += ["## AI Conclusions", ""]
    if ai.get("business_risk"):
        L += ["**Business risk:** " + _clean(ai.get("business_risk")), ""]
    if ai.get("vulnerability_description"):
        L += [_clean(ai.get("vulnerability_description")), ""]
    roadmap = ai.get("prioritized_roadmap") or []
    if isinstance(roadmap, list) and roadmap:
        L.append("**Prioritized roadmap:**")
        for step in roadmap:
            L.append(f"- {_clean(step)}")
        L.append("")
    if not any(ai.get(k) for k in ("vulnerability_description", "business_risk", "prioritized_roadmap")):
        L += ["_Not available._", ""]
    return ("\n".join(L)).encode("utf-8")
