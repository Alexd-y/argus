"""Paid-tier (Asgard) XML serializer.

Extracted from ``generators.py`` (module-size ratchet) so the Asgard XML stays at
content parity with the Asgard JSON/HTML. Reads ONLY ``build_asgard_payload`` and
assembles XML by hand with escaping (no XML parser → no XXE surface).
"""

from __future__ import annotations

from typing import Any

from src.reports.generators import ReportData


def generate_asgard_paid_xml(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Paid-tier XML — ``<argus_report tier="asgard">`` with per-finding location.

    Fixes the memory defect where ``<finding>`` carried no location: every
    finding element nests ``<location><asset>``. Built by string assembly with
    XML-escaping — no XML parser, so no XXE surface.
    """
    from xml.sax.saxutils import escape, quoteattr

    from src.reports.asgard_paid import build_asgard_payload

    p = build_asgard_payload(data, jinja_context)

    def esc(v: Any) -> str:
        return escape("" if v is None else str(v))

    out: list[str] = ['<?xml version="1.0" encoding="utf-8"?>']
    out.append('<argus_report tier="asgard" schema="asgard-v1">')
    # meta
    out.append("  <meta>")
    for k, v in p["meta"].items():
        out.append(f"    <{k}>{esc(v)}</{k}>")
    out.append("  </meta>")
    # severity counts
    out.append("  <severity_counts>")
    for sev in ("critical", "high", "medium", "low", "info"):
        out.append(f'    <count severity="{sev}">{int(p["severity_counts"].get(sev, 0))}</count>')
    out.append("  </severity_counts>")
    # findings
    out.append(f'  <findings count="{len(p["findings"])}">')
    for f in p["findings"]:
        out.append(
            f'    <finding id={quoteattr(str(f.get("id", "")))} severity={quoteattr(str(f.get("severity", "")))}>'
        )
        out.append(f"      <title>{esc(f.get('title'))}</title>")
        out.append(f"      <cwe>{esc(f.get('cwe'))}</cwe>")
        out.append(f"      <owasp>{esc(f.get('owasp'))}</owasp>")
        if f.get("cvss") is not None:
            out.append(f"      <cvss>{esc(f.get('cvss'))}</cvss>")
        if f.get("cvss_vector"):
            out.append(f"      <cvss_vector>{esc(f.get('cvss_vector'))}</cvss_vector>")
        out.append("      <location>")
        out.append(f"        <asset>{esc(f.get('asset'))}</asset>")
        out.append("      </location>")
        out.append(f"      <status>{esc(f.get('status'))}</status>")
        out.append(f"      <confidence>{esc(f.get('confidence'))}</confidence>")
        # Exploitation outcome — present in the Asgard JSON/HTML; was missing from
        # XML, so the XML under-reported which findings were actually proven.
        out.append(
            f"      <exploit_demonstrated>{esc(str(bool(f.get('exploit_demonstrated'))).lower())}</exploit_demonstrated>"
        )
        if f.get("exploit_summary"):
            out.append(f"      <exploit_summary>{esc(f.get('exploit_summary'))}</exploit_summary>")
        out.append(f"      <what>{esc(f.get('what'))}</what>")
        out.append(f"      <why>{esc(f.get('why'))}</why>")
        out.append(f"      <evidence>{esc(f.get('evidence'))}</evidence>")
        if f.get("negative_control"):
            out.append(
                f"      <negative_control>{esc(f.get('negative_control'))}</negative_control>"
            )
        out.append("      <remediation>")
        for step in f.get("remediation", []) or []:
            out.append(f"        <step>{esc(step)}</step>")
        out.append("      </remediation>")
        out.append(f"      <validation>{esc(f.get('validation'))}</validation>")
        out.append("    </finding>")
    out.append("  </findings>")
    # paid sections
    tls = p["tls_analysis"]
    out.append("  <tls_analysis>")
    out.append(f"    <summary>{esc(tls.get('summary'))}</summary>")
    for r in tls.get("rows", []):
        out.append(
            f'    <row check={quoteattr(str(r.get("check", "")))} status={quoteattr(str(r.get("status", "")))}>'
            f"{esc(r.get('result'))}</row>"
        )
    out.append("  </tls_analysis>")
    hdr = p["header_analysis"]
    out.append("  <header_analysis>")
    out.append(f"    <summary>{esc(hdr.get('summary'))}</summary>")
    for r in hdr.get("rows", []):
        out.append(
            f'    <header name={quoteattr(str(r.get("header", "")))} present={quoteattr(str(bool(r.get("present"))).lower())}>'
            f"{esc(r.get('recommended'))}</header>"
        )
    out.append("  </header_analysis>")
    dw = p["dark_web"]
    out.append("  <dark_web>")
    out.append(f"    <summary>{esc(dw.get('summary'))}</summary>")
    out.append(f"    <monitored_domain>{esc(dw.get('monitored_domain'))}</monitored_domain>")
    out.append("    <sources_checked>")
    for s in dw.get("sources_checked", []) or []:
        out.append(f"      <source>{esc(s)}</source>")
    out.append("    </sources_checked>")
    out.append(f"    <new_exposures>{esc(dw.get('new_exposures'))}</new_exposures>")
    out.append(f"    <total_tracked>{esc(dw.get('total_tracked'))}</total_tracked>")
    out.append(f"    <last_checked>{esc(dw.get('last_checked'))}</last_checked>")
    if dw.get("status") is not None:
        out.append(f"    <status>{esc(dw.get('status'))}</status>")
    # Exposure rows — present in the Asgard JSON/HTML; were dropped from XML, so a
    # DWM sweep that returned exposures left the XML dark-web section empty.
    out.append("    <rows>")
    for r in dw.get("rows", []) or []:
        out.append("      <exposure>")
        if isinstance(r, dict):
            for rk, rv in r.items():
                out.append(f"        <{rk}>{esc(rv)}</{rk}>")
        out.append("      </exposure>")
    out.append("    </rows>")
    out.append("  </dark_web>")
    out.append("  <owasp_alignment>")
    for r in p["owasp_alignment"]:
        out.append(
            f'    <category count="{int(r.get("count", 0))}">{esc(r.get("category"))}</category>'
        )
    out.append("  </owasp_alignment>")
    ai = p["ai_conclusions"]
    out.append("  <ai_conclusions>")
    out.append(
        f"    <vulnerability_description>{esc(ai.get('vulnerability_description'))}</vulnerability_description>"
    )
    out.append(f"    <business_risk>{esc(ai.get('business_risk'))}</business_risk>")
    out.append("    <prioritized_roadmap>")
    for step in ai.get("prioritized_roadmap", []) or []:
        out.append(f"      <step>{esc(step)}</step>")
    out.append("    </prioritized_roadmap>")
    out.append("  </ai_conclusions>")
    out.append("</argus_report>")
    return ("\n".join(out) + "\n").encode("utf-8")
