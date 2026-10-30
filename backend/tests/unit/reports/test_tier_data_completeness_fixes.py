"""QA regression guards for the plan×tier report data-completeness fixes.

Covers: free-tier Markdown tier isolation (no paid-layer leak), free-tier Target
Intelligence reads the nested ownership_evidence, and the Asgard XML carries the
exploitation outcome + dark-web rows at parity with the Asgard JSON/HTML.
"""

from __future__ import annotations

from src.api.schemas import Finding
from src.reports.asgard_xml import generate_asgard_paid_xml
from src.reports.generators import ReportData, generate_markdown
from src.reports.midgard_free import INTEL_NOT_COLLECTED, build_midgard_intel
from src.reports.report_bundle import ReportTier
from src.reports.tier_classifier import classify_for_tier

_SECRET_DESC = "SENSITIVE internal detail — DB creds path /etc/argus/secret"
_SECRET_CMD = "sqlmap -u https://x.test/?id=1 --dump --batch --os-shell"


def _finding(**kw) -> Finding:
    base = dict(severity="high", title="SQLi on id", description=_SECRET_DESC, cwe="CWE-89", cvss=8.1)
    base.update(kw)
    return Finding(**base)


def _report_data(findings) -> ReportData:
    return ReportData(
        report_id="r-qa",
        target="https://x.test",
        summary=None,
        findings=findings,
        technologies=["nginx"],
        executive_summary="Exec summary.",
    )


def test_midgard_markdown_does_not_leak_paid_layer() -> None:
    # Two findings: the free tier shows at most ONE teaser writeup, so the SECOND
    # finding's description must never be rendered, and the internal verification
    # command / AI-analysis block must never appear for ANY finding.
    f1 = _finding(verification_command=_SECRET_CMD)
    f2 = _finding(
        title="IDOR on orders",
        description="SECOND secret description — must not be dumped",
        cwe="CWE-639",
        verification_command="curl https://x.test/orders/2 -H 'Authorization: stolen'",
    )
    data = _report_data([f1, f2])
    proj = classify_for_tier(data, ReportTier.MIDGARD)
    md = generate_markdown(proj, tier="midgard").decode("utf-8")
    # Both titles appear in the inventory…
    assert "SQLi on id" in md and "IDOR on orders" in md
    # …but NO verification command, no stolen-auth repro, no per-finding AI block,
    # and not every finding's description is dumped (the second one stays hidden).
    assert _SECRET_CMD not in md
    assert "--os-shell" not in md
    assert "stolen" not in md
    assert "## Analysis" not in md
    # Only the single shared teaser writeup may show a description — never a full
    # per-finding dump. So at most ONE of the two descriptions appears.
    shown = (_SECRET_DESC in md) + ("SECOND secret description" in md)
    assert shown <= 1, f"free markdown dumped more than the one teaser writeup ({shown})"


def test_asgard_markdown_carries_paid_sections() -> None:
    data = _report_data([_finding()])
    proj = classify_for_tier(data, ReportTier.ASGARD)
    md = generate_markdown(proj, tier="asgard").decode("utf-8")
    for marker in ("## Findings", "TLS", "HTTP Security Headers", "Dark-Web", "OWASP", "AI Conclusions"):
        assert marker in md, f"asgard markdown missing section: {marker}"


def test_midgard_intel_reads_nested_ownership_evidence() -> None:
    vc = {
        "ownership_evidence": {
            "whois_registrar": "MarkMonitor",
            "whois_org": "Example Corp",
            "dns_ns_records": ["ns1.example", "ns2.example"],
            "dns_mx_records": ["mx1.example"],
            "ip_whois_asn": "AS15169",
            "ip_whois_org": "Example Hosting",
        }
    }
    intel = build_midgard_intel({"valhalla_context": vc}, _report_data([]))
    assert intel["whois"]["registrar"] == "MarkMonitor"
    assert intel["whois"]["registrant_org"] == "Example Corp"
    assert intel["dns"]["ns"] == ["ns1.example", "ns2.example"]
    assert intel["dns"]["mx"] == ["mx1.example"]
    assert intel["asn"]["asn"] == "AS15169"
    assert intel["asn"]["org"] == "Example Hosting"
    # Sanity: without ownership_evidence it still degrades gracefully.
    empty = build_midgard_intel({"valhalla_context": {}}, _report_data([]))
    assert empty["whois"]["registrar"] == INTEL_NOT_COLLECTED


def test_asgard_branded_pdf_html_escapes_injected_markup() -> None:
    # The Asgard branded PDF template renders dynamic finding text without explicit
    # ``| e`` because its Jinja environment (_render_branded_pdf_html) runs with
    # autoescape=True. Guard that invariant: a finding whose evidence/title carry
    # HTML/script/file:// markup must be escaped in the rendered PDF HTML, never
    # emitted as live markup (defence-in-depth on top of the chromium backend,
    # which also disables JS and blocks network/file fetches).
    from src.reports.generators import (
        _build_branded_pdf_context,
        _render_branded_pdf_html,
        _resolve_branded_pdf_template_path,
    )

    payload = "<script>alert(1)</script><img src=file:///etc/passwd>"
    f = _finding(title=payload, description=payload)
    data = _report_data([f])
    proj = classify_for_tier(data, ReportTier.ASGARD)
    tpl = _resolve_branded_pdf_template_path("asgard")
    assert tpl is not None, "asgard branded PDF template missing"
    ctx = _build_branded_pdf_context(proj, None, tier="asgard")
    html = _render_branded_pdf_html(tpl, ctx)
    # No LIVE markup: the tags must be escaped, not emitted as real elements.
    assert "<script>alert(1)</script>" not in html
    assert "<img src=file:///etc/passwd>" not in html
    assert "&lt;script&gt;" in html  # escaped form is present
    assert "&lt;img src=file:///etc/passwd&gt;" in html


def test_free_canonical_bundle_has_no_per_finding_detail() -> None:
    # B3 made the free Midgard inventory list ALL findings; the canonical snapshot
    # renders findings in full, so the free canonical_* artifacts must redact every
    # finding's paid detail (description/impact/PoC/verification), leaving inventory
    # only. Guards redact_free_canonical_finding (used in _rgp_canonical_snapshot).
    from dataclasses import replace as dcr

    from src.reports.report_pipeline import redact_free_canonical_finding
    from src.reports.snapshot_builder import build_snapshot_from_report_data

    f = _finding(
        description="SECRETDESC_detail",
        proof_of_concept={"reproducer": "SECRETPOC_cmd", "payload": "x"},
        verification_command="SECRETVERIFY_cmd",
        observed_impact="SECRETIMPACT_text",
    )
    data = _report_data([f, f, f])
    pm = classify_for_tier(data, ReportTier.MIDGARD)
    pm = dcr(pm, findings=[redact_free_canonical_finding(x) for x in pm.findings])
    js = build_snapshot_from_report_data(pm).model_dump_json()
    for secret in ("SECRETDESC_detail", "SECRETPOC_cmd", "SECRETVERIFY_cmd", "SECRETIMPACT_text"):
        assert secret not in js, f"free canonical bundle leaked {secret}"


def test_asgard_xml_carries_exploit_outcome() -> None:
    f = _finding(exploit_demonstrated=True, exploit_summary="Proven via boolean-blind SQLi")
    data = _report_data([f])
    proj = classify_for_tier(data, ReportTier.ASGARD)
    xml = generate_asgard_paid_xml(proj).decode("utf-8")
    assert "<exploit_demonstrated>true</exploit_demonstrated>" in xml
    # dark-web section always carries the (possibly empty) rows container now.
    assert "<rows>" in xml and "</dark_web>" in xml
