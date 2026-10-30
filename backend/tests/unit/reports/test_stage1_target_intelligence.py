"""Stage-1 recon persistence feeds the report Target Intelligence panel.

Regression: the live scan never persisted recon_results.json, so WHOIS/DNS/ASN/
email-auth were empty in every report. This checks the mapper → ownership_evidence
→ Target Intelligence chain so the data actually reaches the free Midgard TI block.
"""

from __future__ import annotations

from src.orchestration.handlers import build_stage1_recon_results
from src.reports.midgard_free import INTEL_NOT_COLLECTED, build_midgard_intel
from src.reports.ownership_evidence import build_ownership_evidence


class _ReconOut:
    def __init__(self) -> None:
        self.tool_results = {
            "whois": {
                "stdout": (
                    "Registrar: MarkMonitor Inc.\n"
                    "Registrant Organization: Example Holdings Ltd\n"
                    "Creation Date: 2001-05-03T00:00:00Z\n"
                    "Registry Expiry Date: 2030-05-03T00:00:00Z\n"
                )
            },
            "dig": {
                "stdout": (
                    "example.com.\t3600\tIN\tNS\tns1.example.net.\n"
                    "example.com.\t3600\tIN\tNS\tns2.example.net.\n"
                    "example.com.\t3600\tIN\tMX\t10 mail.example.com.\n"
                    "example.com.\t3600\tIN\tSOA\tns1.example.net. host.example.com. 1 2 3 4 5\n"
                )
            },
            "asn_summary": {"asn": "AS15169", "org": "Example Hosting", "country": "US"},
            "dns_security_findings": [
                {"vuln_type": "dnssec_missing", "title": "DNSSEC not enabled"},
                {"title": "DMARC record missing"},
            ],
        }
        self.technologies = ["nginx", "wordpress"]
        self.assets = ["example.com"]
        self.subdomains = ["www.example.com"]


def test_stage1_recon_results_feed_ownership_evidence() -> None:
    rr = build_stage1_recon_results("example.com", _ReconOut())
    oe = build_ownership_evidence("https://example.com", rr)
    d = oe.model_dump() if hasattr(oe, "model_dump") else oe
    assert d["whois_registrar"] == "MarkMonitor Inc."
    assert "Example Holdings" in d["whois_org"]
    assert d["dns_ns_records"] == ["ns1.example.net", "ns2.example.net"]
    assert d["dns_mx_records"] == ["mail.example.com"]
    assert d["ip_whois_asn"] == "AS15169"
    assert d["ip_whois_org"] == "Example Hosting"


def test_target_intelligence_populated_from_stage1() -> None:
    rr = build_stage1_recon_results("example.com", _ReconOut())
    oe = build_ownership_evidence("https://example.com", rr)
    # valhalla_context the report passes to build_midgard_intel carries the nested
    # ownership_evidence (model_dump() of it in production); build_midgard_intel
    # reads WHOIS/DNS/ASN from there.
    vc = {"ownership_evidence": oe.model_dump() if hasattr(oe, "model_dump") else oe}

    class _RD:
        technologies = ["nginx", "wordpress"]

    intel = build_midgard_intel({"valhalla_context": vc, "recon_summary": {}}, _RD())
    assert intel["whois"]["registrar"] == "MarkMonitor Inc."
    assert intel["whois"]["registrar"] != INTEL_NOT_COLLECTED
    assert intel["dns"]["ns"] == ["ns1.example.net", "ns2.example.net"]
    assert intel["asn"]["asn"] == "AS15169"


def test_email_auth_derived_and_persisted_in_recon_results() -> None:
    # email-auth verdicts are derived from the DNS-security findings and PERSISTED
    # in recon_results.json (ready for the TI email-auth panel). NOTE: surfacing
    # them in the rendered panel needs a context carrier (follow-up) — tracked.
    rr = build_stage1_recon_results("example.com", _ReconOut())
    assert rr["email_auth"]["dnssec"] == "Missing"
    assert rr["email_auth"]["dmarc"] == "Missing"
