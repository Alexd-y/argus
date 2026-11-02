"""Target-Intelligence parity gate.

The session's report bugs were all one shape: a TI field was collected but lost on
the way to a tier (carrier had no field, a merge dropped it, a projection read the
wrong key, a tier had no block at all). This gate pins the invariant that would
have caught every one of them: given ONE populated report context, every TI field
is present and populated in each tier that shows it (Midgard and Asgard share the
``build_midgard_intel`` projector, so they must agree field-for-field).
"""

from __future__ import annotations

from src.reports.asgard_paid import build_asgard_payload
from src.reports.midgard_free import INTEL_NOT_ASSESSED, INTEL_NOT_COLLECTED, build_midgard_intel

# One fully-populated collected context (model_dump shapes, as the renderers see them).
_VC = {
    "ownership_evidence": {
        "whois_registrar": "WHC Online Solutions Inc.",
        "whois_org": "Svalbard Security",
        "whois_creation_date": "2023-07-19T03:40:57Z",
        "whois_expiry_date": "2027-07-19T03:40:57Z",
        "dns_ns_records": ["ns1.vercel-dns.com", "ns2.vercel-dns.com"],
        "dns_mx_records": ["svalbard-ca.mail.protection.outlook.com"],
        "dns_soa_primary_ns": "ns1.vercel-dns.com",
        "ip_whois_asn": "AS16509",
        "ip_whois_org": "amazon-02",
        "email_auth": {
            "dnssec": "Missing",
            "spf": "Present",
            "dmarc": "Present",
            "dkim": "Present",
        },
    },
    "ssl_tls_analysis": {
        "issuer": "YR1 (Let's Encrypt from US)",
        "subject": "*.svalbard.ca",
        "san": ["*.svalbard.ca", "svalbard.ca"],
        "valid_from": "2026-10-16",
        "valid_to": "2027-01-14",
        "protocols": ["TLS 1.2", "TLS 1.3"],
        "weak_protocols": [],
        "hsts": "max-age=63072000",
    },
}
_RECON = {
    "technologies": ["Vercel", "Html5"],
    "pipeline_subdomains": ["www.svalbard.ca", "mail.svalbard.ca"],
}
_CTX = {"valhalla_context": _VC, "recon_summary": _RECON}


class _RD:
    target = "https://svalbard.ca"
    created_at = "2026-11-02T00:00:00Z"
    technologies = ["Vercel", "Html5"]
    findings: list = []
    scan_id = "s1"
    report_id = "r1"
    tenant_id = "t1"


def _assert_ti_complete(ti: dict) -> None:
    assert ti["whois"]["registrar"] not in ("", INTEL_NOT_COLLECTED)
    assert ti["asn"]["asn"] == "AS16509"
    assert ti["dns"]["ns"] == ["ns1.vercel-dns.com", "ns2.vercel-dns.com"]
    assert ti["email_auth"] == {
        "dnssec": "Missing",
        "spf": "Present",
        "dmarc": "Present",
        "dkim": "Present",
    }
    assert all(v != INTEL_NOT_ASSESSED for v in ti["email_auth"].values())
    assert ti["tls"]["issuer"].startswith("YR1")
    assert ti["tls"]["subject"] == "*.svalbard.ca"
    assert ti["tls"]["sans"] == ["*.svalbard.ca", "svalbard.ca"]
    assert ti["tls"]["not_after"].startswith("2027-01-14")
    assert ti["tls"]["protocols"] == ["TLS 1.2", "TLS 1.3"]
    assert ti["technologies"] == ["Vercel", "Html5"]
    assert ti["subdomains"] == ["www.svalbard.ca", "mail.svalbard.ca"]


def test_midgard_ti_fully_populated_from_one_context() -> None:
    _assert_ti_complete(build_midgard_intel(_CTX, _RD()))


def test_asgard_ti_parity_with_midgard() -> None:
    # Asgard must carry the SAME Target-Intelligence block as Midgard, field-for-field.
    midgard_ti = build_midgard_intel(_CTX, _RD())
    payload = build_asgard_payload(_RD(), _CTX)
    assert "target_intelligence" in payload, "Asgard lost its Target Intelligence block"
    _assert_ti_complete(payload["target_intelligence"])
    assert payload["target_intelligence"] == midgard_ti  # exact parity


def test_asgard_tls_rows_reflect_the_certificate() -> None:
    payload = build_asgard_payload(_RD(), _CTX)
    rows = {r["check"]: r for r in payload["tls_analysis"]["rows"]}
    assert rows["Certificate Issuer"]["result"].startswith("YR1")
    assert rows["Certificate Subject"]["result"] == "*.svalbard.ca"
    assert "TLS 1.2" in rows["Negotiated protocols"]["result"]
