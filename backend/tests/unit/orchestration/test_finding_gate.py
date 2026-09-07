"""Unit tests for evidence gating + deduplication (Block 1.2 / 1.3).

Fixtures mirror the noise observed on the real alleksy.com scan
(91dfff21): ten evidence-less ``unknown finding`` records, WhatWeb
fingerprint-only hits, and duplicated TLS_PROBE / rate-limiting findings.
"""

from __future__ import annotations

from src.orchestration.finding_gate import (
    EvidenceQuality,
    dedupe_findings,
    evidence_quality_of,
    finding_key,
    gate_and_dedupe_findings,
    gate_findings,
)


def _tls_probe() -> dict:
    return {
        "title": "TLS_PROBE finding — https://alleksy.com/",
        "severity": "medium",
        "description": "TLS_PROBE; Matched: alleksy.com:443",
        "source_tool": "testssl",
        "proof_of_concept": {"url": "https://alleksy.com/"},
    }


def _rate_limit() -> dict:
    return {
        "title": "No HTTP 429 observed on rapid login-path requests — https://alleksy.com/login",
        "severity": "low",
        "description": "Rate limiting probe against /login",
        "source_tool": "web_vuln_heuristics",
        "proof_of_concept": {"url": "https://alleksy.com/login"},
    }


def _unknown() -> dict:
    return {"title": "unknown finding", "severity": "info", "description": ""}


def _whatweb_fingerprint() -> dict:
    return {
        "title": "WHATWEB_PLUGIN finding — https://alleksy.com/",
        "severity": "info",
        "description": "",
        "source_tool": "whatweb",
    }


def _real_xss() -> dict:
    return {
        "title": "Reflected XSS — https://alleksy.com/search?q=",
        "severity": "high",
        "description": "Reflected XSS via q parameter",
        "cwe": "CWE-79",
        "cvss": 7.2,
        "source_tool": "dalfox",
        "proof_of_concept": {
            "url": "https://alleksy.com/search?q=<script>alert(1)</script>",
            "curl_command": "curl -v 'https://alleksy.com/search?q=<script>alert(1)</script>'",
        },
        "evidence": "REQUEST: GET /search?q=... RESPONSE: <script>alert(1)</script> reflected",
    }


class TestEvidenceQuality:
    def test_placeholder_title_is_none(self):
        assert evidence_quality_of(_unknown()) == EvidenceQuality.NONE

    def test_fingerprint_without_evidence_is_none(self):
        assert evidence_quality_of(_whatweb_fingerprint()) == EvidenceQuality.NONE

    def test_poc_plus_evidence_is_strong(self):
        assert evidence_quality_of(_real_xss()) == EvidenceQuality.STRONG

    def test_poc_only_is_moderate(self):
        assert evidence_quality_of(_tls_probe()) == EvidenceQuality.MODERATE

    def test_description_only_is_weak(self):
        finding = {
            "title": "Verbose error message",
            "description": "Application returned a stack trace on 500",
            "source_tool": "web_vuln_heuristics",
        }
        assert evidence_quality_of(finding) == EvidenceQuality.WEAK


class TestGate:
    def test_unknown_findings_are_dropped(self):
        findings = [_unknown() for _ in range(10)] + [_real_xss()]
        kept, dropped = gate_findings(findings)
        assert len(dropped) == 10
        assert len(kept) == 1
        assert kept[0]["title"].startswith("Reflected XSS")

    def test_fingerprint_only_dropped(self):
        kept, dropped = gate_findings([_whatweb_fingerprint()])
        assert kept == []
        assert len(dropped) == 1

    def test_evidence_quality_annotated(self):
        kept, _ = gate_findings([_real_xss()])
        assert kept[0]["evidence_quality"] == "strong"


class TestDedupe:
    def test_duplicate_tls_collapses_to_one(self):
        result = dedupe_findings([_tls_probe(), _tls_probe()])
        assert len(result) == 1
        assert result[0]["occurrences"] == 2

    def test_duplicate_rate_limit_collapses_to_one(self):
        result = dedupe_findings([_rate_limit(), _rate_limit()])
        assert len(result) == 1
        assert result[0]["occurrences"] == 2

    def test_distinct_findings_not_merged(self):
        result = dedupe_findings([_tls_probe(), _rate_limit()])
        assert len(result) == 2

    def test_finding_key_stable_across_url_variants(self):
        a = _tls_probe()
        b = _tls_probe()
        b["title"] = "TLS_PROBE finding — https://alleksy.com/?utm=1"
        b["proof_of_concept"] = {"url": "https://alleksy.com/?utm=1"}
        assert finding_key(a) == finding_key(b)

    def test_merge_keeps_strongest_severity(self):
        low = _tls_probe()
        low["severity"] = "low"
        high = _tls_probe()
        high["severity"] = "high"
        result = dedupe_findings([low, high])
        assert result[0]["severity"] == "high"


class TestMetaNoiseAndSemantic:
    def test_meta_unknown_with_description_is_dropped(self):
        findings = [
            {
                "title": "Unknown finding with insufficient evidence",
                "severity": "info",
                "description": "Ten findings labeled unknown with no details.",
            },
            {
                "title": "Insufficient evidence for unknown informational findings",
                "severity": "info",
                "description": "Multiple informational findings without detail.",
            },
            _real_xss(),
        ]
        kept = gate_and_dedupe_findings(findings, scan_id="t")
        titles = [f["title"] for f in kept]
        assert len(kept) == 1
        assert titles[0].startswith("Reflected XSS")

    def test_paraphrased_rate_limit_collapse_to_one(self):
        findings = [
            {"title": "No HTTP 429 observed on rapid login-path requests", "severity": "high",
             "source_tool": "web_vuln_heuristics", "proof_of_concept": {"url": "https://alleksy.com/login"}},
            {"title": "No Rate Limiting on Login Path", "severity": "medium",
             "description": "Rapid requests to /login did not trigger 429.",
             "proof_of_concept": {"url": "https://alleksy.com/login"}},
            {"title": "Missing rate limiting on login endpoint", "severity": "low",
             "description": "brute-force possible", "proof_of_concept": {"url": "https://alleksy.com/login"}},
        ]
        kept = gate_and_dedupe_findings(findings, scan_id="t")
        assert len(kept) == 1
        assert kept[0]["occurrences"] == 3
        assert kept[0]["severity"] == "high"  # strongest kept

    def test_paraphrased_tls_collapse_to_one(self):
        findings = [
            _tls_probe(),
            {"title": "TLS Configuration Probe", "severity": "medium",
             "description": "weak TLS config", "proof_of_concept": {"url": "https://alleksy.com/"}},
            {"title": "TLS configuration weakness detected", "severity": "low",
             "description": "ssl/tls potential issue", "proof_of_concept": {"url": "https://alleksy.com/"}},
        ]
        kept = gate_and_dedupe_findings(findings, scan_id="t")
        assert len(kept) == 1

    def test_distinct_email_findings_not_merged(self):
        findings = [
            {"title": "SPF not enforced (~all) — alleksy.com", "severity": "low",
             "source_tool": "dns_recon", "description": "SPF record uses ~all (softfail).",
             "evidence": "v=spf1 include:_spf.google.com ~all"},
            {"title": "DMARC has no aggregate reporting (rua) — alleksy.com", "severity": "low",
             "source_tool": "dns_recon", "description": "DMARC defines no rua= address.",
             "evidence": "v=DMARC1; p=reject"},
            {"title": "DKIM not detected — alleksy.com", "severity": "low",
             "source_tool": "dns_recon", "description": "No DKIM key across probed selectors.",
             "evidence": "probed: default, google, k1"},
        ]
        kept = gate_and_dedupe_findings(findings, scan_id="t")
        assert len(kept) == 3  # SPF/DMARC/DKIM are distinct, not a semantic class


class TestComposed:
    def test_real_scan_noise_reduced(self):
        """The 91dfff21 case: 10 unknown + 2 TLS + 2 rate-limit + 1 xss -> 3 clean."""
        findings = (
            [_unknown() for _ in range(10)]
            + [_tls_probe(), _tls_probe()]
            + [_rate_limit(), _rate_limit()]
            + [_real_xss()]
        )
        result = gate_and_dedupe_findings(findings, scan_id="test")
        titles = [f["title"].split(" — ")[0] for f in result]
        assert len(result) == 3
        assert "unknown finding" not in [t.lower() for t in titles]
        assert titles.count("TLS_PROBE finding") == 1

    def test_disabled_returns_all_but_annotates(self):
        findings = [_unknown(), _real_xss()]
        result = gate_and_dedupe_findings(findings, enabled=False)
        assert len(result) == 2
        assert all("evidence_quality" in f for f in result)
