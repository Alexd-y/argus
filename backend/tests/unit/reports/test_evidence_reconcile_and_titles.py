"""VHL-PROVABLE-001 / VHL-TITLE-001 — evidence-view reconciliation and title humanization.

Covers the historical "confidence mixed with verification_status" bug: a finding
with ``evidence_quality == "none"`` must never be ``is_provable`` and its
confidence must be clamped to at most ``possible`` (not above the SUSPECTED
tier), regardless of the confidence persisted on the DB row.
"""

from __future__ import annotations

from src.reports.evidence_partition import (
    clamp_confidence_to_evidence,
    reconcile_finding_evidence_view,
)
from src.reports.finding_title_normalizer import humanize_finding_title


class TestClampConfidenceToEvidence:
    def test_none_quality_caps_at_possible(self) -> None:
        assert clamp_confidence_to_evidence("none", "confirmed") == "possible"

    def test_moderate_quality_caps_at_likely(self) -> None:
        assert clamp_confidence_to_evidence("moderate", "confirmed") == "likely"

    def test_weak_quality_caps_at_possible(self) -> None:
        assert clamp_confidence_to_evidence("weak", "likely") == "possible"

    def test_strong_quality_keeps_confirmed(self) -> None:
        assert clamp_confidence_to_evidence("strong", "confirmed") == "confirmed"

    def test_never_upgrades_confidence(self) -> None:
        # Strong evidence but an advisory declared confidence is not inflated.
        assert clamp_confidence_to_evidence("strong", "advisory") == "advisory"

    def test_blank_declared_defaults_to_cap(self) -> None:
        assert clamp_confidence_to_evidence("none", "") == "possible"
        assert clamp_confidence_to_evidence("moderate", None) == "likely"


class TestReconcileFindingEvidenceView:
    def test_evidence_none_is_not_provable_and_confidence_clamped(self) -> None:
        # WhatWeb fingerprint hit: PoC has only a URL (no raw request/response),
        # no refs → evidence quality NONE, yet DB confidence is "confirmed".
        finding = {
            "title": "WHATWEB_PLUGIN finding",
            "confidence": "confirmed",
            "proof_of_concept": {"url": "https://alleksy.com"},
        }
        view = reconcile_finding_evidence_view(finding)
        assert view["evidence_quality"] == "none"
        assert view["is_provable"] is False
        assert view["confidence"] == "possible"  # not above SUSPECTED
        assert view["evidence_classification"] == "inconclusive"
        assert view["validation_status"] == "missing"
        assert view["unconfirmed_reason"]  # non-empty explanation

    def test_observed_finding_stays_provable(self) -> None:
        # Missing-header observation demonstrated by a raw request/response pair.
        finding = {
            "title": "Missing Content-Security-Policy header",
            "confidence": "likely",
            "proof_of_concept": {
                "request": "GET / HTTP/1.1",
                "response": "HTTP/1.1 200 OK",
            },
            "evidence_refs": ["minio://artifacts/req-1"],
        }
        view = reconcile_finding_evidence_view(finding)
        assert view["evidence_quality"] in ("moderate", "strong")
        assert view["evidence_classification"] == "observed"
        assert view["is_provable"] is True
        assert view["confidence"] in ("likely", "confirmed")
        assert view["unconfirmed_reason"] is None

    def test_pretagged_quality_is_respected(self) -> None:
        finding = {
            "title": "Some finding",
            "confidence": "confirmed",
            "evidence_quality": "none",
        }
        view = reconcile_finding_evidence_view(finding)
        assert view["is_provable"] is False
        assert view["confidence"] == "possible"


class TestHumanizeFindingTitle:
    def test_whatweb_plugin_token(self) -> None:
        assert (
            humanize_finding_title("WHATWEB_PLUGIN finding")
            == "Technology fingerprint (WhatWeb)"
        )

    def test_tls_probe_token_preserves_locator_suffix(self) -> None:
        assert (
            humanize_finding_title("TLS_PROBE finding — https://alleksy.com")
            == "TLS/SSL configuration observation — https://alleksy.com"
        )

    def test_unknown_raw_token_is_title_cased(self) -> None:
        assert humanize_finding_title("SOME_RAW_TYPE finding") == "Some Raw Type"

    def test_bare_token_without_finding_word(self) -> None:
        assert humanize_finding_title("TLS_PROBE") == "TLS/SSL configuration observation"

    def test_human_title_unchanged(self) -> None:
        assert (
            humanize_finding_title("SQL Injection in login form")
            == "SQL Injection in login form"
        )

    def test_empty_falls_back_to_vuln_type(self) -> None:
        assert humanize_finding_title("", "tls_probe") == "TLS/SSL configuration observation"
        assert humanize_finding_title(None) == "Security finding"

    def test_idempotent(self) -> None:
        once = humanize_finding_title("WHATWEB_PLUGIN finding — https://x")
        assert humanize_finding_title(once) == once
