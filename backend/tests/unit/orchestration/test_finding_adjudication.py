"""Wave 3 / etap 4b — the production reconcile that wires the arbiter into the
live tier-assignment path (R-5.1.2).

Proves the four safety properties of :func:`adjudicate_finding_tier`:
cap-only, in-domain-only, genuine-artifacts-only, and that the per-class bar is
folded in as the arbiter's gate.
"""

from __future__ import annotations

from src.orchestration.finding_adjudication import adjudicate_finding_tier
from src.pipeline.contracts.finding_dto import EvidenceTier

_GENUINE_HAR = "tenant/scan/run/har-0123456789abcdef.bin"


def test_out_of_domain_finding_is_untouched() -> None:
    # A fuzzer crash: no PoC artifact keys, no resolvable confirmation class.
    # Its locally-justified CONFIRMED tier must survive unchanged.
    finding = {
        "title": "Fuzz: crash in parse.c",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
    }
    adj = adjudicate_finding_tier(finding)
    assert adj.applicable is False
    assert adj.tier == int(EvidenceTier.CONFIRMED)
    assert adj.verdict is None


def test_classifiable_claim_with_no_artifacts_is_capped_to_informational() -> None:
    # The model called it CONFIRMED XSS but collected nothing — the hole wave 3
    # closes. In-domain (class resolves), no artifacts → INFORMATIONAL.
    finding = {
        "title": "Reflected XSS in search parameter",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {},
    }
    adj = adjudicate_finding_tier(finding)
    assert adj.applicable is True
    assert adj.tier == int(EvidenceTier.INFORMATIONAL)


def test_genuine_har_reaches_confirmed_tier() -> None:
    # A real content-addressed HAR + a browser-execution PoC (class bar met) →
    # CONFIRMED (no impact-proof artifact → not EXPLOITED).
    finding = {
        "title": "Reflected XSS in q",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {
            "har_evidence_key": _GENUINE_HAR,
            "verified_via_browser": True,
            "browser_alert_text": "1",
        },
    }
    adj = adjudicate_finding_tier(finding)
    assert adj.applicable is True
    assert adj.tier == int(EvidenceTier.CONFIRMED)


def test_hallucinated_har_key_does_not_count() -> None:
    # A PoC that merely *asserts* a HAR key that is not a content-addressed
    # object stores no genuine artifact — so even with the class bar "met", the
    # arbiter floor with zero real artifacts is INFORMATIONAL (a claim without a
    # stored artifact is information, not proof).
    finding = {
        "title": "Reflected XSS in q",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {
            "har_evidence_key": "definitely-a-real-har-trust-me",
            "verified_via_browser": True,
            "browser_alert_text": "1",
        },
    }
    adj = adjudicate_finding_tier(finding)
    assert adj.tier == int(EvidenceTier.INFORMATIONAL)


def test_cap_only_never_raises_above_model_tier() -> None:
    # Genuine HAR would justify CONFIRMED, but the model only claimed SUSPECTED.
    # The arbiter must not raise it — cap-only keeps SUSPECTED.
    finding = {
        "title": "Reflected XSS in q",
        "evidence_tier": int(EvidenceTier.SUSPECTED),
        "proof_of_concept": {
            "har_evidence_key": _GENUINE_HAR,
            "verified_via_browser": True,
            "browser_alert_text": "1",
        },
    }
    adj = adjudicate_finding_tier(finding)
    assert adj.arbiter_tier == int(EvidenceTier.CONFIRMED)
    assert adj.tier == int(EvidenceTier.SUSPECTED)


def test_xss_class_bar_not_met_caps_to_suspected() -> None:
    # Genuine HAR (raw exchange) but the XSS only reflected — never executed —
    # so the per-class bar caps it at SUSPECTED even with the HAR.
    finding = {
        "title": "Reflected XSS in q",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {"har_evidence_key": _GENUINE_HAR},
    }
    adj = adjudicate_finding_tier(finding)
    assert adj.tier == int(EvidenceTier.SUSPECTED)
    assert "class_bar_not_met" in adj.reasons


def test_idor_without_negative_control_is_capped() -> None:
    # IDOR mandates a negative control. A genuine HAR + cross-owner access but
    # no negative control → capped at SUSPECTED.
    finding = {
        "title": "IDOR on /api/orders/{id}",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {
            "har_evidence_key": _GENUINE_HAR,
            "cross_owner_access": True,
        },
    }
    adj = adjudicate_finding_tier(finding)
    assert adj.tier == int(EvidenceTier.SUSPECTED)
    assert "negative_control_missing" in adj.reasons


def test_idor_with_negative_control_confirms() -> None:
    finding = {
        "title": "IDOR on /api/orders/{id}",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {
            "har_evidence_key": _GENUINE_HAR,
            "cross_owner_access": True,
            "negative_control_result": "own object: 200, other: 403",
        },
    }
    adj = adjudicate_finding_tier(finding)
    assert adj.tier == int(EvidenceTier.CONFIRMED)


def test_bool_evidence_tier_is_rejected() -> None:
    # bool is an int subclass; True must not be read as tier 1.
    finding = {"title": "Fuzz: crash", "evidence_tier": True}
    adj = adjudicate_finding_tier(finding)
    assert adj.model_tier is None
