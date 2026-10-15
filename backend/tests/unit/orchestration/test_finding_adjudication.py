"""Wave 3 / etap 4b — the production reconcile that wires the arbiter into the
live tier-assignment path (R-5.1.2).

Proves the safety properties of :func:`adjudicate_finding_tier`: cap-only,
in-domain-only (active classes / verified artifacts), verified-artifacts-only
(a shape-valid but nonexistent key is NOT credited — the critical integrity
gate), and that the per-class bar is folded in as the arbiter's gate.
"""

from __future__ import annotations

from src.orchestration.finding_adjudication import adjudicate_finding_tier
from src.pipeline.contracts.finding_dto import EvidenceTier

_GENUINE_HAR = "tenant/scan/evidence/har-0123456789abcdef.bin"
_GENUINE_SHOT = "tenant/scan/evidence/screenshot-aabbccddeeff0011.bin"


# A verifier that only vouches for the two genuinely-"stored" keys above.
def _verify(key: str) -> bool:
    return key in (_GENUINE_HAR, _GENUINE_SHOT)


def test_out_of_domain_finding_is_untouched() -> None:
    # A fuzzer crash: no artifact keys, no resolvable confirmation class.
    finding = {"title": "Fuzz: crash in parse.c", "evidence_tier": int(EvidenceTier.CONFIRMED)}
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.applicable is False
    assert adj.tier == int(EvidenceTier.CONFIRMED)
    assert adj.verdict is None


def test_passive_class_without_artifacts_is_untouched() -> None:
    # TLS/headers finding — passive class, not the arbiter's raw-exchange domain.
    # Its model tier must survive (the arbiter must not demote passive findings).
    finding = {
        "title": "Missing security header: Strict-Transport-Security (TLS)",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
    }
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.applicable is False
    assert adj.tier == int(EvidenceTier.CONFIRMED)


def test_active_class_claim_with_no_artifacts_is_capped_to_informational() -> None:
    # The model called it CONFIRMED XSS but collected nothing — in-domain (active
    # class), no artifacts → INFORMATIONAL.
    finding = {
        "title": "Reflected XSS in search parameter",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {},
    }
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.applicable is True
    assert adj.tier == int(EvidenceTier.INFORMATIONAL)


def test_verified_har_reaches_confirmed_tier() -> None:
    finding = {
        "title": "Reflected XSS in q",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {
            "har_evidence_key": _GENUINE_HAR,
            "verified_via_browser": True,
            "browser_alert_text": "1",
        },
    }
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.tier == int(EvidenceTier.CONFIRMED)


def test_verified_har_plus_screenshot_reaches_exploited() -> None:
    finding = {
        "title": "Reflected XSS in q",
        "evidence_tier": int(EvidenceTier.EXPLOITED),
        "proof_of_concept": {
            "har_evidence_key": _GENUINE_HAR,
            "screenshot_key": _GENUINE_SHOT,
            "verified_via_browser": True,
            "browser_alert_text": "1",
        },
    }
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.tier == int(EvidenceTier.EXPLOITED)


def test_shape_valid_but_unverified_har_is_NOT_credited() -> None:
    # THE integrity gate (critical fix): a content-addressed-SHAPED key that the
    # store cannot confirm must not lift the tier. A model forging
    # har_evidence_key gets INFORMATIONAL, not CONFIRMED.
    forged = "tenant/scan/evidence/har-ffffffffffffffff.bin"  # well-shaped, not "stored"
    finding = {
        "title": "Reflected XSS in q",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {
            "har_evidence_key": forged,
            "verified_via_browser": True,
            "browser_alert_text": "1",
        },
    }
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.tier == int(EvidenceTier.INFORMATIONAL)


def test_no_verifier_is_fail_closed() -> None:
    # With no verifier, even a genuine-looking key is not credited (fail-closed).
    finding = {
        "title": "Reflected XSS in q",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {
            "har_evidence_key": _GENUINE_HAR,
            "verified_via_browser": True,
            "browser_alert_text": "1",
        },
    }
    adj = adjudicate_finding_tier(finding)  # no verify_artifact
    assert adj.tier == int(EvidenceTier.INFORMATIONAL)


def test_cap_only_never_raises_above_model_tier() -> None:
    finding = {
        "title": "Reflected XSS in q",
        "evidence_tier": int(EvidenceTier.SUSPECTED),
        "proof_of_concept": {
            "har_evidence_key": _GENUINE_HAR,
            "verified_via_browser": True,
            "browser_alert_text": "1",
        },
    }
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.arbiter_tier == int(EvidenceTier.CONFIRMED)
    assert adj.tier == int(EvidenceTier.SUSPECTED)


def test_xss_class_bar_not_met_caps_to_suspected() -> None:
    # Verified HAR (raw exchange) but XSS only reflected — class bar caps SUSPECTED.
    finding = {
        "title": "Reflected XSS in q",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {"har_evidence_key": _GENUINE_HAR},
    }
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.tier == int(EvidenceTier.SUSPECTED)
    assert "class_bar_not_met" in adj.reasons


def test_idor_without_negative_control_is_capped() -> None:
    finding = {
        "title": "IDOR on /api/orders/{id}",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "proof_of_concept": {"har_evidence_key": _GENUINE_HAR, "cross_owner_access": True},
    }
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
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
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.tier == int(EvidenceTier.CONFIRMED)


def test_bool_evidence_tier_is_rejected() -> None:
    finding = {"title": "Fuzz: crash", "evidence_tier": True}
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.model_tier is None


def test_sqli_with_har_and_class_confirmation_reaches_confirmed() -> None:
    # A sqlmap SQLi re-proven with a stored HAR raw-exchange + boolean class
    # confirmation (the enrichment) reaches CONFIRMED (tier 3), not SUSPECTED.
    finding = {
        "title": "Sqli Candidate — http://x/rest/user/login",
        "cwe": "CWE-89",
        "proof_of_concept": {
            "har_evidence_key": _GENUINE_HAR,
            "boolean_true_response": "HTTP 200 (900 bytes) for tautology injection",
            "boolean_false_response": "HTTP 401 (60 bytes) for benign value",
            "payload": "' OR 1=1-- -",
        },
    }
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.tier == int(EvidenceTier.CONFIRMED)


def test_sqli_with_har_but_no_boolean_stays_suspected() -> None:
    # HAR alone (no class confirmation) is capped at SUSPECTED by the SQLI bar.
    finding = {
        "title": "Sqli Candidate — http://x/rest/user/login",
        "cwe": "CWE-89",
        "proof_of_concept": {"har_evidence_key": _GENUINE_HAR, "payload": "x"},
    }
    adj = adjudicate_finding_tier(finding, verify_artifact=_verify)
    assert adj.tier == int(EvidenceTier.SUSPECTED)
    assert "class_bar_not_met" in adj.reasons
