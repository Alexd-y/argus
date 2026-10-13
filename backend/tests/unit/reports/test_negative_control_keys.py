"""Wave 3 / etap 1 — negative-control key consistency.

A producer writes ``negative_control_url`` / ``negative_control_result`` (the
canonical poc_schema keys), but the validators used to read only
``negative_control`` / ``baseline`` — so every collected negative control was
invisible and IDOR/BOLA/AUTH_BYPASS could never confirm. This guards against
that drift reappearing.
"""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.poc_schema import (
    PROOF_OF_CONCEPT_KEYS,
    build_proof_of_concept,
)
from src.reports.poc_validation import (
    _NEGATIVE_CONTROL_KEYS,
    _has_negative_control,
    _negative_control_value,
    validate_xss_poc,
)

# The canonical keys (first two) are the producer's; the rest are deprecated
# synonyms kept only for a transition window.
_CANONICAL = ("negative_control_result", "negative_control_url")
_DEPRECATED = ("negative_control", "baseline")


def test_canonical_keys_are_in_the_schema() -> None:
    for key in _CANONICAL:
        assert key in PROOF_OF_CONCEPT_KEYS, f"{key} must be a canonical PoC key"
    # The reader checks the canonical keys FIRST, then the deprecated synonyms.
    assert _NEGATIVE_CONTROL_KEYS[: len(_CANONICAL)] == _CANONICAL
    assert set(_DEPRECATED) <= set(_NEGATIVE_CONTROL_KEYS)


def test_producer_negative_control_is_visible_to_validator() -> None:
    poc = build_proof_of_concept(
        tool="va",
        parameter="q",
        negative_control_url="https://t.example/s?q=benign",
        negative_control_result="no reflection; baseline 200/512b",
    )
    # The exact drift that kept IDOR/BOLA unconfirmable: this MUST now be True.
    assert _has_negative_control(poc) is True
    assert _negative_control_value(poc) == "no reflection; baseline 200/512b"


def test_deprecated_synonyms_still_accepted() -> None:
    assert _has_negative_control({"negative_control": "x"}) is True
    assert _has_negative_control({"baseline": "y"}) is True
    assert _has_negative_control({"unrelated": "z"}) is False


def test_validate_xss_reads_canonical_negative_control() -> None:
    poc = {
        "reflection_context": "html",
        "payload_entered": "<x>",
        "payload_reflected": "<x>",
        "verified_via_browser": True,
        "browser_alert_text": "1",
        "affected_parameter": "q",
        "negative_control_result": "benign value not reflected",
    }
    res = validate_xss_poc(poc)
    assert res.negative_control == "benign value not reflected"
    assert res.is_validated() is True
