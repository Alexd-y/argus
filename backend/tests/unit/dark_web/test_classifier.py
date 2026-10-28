"""Classifier tests — exposure typing + the evidence_tier hard cap (never 3/4)."""

from __future__ import annotations

from src.intel.dark_web.catalog import load_catalog
from src.intel.dark_web.classifier import classify
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    ExposureType,
    SourceNetwork,
)

_RULES = load_catalog().classifier_rules


def _rec(content: str, hint: ExposureType | None = None) -> DarkWebRawRecord:
    return DarkWebRawRecord(
        source_network=SourceNetwork.PASTE,
        content=content,
        exposure_hint=hint,
    )


def test_credential_combolist_classified_high_tier2() -> None:
    c = classify(_rec("fresh combolist email:pass dump"), _RULES)
    assert c.exposure_type == ExposureType.CREDENTIAL
    assert c.severity.value == "high"
    assert c.evidence_tier == 2


def test_stealer_log_critical_tier2() -> None:
    c = classify(_rec("redline stealer logs with passwords.txt"), _RULES)
    assert c.exposure_type == ExposureType.STEALER_LOG
    assert c.evidence_tier == 2


def test_default_is_mention_tier1() -> None:
    c = classify(_rec("just a general discussion"), _RULES)
    assert c.exposure_type == ExposureType.MENTION
    assert c.evidence_tier == 1


def test_tier_never_exceeds_2_even_if_rule_says_4() -> None:
    bad_rules = {
        "defaults": {"exposure_type": "mention", "severity": "info", "evidence_tier": 9},
        "rules": [
            {"id": "evil", "match": ["pwn"], "exposure_type": "credential",
             "severity": "critical", "evidence_tier": 4},
        ],
    }
    assert classify(_rec("total pwn here"), bad_rules).evidence_tier == 2  # clamped from 4
    assert classify(_rec("nothing matches"), bad_rules).evidence_tier == 2  # clamped default from 9


def test_classify_with_no_rules_falls_back_to_hint() -> None:
    c = classify(_rec("x", hint=ExposureType.SECRET_KEY), rules=None)
    assert c.exposure_type == ExposureType.SECRET_KEY
    assert c.evidence_tier == 1


def test_malformed_rules_do_not_crash() -> None:
    c = classify(_rec("anything"), {"rules": ["not a dict", {"match": "notalist"}, 42]})
    assert c.evidence_tier in (1, 2)
