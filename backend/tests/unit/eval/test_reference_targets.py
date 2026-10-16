"""Wave 5 / R-9.6 — reference target set loader + scorer."""

from __future__ import annotations

import pytest
from src.eval.reference_targets import (
    ReferenceFinding,
    ReferenceTarget,
    load_reference_targets,
    score_against_reference,
)


def test_loads_versioned_set_from_repo():
    targets = load_reference_targets()
    assert "juice-shop" in targets
    js = targets["juice-shop"]
    assert js.url
    assert len(js.expected) >= 1
    assert all(isinstance(e, ReferenceFinding) and e.vuln_class for e in js.expected)
    assert len(js.forbidden) >= 1


def test_unsupported_schema_version_raises(tmp_path):
    p = tmp_path / "ref.yaml"
    p.write_text("schema_version: 999\ntargets: []\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_reference_targets(p)


def _target() -> ReferenceTarget:
    return ReferenceTarget(
        id="t",
        url="http://t",
        expected=(
            ReferenceFinding(vuln_class="sqli", location="/rest/products/search"),
            ReferenceFinding(vuln_class="xss"),
        ),
        forbidden=(ReferenceFinding(vuln_class="log4shell"),),
    )


def test_recall_full_when_all_expected_matched():
    findings = [
        {"vuln_class": "sqli", "location": "/rest/products/search?q=1"},
        {"category": "xss", "location": "/#/search"},
    ]
    score = score_against_reference(_target(), findings)
    assert score.recall == 1.0
    assert score.missed == ()
    assert score.forbidden_hits == ()


def test_location_mismatch_counts_as_missed():
    findings = [{"vuln_class": "sqli", "location": "/some/other/path"}]
    score = score_against_reference(_target(), findings)
    # sqli at the wrong location does not match; xss missing too
    assert score.recall == 0.0
    assert len(score.missed) == 2


def test_forbidden_hit_is_flagged():
    findings = [{"vuln_class": "log4shell", "location": "/"}]
    score = score_against_reference(_target(), findings)
    assert len(score.forbidden_hits) == 1
    assert score.forbidden_hits[0].vuln_class == "log4shell"


def test_partial_recall():
    findings = [{"vuln_class": "xss"}]  # only xss, no sqli
    score = score_against_reference(_target(), findings)
    assert score.recall == 0.5
    assert len(score.matched) == 1 and len(score.missed) == 1
