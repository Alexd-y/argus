"""VHQ-002 — Finding deduplication before report generation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from src.reports.finding_dedup import (
    _get_attr,
    _normalize_url,
    _richness_score,
    deduplicate_findings,
)


def test_deduplicate_empty_list_returns_empty_list() -> None:
    findings: list[Any] = []
    out = deduplicate_findings(findings)
    assert out == []
    assert out is findings


def test_deduplicate_no_duplicates_returns_all_findings() -> None:
    findings = [
        {
            "title": "Alpha issue",
            "cwe": "CWE-79",
            "affected_url": "https://a.example.com/x",
        },
        {
            "title": "Beta issue",
            "cwe": "CWE-89",
            "affected_url": "https://b.example.com/y",
        },
        {
            "title": "Gamma issue",
            "cwe": "CWE-352",
            "affected_url": "https://c.example.com/z",
        },
    ]
    out = deduplicate_findings(findings)
    assert len(out) == 3
    assert out == findings


def test_hard_deduplicate_same_cwe_same_url_keeps_richer_finding() -> None:
    sparse = {
        "title": "Missing CSP",
        "cwe": "CWE-693",
        "affected_url": "https://app.example.com/",
        "description": "",
    }
    rich = {
        "title": "CSP not set",
        "cwe": "CWE-693",
        "affected_url": "https://app.example.com",
        "description": "Content-Security-Policy header is absent.",
        "proof_of_concept": "curl -I https://app.example.com",
        "cvss": 5.0,
    }
    out = deduplicate_findings([sparse, rich])
    assert len(out) == 1
    assert out[0] is rich


def test_hard_deduplicate_same_cwe_different_url_keeps_both() -> None:
    a = {
        "title": "Reflected XSS on profile editor",
        "cwe": "CWE-79",
        "affected_url": "https://app.example.com/page-a",
    }
    b = {
        "title": "Stored XSS in comment thread",
        "cwe": "CWE-79",
        "affected_url": "https://app.example.com/page-b",
    }
    out = deduplicate_findings([a, b])
    assert len(out) == 2
    assert a in out and b in out


def test_soft_deduplicate_similar_titles_keeps_richer_finding() -> None:
    """Titles ~0.85+ similarity; different URLs so hard dedup does not apply."""
    lighter = {
        "title": "SQL injection in login form",
        "cwe": "CWE-89",
        "affected_url": "https://app.example.com/login",
    }
    heavier = {
        "title": "SQL injection in login page",
        "cwe": "CWE-89",
        "affected_url": "https://app.example.com/auth",
        "description": "Parameterized queries missing on login.",
        "poc": "POST /login ...",
    }
    out = deduplicate_findings([lighter, heavier])
    assert len(out) == 1
    assert out[0] is heavier


def test_soft_deduplicate_different_titles_keeps_both() -> None:
    low_sim_a = {
        "title": "Weak password policy detected",
        "cwe": "CWE-521",
        "affected_url": "https://app.example.com/register",
    }
    low_sim_b = {
        "title": "Critical RCE in upload handler",
        "cwe": "CWE-502",
        "affected_url": "https://app.example.com/upload",
    }
    out = deduplicate_findings([low_sim_a, low_sim_b])
    assert len(out) == 2


def test_richness_score_prefers_finding_with_poc_over_one_without() -> None:
    without_poc = {"cwe": "CWE-79", "affected_url": "https://x.example/"}
    with_poc = {
        **without_poc,
        "proof_of_concept": "GET /search?q=<script>",
    }
    assert _richness_score(with_poc) > _richness_score(without_poc)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://Example.COM/path/", "http://example.com/path"),
        ("http://example.com/path#frag", "http://example.com/path"),
        ("HTTP://EXAMPLE.COM/", "http://example.com"),
    ],
)
def test_normalize_url_trailing_slash_fragment_case(raw: str, expected: str) -> None:
    assert _normalize_url(raw) == expected


def test_normalize_url_empty_string() -> None:
    assert _normalize_url("") == ""


def test_get_attr_dict_and_object() -> None:
    @dataclass
    class ObjFinding:
        title: str
        extra: str | None = None

    d: dict[str, Any] = {"title": "from dict", "cwe": "CWE-1"}
    o = ObjFinding(title="from object")
    assert _get_attr(d, "title") == "from dict"
    assert _get_attr(d, "missing") is None
    assert _get_attr(o, "title") == "from object"
    assert _get_attr(o, "nope") is None


@dataclass
class _ObjectFinding:
    title: str
    cwe: str
    affected_url: str
    description: str = ""
    proof_of_concept: str | None = None
    poc: str | None = None
    cvss: float | None = None
    cvss_score: float | None = None


def test_deduplicate_works_with_object_style_findings() -> None:
    thin = _ObjectFinding(
        title="Header issue",
        cwe="CWE-693",
        affected_url="https://api.example.com/v1/",
    )
    fat = _ObjectFinding(
        title="Security header gap",
        cwe="CWE-693",
        affected_url="https://api.example.com/v1",
        description="HSTS missing.",
        proof_of_concept="curl -I https://api.example.com/v1",
        cvss=4.0,
    )
    out = deduplicate_findings([thin, fat])
    assert len(out) == 1
    assert out[0] is fat


def test_deduplicate_mixed_dict_and_object_hard_duplicate_keeps_richer() -> None:
    dict_finding: dict[str, Any] = {
        "title": "d",
        "cwe": "CWE-79",
        "affected_url": "https://mix.example/path",
    }
    obj_finding = _ObjectFinding(
        title="o",
        cwe="CWE-79",
        affected_url="https://mix.example/path/",
        description="Reflected input.",
        poc="GET /path?q=<img>",
    )
    out = deduplicate_findings([dict_finding, obj_finding])
    assert len(out) == 1
    assert out[0] is obj_finding


def test_multiple_duplicates_chain_collapses_to_single_finding() -> None:
    base = {
        "title": "t",
        "cwe": "CWE-22",
        "affected_url": "https://dup.example/file",
    }
    step2 = {**base, "description": "d"}
    step3 = {**step2, "proof_of_concept": "p"}
    step4 = {**step3, "cvss": 7.5}
    out = deduplicate_findings([base, step2, step3, step4])
    assert len(out) == 1
    assert out[0] is step4
