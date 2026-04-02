"""T9 — deterministic finding_id (UUIDv5) from endpoint + vuln type + parameter / title slug."""

from __future__ import annotations

from src.recon.vulnerability_analysis.finding_stable_id import (
    assign_stable_finding_ids,
    compute_stable_finding_id,
    title_slug,
)


def test_title_slug_normalizes() -> None:
    assert title_slug("Foo Bar!") == "foo-bar"


def test_compute_stable_finding_id_deterministic() -> None:
    f = {
        "title": "XSS",
        "cwe": "CWE-79",
        "proof_of_concept": {"url": "https://Example.com/path/", "parameter": "q"},
    }
    a = compute_stable_finding_id(f)
    b = compute_stable_finding_id(f)
    assert a == b
    assert len(a) == 36


def test_different_parameter_changes_id() -> None:
    base = {
        "title": "XSS",
        "cwe": "CWE-79",
        "proof_of_concept": {"url": "https://example.com/x"},
    }
    f1 = {**base, "proof_of_concept": {**base["proof_of_concept"], "parameter": "a"}}
    f2 = {**base, "proof_of_concept": {**base["proof_of_concept"], "parameter": "b"}}
    assert compute_stable_finding_id(f1) != compute_stable_finding_id(f2)


def test_same_finding_different_scan_id_changes_id() -> None:
    f = {
        "title": "XSS",
        "cwe": "CWE-79",
        "proof_of_concept": {"url": "https://example.com/x", "parameter": "q"},
    }
    a = compute_stable_finding_id(f, scan_id="11111111-1111-1111-1111-111111111111")
    b = compute_stable_finding_id(f, scan_id="22222222-2222-2222-2222-222222222222")
    assert a != b


def test_assign_stable_finding_ids_collision_salts() -> None:
    dup = {
        "title": "Same",
        "cwe": "CWE-79",
        "proof_of_concept": {"url": "https://example.com/z", "parameter": "p"},
    }
    rows = [dict(dup), dict(dup)]
    assign_stable_finding_ids(rows)
    assert rows[0]["finding_id"] != rows[1]["finding_id"]
