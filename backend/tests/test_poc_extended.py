"""PoC schema: truncation, merge, screenshot_key, response_snippet extraction (fast, no network)."""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.poc_schema import (
    PROOF_OF_CONCEPT_KEYS,
    build_proof_of_concept,
    extract_response_snippet_around_payload,
    merge_proof_of_concept,
)


def test_proof_of_concept_keys_include_response_snippet_and_screenshot() -> None:
    assert "response_snippet" in PROOF_OF_CONCEPT_KEYS
    assert "screenshot_key" in PROOF_OF_CONCEPT_KEYS


def test_build_proof_of_concept_truncates_response_snippet_to_500() -> None:
    long_snip = "S" * 800
    d = build_proof_of_concept("t", response_snippet=long_snip)
    assert "response_snippet" in d
    assert len(d["response_snippet"]) == 500


def test_build_proof_of_concept_truncates_response_to_1024() -> None:
    long_r = "R" * 1500
    d = build_proof_of_concept("nuclei", response=long_r)
    assert len(d["response"]) == 1024


def test_build_proof_of_concept_optional_screenshot_key_capped() -> None:
    key = "k" * 600
    d = build_proof_of_concept("dalfox", screenshot_key=key)
    assert d.get("screenshot_key") is not None
    assert len(d["screenshot_key"]) == 512


def test_build_proof_of_concept_omits_empty_screenshot_key() -> None:
    d = build_proof_of_concept("x", screenshot_key="   ")
    assert "screenshot_key" not in d


def test_merge_proof_of_concept_none_none() -> None:
    assert merge_proof_of_concept(None, None) is None


def test_merge_proof_of_concept_fills_from_second() -> None:
    a = build_proof_of_concept("a", payload="p1")
    b = build_proof_of_concept("b", curl_command="curl -v x")
    m = merge_proof_of_concept(a, b)
    assert m is not None
    assert m.get("payload") == "p1"
    assert "curl -v x" in (m.get("curl_command") or "")


def test_merge_proof_of_concept_prefers_longer_string_for_overlap() -> None:
    short = build_proof_of_concept("t", response_snippet="ab")
    long_ = build_proof_of_concept("t", response_snippet="abcd")
    m = merge_proof_of_concept(short, long_)
    assert m is not None
    assert m["response_snippet"] == "abcd"
    m2 = merge_proof_of_concept(long_, short)
    assert m2 is not None
    assert m2["response_snippet"] == "abcd"


def test_merge_proof_of_concept_ignores_unknown_keys() -> None:
    a = {"tool": "t", "extra_field": "noise"}
    b = {"payload": "x", "not_a_poc_key": "y"}
    m = merge_proof_of_concept(a, b)
    assert m is not None
    assert m.get("payload") == "x"
    assert "extra_field" in m
    assert "not_a_poc_key" not in m


def test_extract_response_snippet_around_payload_respects_cap() -> None:
    # Prefix short enough that [:cap] still includes the match after window trim.
    body = "A" * 12 + "NEEDLE" + "B" * 120
    sn = extract_response_snippet_around_payload(body, "NEEDLE", radius=40, cap=48)
    assert sn is not None
    assert "NEEDLE" in sn
    assert len(sn) <= 48


def test_extract_response_snippet_around_payload_not_found() -> None:
    assert extract_response_snippet_around_payload("no match here", "MISSING") is None
    assert extract_response_snippet_around_payload("", "x") is None
    assert extract_response_snippet_around_payload("body", None) is None
