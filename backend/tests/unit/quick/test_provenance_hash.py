"""QUICK-005 — evidence hash stability and secret-free LLM JSON."""

from __future__ import annotations

from src.quick.provenance import (
    FINGERPRINT_VERSION,
    QuickProvenance,
    build_provenance,
    compute_evidence_hash,
    digest_template_ids,
    evidence_json_for_llm,
    mint_evidence_id,
    provenance_public_dict,
    public_fingerprint,
    redact_mapping_for_llm,
)

_SCAN_ID = "11111111-2222-3333-4444-555555555555"
_TASK_ID = "fedcba98-7654-3210-fedc-ba9876543210"


def test_compute_evidence_hash_is_stable_and_order_independent() -> None:
    left = {"template_id": "http-cve-nginx", "matched_at": "https://app.example/", "n": 1}
    right = {"n": 1, "matched_at": "https://app.example/", "template_id": "http-cve-nginx"}
    first = compute_evidence_hash(left)
    second = compute_evidence_hash(right)
    assert first == second
    assert first == compute_evidence_hash(left)
    assert len(first) == 64
    assert first != compute_evidence_hash({**left, "n": 2})


def test_hash_of_string_and_bytes_matches_utf8() -> None:
    text = "raw-evidence-blob"
    assert compute_evidence_hash(text) == compute_evidence_hash(text.encode("utf-8"))
    assert compute_evidence_hash(text) != compute_evidence_hash({"k": "v"})


def test_mint_evidence_id_is_deterministic() -> None:
    digest = compute_evidence_hash({"tool_id": "nuclei"})
    first = mint_evidence_id(scan_id=_SCAN_ID, task_id=_TASK_ID, evidence_hash=digest)
    second = mint_evidence_id(scan_id=_SCAN_ID, task_id=_TASK_ID, evidence_hash=digest)
    assert first == second
    assert len(first) == 36
    other_scan = mint_evidence_id(scan_id="0" * 36, task_id=_TASK_ID, evidence_hash=digest)
    assert other_scan != first
    no_task = mint_evidence_id(scan_id=_SCAN_ID, task_id=None, evidence_hash=digest)
    assert no_task != first


def test_secrets_not_in_llm_evidence_json() -> None:
    payload = {
        "tool_id": "nuclei",
        "template_id": "http-cve-nginx",
        "matched_at": "https://app.example/login",
        "password": "hunter2",
        "passwd": "also-secret",
        "token": "abc123",
        "api_key": "sk-live",
        "authorization": "Bearer leaked",
        "cookie": "session=abc",
        "credentials": {"user": "admin", "password": "x"},
        "nested": {"refresh_token": "rrr", "host": "app.example"},
        "note": "password=supersecret",
    }
    redacted = evidence_json_for_llm(payload)
    blob = str(redacted)
    for key in (
        "password",
        "passwd",
        "token",
        "api_key",
        "authorization",
        "cookie",
        "credentials",
        "refresh_token",
    ):
        assert key not in redacted
        assert key not in (redacted.get("nested") or {})
    assert "hunter2" not in blob
    assert "sk-live" not in blob
    assert "Bearer leaked" not in blob
    assert "supersecret" not in blob
    assert "[REDACTED]" in redacted["note"]
    assert redacted["tool_id"] == "nuclei"
    assert redacted["template_id"] == "http-cve-nginx"
    assert redacted["nested"]["host"] == "app.example"


def test_redact_mapping_for_llm_handles_lists_and_empty() -> None:
    assert evidence_json_for_llm(None) == {}
    assert evidence_json_for_llm({}) == {}
    cleaned = redact_mapping_for_llm(
        {
            "items": [{"token": "x", "ok": True}, "Bearer abcdef"],
            "Authorization": "secret",
        }
    )
    assert "Authorization" not in cleaned
    assert cleaned["items"][0] == {"ok": True}
    assert cleaned["items"][1] == "[REDACTED]"


def test_build_provenance_is_identifiers_only() -> None:
    digest = compute_evidence_hash({"tool_id": "nuclei"})
    provenance = build_provenance(
        evidence_hash=digest.upper(),
        tool_id="nuclei",
        tool_version="3.3.0",
        scan_id=_SCAN_ID,
        template_id="http-cve-nginx",
        template_digest="C" * 64,
        policy_decision_id="01234567-89ab-cdef-0123-456789abcdef",
        lease_id="aa11bb22-cc33-dd44-ee55-ff6677889900",
        task_id=_TASK_ID,
        artifact_key="t/s/vuln_analysis/raw/x.json",
    )
    assert isinstance(provenance, QuickProvenance)
    assert provenance.evidence_hash == digest.lower()
    assert provenance.fingerprint_version == FINGERPRINT_VERSION
    dumped = provenance_public_dict(provenance)
    blob = str(dumped)
    assert "password" not in blob
    assert "token" not in blob
    assert dumped["tool_id"] == "nuclei"
    assert dumped["task_id"] == _TASK_ID
    fp = public_fingerprint(fingerprint_key="a" * 64)
    assert fp == {"fingerprint_key": "a" * 64, "fingerprint_version": FINGERPRINT_VERSION}


def test_digest_template_ids_is_stable() -> None:
    first = digest_template_ids(("b-tpl", "a-tpl", "a-tpl"))
    second = digest_template_ids(("a-tpl", "b-tpl"))
    assert first == second
    assert len(first) == 64
    assert first != digest_template_ids(("c-tpl",))
