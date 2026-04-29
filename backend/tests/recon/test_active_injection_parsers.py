"""P2-007 — injection stdout/jsonl parsers and evidence normalization."""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.injection_findings_normalize import (
    DEFAULT_INJECTION_EVIDENCE_RULES,
    InjectionEvidenceRules,
    NormalizedInjectionFinding,
    apply_evidence_quality_to_normalized_finding,
    normalize_evidence_quality_for_family,
    parse_dalfox_stdout,
    parse_nuclei_jsonl,
    parse_sqlmap_stdout,
)


def test_parse_sqlmap_stdout_minimal_chunk() -> None:
    snippet = """
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
http://example.com/vuln?id=1
"""
    rows = parse_sqlmap_stdout(snippet)
    assert len(rows) == 1
    assert rows[0].injection_family == "sqli"
    assert rows[0].parameter == "id"
    assert rows[0].method == "GET"


def test_parse_sqlmap_stdout_garbage_empty() -> None:
    assert parse_sqlmap_stdout("") == []
    assert parse_sqlmap_stdout("hello world no markers") == []


def test_parse_dalfox_stdout_poc_url() -> None:
    snippet = "[POC][V] https://app.test/search?q=1\n"
    rows = parse_dalfox_stdout(snippet)
    assert len(rows) >= 1
    assert rows[0].injection_family == "xss"
    assert "app.test" in rows[0].affected_url


def test_parse_nuclei_jsonl_sqli() -> None:
    line = (
        '{"template-id":"dast/sqli-error","matched-at":"https://x/y?id=1",'
        '"info":{"name":"SQL Injection","severity":"high"}}'
    )
    rows = parse_nuclei_jsonl(line)
    assert len(rows) == 1
    assert rows[0].injection_family == "sqli"
    assert rows[0].proof_of_concept.get("tool") == "nuclei"


def test_normalize_evidence_xss_confirmed_without_execution_weak() -> None:
    fd = {
        "injection_family": "xss",
        "confidence": "confirmed",
        "validation_status": "validated",
        "evidence_quality": "strong",
        "proof_of_concept": {"payload": "<script>1</script>"},
        "title": "X",
    }
    q, notes = normalize_evidence_quality_for_family(fd, DEFAULT_INJECTION_EVIDENCE_RULES)
    assert q == "weak"
    assert "xss_confirmed_without_execution_or_oast" in notes


def test_normalize_evidence_ssrf_meta_oast_strong() -> None:
    fd = {
        "injection_family": "ssrf",
        "confidence": "confirmed",
        "evidence_quality": "strong",
        "proof_of_concept": {},
        "finding_meta": {"oast_callback": True},
    }
    q, notes = normalize_evidence_quality_for_family(fd, DEFAULT_INJECTION_EVIDENCE_RULES)
    assert q == "strong"
    assert not notes


def test_normalize_time_based_sqli_requires_samples() -> None:
    fd = {
        "injection_family": "sqli",
        "confidence": "confirmed",
        "title": "Time-based blind SQL injection",
        "evidence_quality": "strong",
        "proof_of_concept": {"type": "time-based blind"},
    }
    q, notes = normalize_evidence_quality_for_family(fd, DEFAULT_INJECTION_EVIDENCE_RULES)
    assert q == "weak"
    assert "sqli_time_based_without_repeated_samples" in notes


def test_apply_evidence_quality_returns_model() -> None:
    n = NormalizedInjectionFinding(
        injection_family="xss",
        confidence="confirmed",
        validation_status="validated",
        evidence_quality="strong",
        title="t",
        proof_of_concept={"payload": "x"},
    )
    out = apply_evidence_quality_to_normalized_finding(
        n, InjectionEvidenceRules(require_xss_execution_for_confirmed=True)
    )
    assert out.evidence_quality == "weak"
    assert "evidence_adjustment_notes" in out.finding_meta
