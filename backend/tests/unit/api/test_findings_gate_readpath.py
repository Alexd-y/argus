"""A1 — UI findings endpoint applies the shared gate+dedupe (single source with snapshot)."""

from __future__ import annotations

from src.api.routers.scans import _gate_finding_rows


class _Row:
    def __init__(self, rid, title, *, cwe="", description="", severity="info",
                 cvss=None, proof_of_concept=None, evidence_refs=None, source_tool=""):
        self.id = rid
        self.title = title
        self.cwe = cwe
        self.description = description
        self.severity = severity
        self.cvss = cvss
        self.proof_of_concept = proof_of_concept
        self.evidence_refs = evidence_refs or []
        self.source_tool = source_tool


def test_duplicate_rate_limit_rows_collapse_to_one():
    rows = [
        _Row("r1", "Missing rate limiting on login endpoint", cwe="CWE-307",
             description="Possible missing rate limiting on the login endpoint.",
             severity="low", source_tool="web_vuln_heuristics"),
        _Row("r2", "Missing or insufficient rate limiting on login endpoint", cwe="CWE-307",
             description="Possible missing rate limiting on the login endpoint.",
             severity="low", source_tool="web_vuln_heuristics"),
        _Row("r3", "Rate limiting weak on /login", cwe="CWE-307",
             description="Possible missing rate limiting on the login endpoint.",
             severity="low", source_tool="web_vuln_heuristics"),
    ]
    kept = _gate_finding_rows(rows)
    assert len(kept) == 1


def test_meta_unknown_finding_is_dropped():
    rows = [
        _Row("m1", "Unknown finding with insufficient evidence", cwe="CWE-200",
             description="The finding is informational with no details provided.", severity="info"),
        _Row("m2", "Insufficient evidence for unknown informational findings", cwe="CWE-200",
             description="Multiple informational findings without sufficient details.", severity="info"),
    ]
    assert _gate_finding_rows(rows) == []


def test_real_finding_with_poc_is_kept():
    rows = [
        _Row("g1", "Reflected XSS in q parameter", cwe="CWE-79",
             description="Reflected XSS confirmed via dalfox payload.", severity="high",
             source_tool="dalfox",
             proof_of_concept={"url": "https://t/?q=<x>", "curl_command": "curl ...",
                               "raw_response": "<x>"}),
    ]
    kept = _gate_finding_rows(rows)
    assert len(kept) == 1
    assert kept[0].id == "g1"


def test_empty_input_returns_empty():
    assert _gate_finding_rows([]) == []
