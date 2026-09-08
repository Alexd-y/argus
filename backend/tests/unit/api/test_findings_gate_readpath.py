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


def test_thin_llm_and_rich_tool_rows_collapse_via_scan_target():
    """Regression (scan d20384ed): an LLM-normalized host-level finding (no
    per-finding URL) and the tool-produced record for the same issue (URL in
    ``proof_of_concept``) must collapse into one.

    The previous host derivation (``target.split('/')[0]``) yielded ``"https:"``
    for the tool record and ``""`` for the URL-less LLM record, so same-class
    findings kept distinct ``finding_key``s and survived dedup. The scan target
    is passed as a fallback host so both resolve to ``alleksy.com``.
    """
    pairs = [
        ("TLS configuration probe indicates potential weakness",
         "TLS_PROBE finding — https://alleksy.com/", "https://alleksy.com/"),
        ("Incomplete security HTTP response headers",
         "Security HTTP response headers missing or incomplete — https://alleksy.com",
         "https://alleksy.com"),
        ("Missing rate limiting on login endpoint",
         "No HTTP 429 observed on rapid login-path requests (rate limit signal)",
         "https://alleksy.com/login"),
    ]
    rows: list[_Row] = []
    for i, (thin_title, rich_title, url) in enumerate(pairs):
        rows.append(
            _Row(f"thin{i}", thin_title, description="x" * 30, severity="medium",
                 source_tool="llm")
        )
        rows.append(
            _Row(f"rich{i}", rich_title, severity="medium", source_tool="testssl",
                 proof_of_concept={"url": url},
                 evidence_refs=[{"object_key": "k", "sha256": "s"}])
        )

    kept = _gate_finding_rows(rows, default_target="alleksy.com")
    # 3 pairs → 3 findings (one per issue).
    assert len(kept) == 3

    # Same collapse even when the scan carries NO target (prod case for
    # d20384ed): the shared host is derived from the URL-bearing records.
    kept_no_target = _gate_finding_rows(rows, default_target="")
    assert len(kept_no_target) == 3


def test_dedupe_survivor_is_the_evidence_bearing_row():
    """The retained row must be the tool record with evidence, not the LLM
    paraphrase — otherwise the UI shows a finding with no proof."""
    thin = _Row("thin", "TLS configuration probe indicates potential weakness",
                description="x" * 30, severity="medium", source_tool="llm")
    rich = _Row("rich", "TLS_PROBE finding — https://alleksy.com/", severity="medium",
                source_tool="testssl", proof_of_concept={"url": "https://alleksy.com/"},
                evidence_refs=[{"object_key": "k", "sha256": "s"}])
    # thin first in iteration order — survivor must still be the rich row.
    kept = _gate_finding_rows([thin, rich], default_target="")
    assert len(kept) == 1
    assert kept[0].id == "rich"


def test_multi_host_findings_do_not_over_collapse():
    """Distinct hosts must NOT collapse even within a semantic class."""
    rows = [
        _Row("a", "Incomplete security HTTP response headers", severity="low",
             source_tool="httpx", proof_of_concept={"url": "https://a.example/"}),
        _Row("b", "Incomplete security HTTP response headers", severity="low",
             source_tool="httpx", proof_of_concept={"url": "https://b.example/"}),
    ]
    assert len(_gate_finding_rows(rows, default_target="")) == 2


def test_host_of_normalizes_scheme_and_port():
    from src.orchestration.finding_gate import _host_of

    assert _host_of("https://alleksy.com/") == "alleksy.com"
    assert _host_of("https://alleksy.com:443/login") == "alleksy.com"
    assert _host_of("alleksy.com") == "alleksy.com"
    assert _host_of("") == ""
