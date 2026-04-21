"""Unit tests for :mod:`src.sandbox.parsers.nuclei_parser` (Backlog/dev1_md §4.7 + §4.8 — ARG-015).

Each test pins one contract documented in the parser:

* ``parse_nuclei_jsonl`` resolves the canonical artifact first
  (``artifacts_dir/nuclei.jsonl`` shared across all four tool_ids), then
  falls back to ``stdout``.
* Severity → confidence ladder:
  ``critical`` / ``high`` → ``LIKELY``; ``medium`` + CVE → ``LIKELY``;
  everything else → ``SUSPECTED``.
* Tag-driven category routing: ``rce`` outranks ``misconfig``; ``ssti``
  outranks ``xss``; ``info`` falls back to :class:`FindingCategory.INFO`.
* CWE extraction prefers ``info.classification.cwe-id``; falls back to a
  per-category default so the FindingDTO contract (``cwe`` non-empty)
  holds.
* CVSS preserved when the template carries a 0.0..10.0 score and a
  vector starting with ``CVSS:3.`` or ``CVSS:4.``; sentinel otherwise.
* CVE normalisation: strips / re-adds the ``CVE-`` prefix; sorts and
  deduplicates; rejects malformed tokens.
* Records collapse on a stable ``(template_id, matched_at, kind)``
  key — re-emission across nuclei ``-c`` parallel workers yields one
  finding per unique match. Same template hitting two distinct paths
  remains two findings.
* Output ordering is deterministic — sorted by the dedup key.
* Hard cap at 10 000 findings — prevents a permissive ``-tags ""``
  run from exhausting worker memory.
* Malformed / empty / non-dict JSONL lines are skipped; a single bad
  line does not poison the whole stream.
* ``matcher-status=False`` records (template ran but did not match)
  are filtered out — Nuclei sometimes uses these as discovery aids,
  they are NOT findings.
* Sidecar JSONL ``nuclei_findings.jsonl`` carries one compact record
  per emitted finding, stamped with the source ``tool_id`` so the
  downstream evidence pipeline can route per-tool.
* The same parser is reused by ``nextjs_check`` / ``spring_boot_actuator``
  / ``jenkins_enum`` (the §4.7 wrappers); the tool_id stamp on the
  sidecar lets the downstream pipeline demultiplex.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_SCORE,
    SENTINEL_CVSS_VECTOR,
    SENTINEL_UUID,
)
from src.sandbox.parsers.nuclei_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_nikto_json,
    parse_nuclei_jsonl,
    parse_wapiti_json,
)


# ---------------------------------------------------------------------------
# Builders for canonical fixture shapes
# ---------------------------------------------------------------------------


def _nuclei_record(
    *,
    template_id: str = "CVE-2024-12345",
    name: str = "Example template",
    severity: str = "high",
    tags: list[str] | None = None,
    matched_at: str | None = "https://target.example/admin",
    host: str | None = "https://target.example",
    matcher_name: str | None = None,
    matcher_status: bool | None = None,
    cve_ids: list[str] | None = None,
    cwe_ids: list[str] | None = None,
    cvss_score: float | None = None,
    cvss_metrics: str | None = None,
    references: list[str] | None = None,
    description: str | None = None,
    record_type: str | None = "http",
    request: str | None = None,
    response: str | None = None,
) -> dict[str, Any]:
    """Build a minimal nuclei JSONL record honouring every documented field."""
    info: dict[str, Any] = {
        "name": name,
        "severity": severity,
    }
    if description:
        info["description"] = description
    if tags is not None:
        info["tags"] = list(tags)
    if references is not None:
        info["reference"] = list(references)

    classification: dict[str, Any] = {}
    if cve_ids is not None:
        classification["cve-id"] = list(cve_ids)
    if cwe_ids is not None:
        classification["cwe-id"] = list(cwe_ids)
    if cvss_score is not None:
        classification["cvss-score"] = cvss_score
    if cvss_metrics is not None:
        classification["cvss-metrics"] = cvss_metrics
    if classification:
        info["classification"] = classification

    record: dict[str, Any] = {
        "template-id": template_id,
        "info": info,
    }
    if matched_at is not None:
        record["matched-at"] = matched_at
    if host is not None:
        record["host"] = host
    if matcher_name is not None:
        record["matcher-name"] = matcher_name
    if matcher_status is not None:
        record["matcher-status"] = matcher_status
    if record_type:
        record["type"] = record_type
    if request is not None:
        record["request"] = request
    if response is not None:
        record["response"] = response
    return record


def _serialise(records: list[dict[str, Any]]) -> bytes:
    """Serialise a sequence of nuclei records as JSONL bytes."""
    return ("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n").encode(
        "utf-8"
    )


def _read_sidecar(artifacts_dir: Path) -> list[dict[str, Any]]:
    """Read the sidecar JSONL into a list of dicts."""
    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    return [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Empty / malformed inputs
# ---------------------------------------------------------------------------


def test_empty_stdout_returns_empty_list_and_writes_no_sidecar(tmp_path: Path) -> None:
    """No stdout + no canonical file → ``[]`` + no sidecar emitted."""
    findings = parse_nuclei_jsonl(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_whitespace_only_stdout_returns_empty(tmp_path: Path) -> None:
    """All-whitespace stdout collapses to ``[]`` (no sidecar)."""
    findings = parse_nuclei_jsonl(
        stdout=b"\n\n\t\n   \n",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_malformed_jsonl_line_is_skipped_other_lines_pass(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """One bad JSON line must not poison the whole stream."""
    good = json.dumps(_nuclei_record(template_id="example-good")).encode("utf-8")
    malformed = b"{this is not valid json}"
    stdout = good + b"\n" + malformed + b"\n"
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = parse_nuclei_jsonl(
            stdout=stdout,
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="nuclei",
        )
    assert len(findings) == 1
    assert any(
        getattr(rec, "event", "") == "parsers_jsonl_malformed" for rec in caplog.records
    )


def test_record_missing_template_id_is_skipped(tmp_path: Path) -> None:
    """A record without ``template-id`` is parser-irrelevant — skipped silently."""
    payload = _nuclei_record()
    payload.pop("template-id")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings == []


def test_matcher_status_false_record_is_filtered_out(tmp_path: Path) -> None:
    """``matcher-status=False`` (template ran but did not match) → drop."""
    payload = _nuclei_record(matcher_status=False)
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings == []


def test_matcher_status_true_record_is_emitted(tmp_path: Path) -> None:
    """``matcher-status=True`` records pass through normally."""
    payload = _nuclei_record(matcher_status=True)
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 1


def test_record_missing_matched_at_falls_back_to_host(tmp_path: Path) -> None:
    """If ``matched-at`` is missing the parser uses ``host`` as the location."""
    payload = _nuclei_record(matched_at=None, host="https://target.example")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["matched_at"] == "https://target.example"


# ---------------------------------------------------------------------------
# Severity → confidence ladder
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("critical", ConfidenceLevel.LIKELY),
        ("high", ConfidenceLevel.LIKELY),
        ("medium", ConfidenceLevel.SUSPECTED),
        ("low", ConfidenceLevel.SUSPECTED),
        ("info", ConfidenceLevel.SUSPECTED),
        ("unknown", ConfidenceLevel.SUSPECTED),
    ],
)
def test_confidence_derives_from_severity_without_cve(
    severity: str, expected: ConfidenceLevel, tmp_path: Path
) -> None:
    """Without CVE: critical / high → LIKELY; medium / low / info → SUSPECTED."""
    rec = _nuclei_record(severity=severity)
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 1
    assert findings[0].confidence is expected


def test_medium_severity_with_cve_escalates_to_likely(tmp_path: Path) -> None:
    """A medium-severity template with a CVE attached → ConfidenceLevel.LIKELY."""
    rec = _nuclei_record(severity="medium", cve_ids=["CVE-2024-12345"])
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_unknown_severity_normalises_to_info_category(tmp_path: Path) -> None:
    """Casing variants / typos → ``info`` fallback (so category=INFO)."""
    rec = _nuclei_record(severity="extreme")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].category is FindingCategory.INFO


def test_uppercase_severity_normalises_to_lowercase(tmp_path: Path) -> None:
    """``HIGH`` / ``High`` / ``high`` all collapse to the canonical ``high``."""
    rec = _nuclei_record(severity="HIGH")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_informational_alias_normalises_to_info(tmp_path: Path) -> None:
    """``informational`` alias normalises to ``info`` bucket."""
    rec = _nuclei_record(severity="informational", tags=None)
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].category is FindingCategory.INFO


# ---------------------------------------------------------------------------
# Tag → FindingCategory routing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tags", "expected_category"),
    [
        (["rce"], FindingCategory.RCE),
        (["sqli"], FindingCategory.SQLI),
        (["xss"], FindingCategory.XSS),
        (["lfi"], FindingCategory.LFI),
        (["path-traversal"], FindingCategory.LFI),
        (["ssrf"], FindingCategory.SSRF),
        (["ssti"], FindingCategory.SSTI),
        (["xxe"], FindingCategory.XXE),
        (["cmdi"], FindingCategory.CMDI),
        (["open-redirect"], FindingCategory.OPEN_REDIRECT),
        (["csrf"], FindingCategory.CSRF),
        (["cors"], FindingCategory.CORS),
        (["jwt"], FindingCategory.JWT),
        (["auth-bypass"], FindingCategory.AUTH),
        (["default-login"], FindingCategory.AUTH),
        (["idor"], FindingCategory.IDOR),
        (["crypto"], FindingCategory.CRYPTO),
        (["misconfig"], FindingCategory.MISCONFIG),
        (["exposure"], FindingCategory.MISCONFIG),
        (["debug"], FindingCategory.MISCONFIG),
        (["tech"], FindingCategory.INFO),
        (["fingerprint"], FindingCategory.INFO),
    ],
)
def test_category_resolves_from_known_tag(
    tags: list[str], expected_category: FindingCategory, tmp_path: Path
) -> None:
    """Each canonical nuclei tag must resolve to the expected category."""
    rec = _nuclei_record(tags=tags, severity="high")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].category is expected_category


def test_rce_tag_outranks_misconfig_tag(tmp_path: Path) -> None:
    """When both ``rce`` and ``misconfig`` are present, RCE wins (priority order)."""
    rec = _nuclei_record(tags=["misconfig", "rce", "exposure"])
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].category is FindingCategory.RCE


def test_no_known_tag_high_severity_falls_back_to_misconfig(tmp_path: Path) -> None:
    """Severity ≥ medium + no recognised tag → MISCONFIG (catch-all)."""
    rec = _nuclei_record(tags=["weird-niche-tag"], severity="high")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].category is FindingCategory.MISCONFIG


def test_no_known_tag_info_severity_falls_back_to_info(tmp_path: Path) -> None:
    """Severity = info + no recognised tag → INFO category."""
    rec = _nuclei_record(tags=["weird-niche-tag"], severity="info")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].category is FindingCategory.INFO


def test_tags_as_csv_string_are_parsed_correctly(tmp_path: Path) -> None:
    """nuclei sometimes emits ``tags`` as a CSV string instead of a list."""
    payload = _nuclei_record()
    payload["info"]["tags"] = "rce, exposure ,misconfig"
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].category is FindingCategory.RCE


# ---------------------------------------------------------------------------
# CWE extraction
# ---------------------------------------------------------------------------


def test_cwe_extracted_from_template_classification(tmp_path: Path) -> None:
    """``info.classification.cwe-id`` is preferred over the category default."""
    rec = _nuclei_record(cwe_ids=["CWE-79", "CWE-200"])
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cwe == [79, 200]


def test_cwe_falls_back_to_category_default_when_template_omits(
    tmp_path: Path,
) -> None:
    """Templates without classification CWE → category default (here CWE-79 for XSS)."""
    rec = _nuclei_record(tags=["xss"], cwe_ids=None)
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert 79 in findings[0].cwe


def test_cwe_extraction_skips_malformed_tokens_keeps_valid(tmp_path: Path) -> None:
    """``CWE-foo``, ``CWE-0`` are filtered; ``200`` (bare digits) parses."""
    rec = _nuclei_record(cwe_ids=["CWE-79", "CWE-foo", "CWE-0", "200"])
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert 79 in findings[0].cwe
    assert 200 in findings[0].cwe
    assert 0 not in findings[0].cwe


def test_cwe_extraction_handles_integer_inputs(tmp_path: Path) -> None:
    """``cwe-id`` shipped as integers (some templates) still parses."""
    payload = _nuclei_record()
    payload["info"]["classification"] = {"cwe-id": [79, 200]}
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cwe == [79, 200]


# ---------------------------------------------------------------------------
# CVSS extraction
# ---------------------------------------------------------------------------


def test_cvss_score_and_vector_preserved_when_valid(tmp_path: Path) -> None:
    """Valid score (0..10) + vector starting with CVSS:3 → both pinned."""
    rec = _nuclei_record(
        cvss_score=8.8,
        cvss_metrics="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cvss_v3_score == 8.8
    assert findings[0].cvss_v3_vector.startswith("CVSS:3.1")


def test_cvss_score_out_of_range_falls_back_to_sentinel(tmp_path: Path) -> None:
    """Score > 10.0 (corrupt) is rejected → sentinel preserved."""
    rec = _nuclei_record(
        cvss_score=99.9,
        cvss_metrics="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cvss_v3_score == SENTINEL_CVSS_SCORE


def test_cvss_score_as_string_parses(tmp_path: Path) -> None:
    """``cvss-score`` shipped as a string (some templates) still parses."""
    payload = _nuclei_record()
    payload["info"]["classification"] = {
        "cvss-score": "7.5",
        "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    }
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cvss_v3_score == 7.5


def test_cvss_vector_without_prefix_is_rejected(tmp_path: Path) -> None:
    """A vector that does not start with ``CVSS:3.`` / ``CVSS:4.`` is dropped."""
    rec = _nuclei_record(cvss_score=5.0, cvss_metrics="bogus-vector")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cvss_v3_vector == SENTINEL_CVSS_VECTOR


def test_cvss_v2_vector_is_rejected(tmp_path: Path) -> None:
    """CVSS:2.0 vectors are not honoured (FindingDTO would reject them)."""
    rec = _nuclei_record(
        cvss_score=5.0,
        cvss_metrics="CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
    )
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cvss_v3_vector == SENTINEL_CVSS_VECTOR


def test_cvss_missing_classification_falls_back_to_sentinel(tmp_path: Path) -> None:
    """Templates without classification entirely → sentinel CVSS."""
    rec = _nuclei_record(cvss_score=None, cvss_metrics=None, cwe_ids=None)
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cvss_v3_score == SENTINEL_CVSS_SCORE
    assert findings[0].cvss_v3_vector == SENTINEL_CVSS_VECTOR


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------


def test_cve_normalised_with_prefix_added(tmp_path: Path) -> None:
    """Bare ``2024-12345`` gets the ``CVE-`` prefix added."""
    rec = _nuclei_record(cve_ids=["2024-12345"])
    parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["cve"] == ["CVE-2024-12345"]


def test_cve_dedup_and_sort_in_sidecar(tmp_path: Path) -> None:
    """Duplicate / out-of-order CVE entries collapse + sort."""
    rec = _nuclei_record(
        cve_ids=["CVE-2024-99999", "2024-11111", "CVE-2024-99999", "cve-2024-22222"]
    )
    parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["cve"] == [
        "CVE-2024-11111",
        "CVE-2024-22222",
        "CVE-2024-99999",
    ]


def test_malformed_cve_is_dropped(tmp_path: Path) -> None:
    """Garbage CVE tokens are dropped from the emitted CVE list."""
    rec = _nuclei_record(cve_ids=["CVE-ABC", "not-a-cve", "CVE-2024-12345"])
    parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["cve"] == ["CVE-2024-12345"]


# ---------------------------------------------------------------------------
# Dedup + ordering + cap
# ---------------------------------------------------------------------------


def test_duplicate_records_collapse_into_one_finding(tmp_path: Path) -> None:
    """Same template + matched-at → one finding (nuclei -c races)."""
    rec = _nuclei_record(template_id="example-dup", matched_at="https://x/path")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec, rec, rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 1


def test_distinct_match_locations_produce_distinct_findings(tmp_path: Path) -> None:
    """Same template hitting two different paths → two findings."""
    rec1 = _nuclei_record(template_id="dup-tpl", matched_at="https://x/a")
    rec2 = _nuclei_record(template_id="dup-tpl", matched_at="https://x/b")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec1, rec2]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 2


def test_distinct_template_ids_produce_distinct_findings(tmp_path: Path) -> None:
    """Two distinct templates hitting the same path → two findings."""
    rec1 = _nuclei_record(template_id="tpl-a", matched_at="https://x/p")
    rec2 = _nuclei_record(template_id="tpl-b", matched_at="https://x/p")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec1, rec2]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 2


def test_output_ordering_is_deterministic(tmp_path: Path) -> None:
    """Two parser runs on the same payload produce identical sidecars."""
    payload = [
        _nuclei_record(template_id="b-second", matched_at="https://x/2"),
        _nuclei_record(template_id="a-first", matched_at="https://x/1"),
        _nuclei_record(template_id="c-third", matched_at="https://x/3"),
    ]
    serialised = _serialise(payload)
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    parse_nuclei_jsonl(
        stdout=serialised,
        stderr=b"",
        artifacts_dir=first_dir,
        tool_id="nuclei",
    )
    parse_nuclei_jsonl(
        stdout=serialised,
        stderr=b"",
        artifacts_dir=second_dir,
        tool_id="nuclei",
    )
    first = (first_dir / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    second = (second_dir / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert first == second


# ---------------------------------------------------------------------------
# Sidecar evidence
# ---------------------------------------------------------------------------


def test_sidecar_carries_one_record_per_finding(tmp_path: Path) -> None:
    """Sidecar JSONL has exactly N records for N findings."""
    payload = [
        _nuclei_record(template_id=f"tpl-{i}", matched_at=f"https://x/{i}")
        for i in range(5)
    ]
    findings = parse_nuclei_jsonl(
        stdout=_serialise(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == len(findings) == 5


def test_sidecar_records_carry_tool_id_and_template_metadata(tmp_path: Path) -> None:
    """Every sidecar record stamps tool_id, template_id, severity, matched_at."""
    rec = _nuclei_record(
        template_id="CVE-2024-99999",
        severity="critical",
        cve_ids=["2024-99999"],
        cwe_ids=["CWE-78"],
        cvss_score=9.8,
        cvss_metrics="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-99999"],
    )
    parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nextjs_check",
    )
    [sidecar] = _read_sidecar(tmp_path)
    assert sidecar["tool_id"] == "nextjs_check"
    assert sidecar["template_id"] == "CVE-2024-99999"
    assert sidecar["severity"] == "critical"
    assert sidecar["matched_at"] == "https://target.example/admin"
    assert sidecar["cve"] == ["CVE-2024-99999"]
    assert 78 in sidecar["cwe"]
    assert sidecar["cvss_v3_score"] == 9.8
    assert sidecar["references"] == ["https://nvd.nist.gov/vuln/detail/CVE-2024-99999"]


def test_sidecar_omits_empty_and_sentinel_fields(tmp_path: Path) -> None:
    """Sidecar drops fields that are None / "" / [] / sentinel CVSS for compactness."""
    rec = _nuclei_record(
        template_id="minimal",
        severity="info",
        tags=None,
        cve_ids=None,
        cwe_ids=None,
        cvss_score=None,
        cvss_metrics=None,
        references=None,
        host=None,
        matcher_name=None,
        matched_at="https://x/path",
    )
    parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    [sidecar] = _read_sidecar(tmp_path)
    assert "cve" not in sidecar
    assert "tags" not in sidecar
    assert "matcher_name" not in sidecar
    assert "cvss_v3_score" not in sidecar  # sentinel score is dropped
    assert "cvss_v3_vector" not in sidecar  # sentinel vector is dropped
    assert sidecar["template_id"] == "minimal"


# ---------------------------------------------------------------------------
# Per-tool dispatch (canonical artifact + stdout fallback)
# ---------------------------------------------------------------------------


def test_canonical_jsonl_takes_precedence_over_stdout(tmp_path: Path) -> None:
    """``artifacts_dir/nuclei.jsonl`` short-circuits stdout."""
    canonical = tmp_path / "nuclei.jsonl"
    canonical.write_bytes(_serialise([_nuclei_record(template_id="from-canonical")]))

    findings = parse_nuclei_jsonl(
        stdout=_serialise([_nuclei_record(template_id="from-stdout")]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    [sidecar] = _read_sidecar(tmp_path)
    assert len(findings) == 1
    assert sidecar["template_id"] == "from-canonical"


def test_canonical_jsonl_used_for_wrapper_tools_too(tmp_path: Path) -> None:
    """The canonical ``nuclei.jsonl`` is consulted for the §4.7 wrappers."""
    canonical = tmp_path / "nuclei.jsonl"
    canonical.write_bytes(_serialise([_nuclei_record(template_id="wrapper-source")]))
    parse_nuclei_jsonl(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="spring_boot_actuator",
    )
    [sidecar] = _read_sidecar(tmp_path)
    assert sidecar["template_id"] == "wrapper-source"
    assert sidecar["tool_id"] == "spring_boot_actuator"


def test_stdout_is_used_only_when_no_canonical_files(tmp_path: Path) -> None:
    """No on-disk artefact → stdout is the source of truth."""
    findings = parse_nuclei_jsonl(
        stdout=_serialise([_nuclei_record(template_id="from-stdout-only")]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="jenkins_enum",
    )
    assert len(findings) == 1


def test_empty_canonical_jsonl_falls_through_to_stdout(tmp_path: Path) -> None:
    """A zero-byte canonical file is treated as missing (defence-in-depth)."""
    canonical = tmp_path / "nuclei.jsonl"
    canonical.write_bytes(b"")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([_nuclei_record(template_id="from-stdout")]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Cross-tool reuse
# ---------------------------------------------------------------------------


def test_sidecar_stamps_correct_tool_id_per_invocation(tmp_path: Path) -> None:
    """Each parser invocation stamps its own tool_id on the shared sidecar."""
    rec = _nuclei_record(template_id="CVE-2025-29927")
    payload = _serialise([rec])

    nuclei_dir = tmp_path / "nuclei"
    wrapper_dir = tmp_path / "wrapper"
    parse_nuclei_jsonl(
        stdout=payload,
        stderr=b"",
        artifacts_dir=nuclei_dir,
        tool_id="nuclei",
    )
    parse_nuclei_jsonl(
        stdout=payload,
        stderr=b"",
        artifacts_dir=wrapper_dir,
        tool_id="nextjs_check",
    )
    [sidecar_a] = _read_sidecar(nuclei_dir)
    [sidecar_b] = _read_sidecar(wrapper_dir)
    assert sidecar_a["tool_id"] == "nuclei"
    assert sidecar_b["tool_id"] == "nextjs_check"


# ---------------------------------------------------------------------------
# FindingDTO sentinel identity
# ---------------------------------------------------------------------------


def test_finding_dto_carries_sentinel_identity(tmp_path: Path) -> None:
    """The parser layer never resolves real tenant / scan ids."""
    rec = _nuclei_record()
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].tenant_id == SENTINEL_UUID
    assert findings[0].scan_id == SENTINEL_UUID
    assert findings[0].asset_id == SENTINEL_UUID
    assert findings[0].tool_run_id == SENTINEL_UUID
    assert findings[0].id == SENTINEL_UUID


# ---------------------------------------------------------------------------
# OWASP WSTG hints
# ---------------------------------------------------------------------------


def test_xss_finding_carries_wstg_inpv_hints(tmp_path: Path) -> None:
    """XSS findings get WSTG-INPV-01 + WSTG-INPV-02 hints by default."""
    rec = _nuclei_record(tags=["xss"])
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert "WSTG-INPV-01" in findings[0].owasp_wstg


def test_misconfig_finding_carries_conf_04_hint(tmp_path: Path) -> None:
    """Misconfig findings get the WSTG-CONF-04 hint."""
    rec = _nuclei_record(tags=["misconfig"], severity="medium")
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert "WSTG-CONF-04" in findings[0].owasp_wstg


def test_rce_finding_carries_inpv_12_hint(tmp_path: Path) -> None:
    """RCE findings get the WSTG-INPV-12 hint."""
    rec = _nuclei_record(tags=["rce"])
    findings = parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert "WSTG-INPV-12" in findings[0].owasp_wstg


# ---------------------------------------------------------------------------
# EPSS extraction
# ---------------------------------------------------------------------------


def test_epss_score_preserved_when_in_range(tmp_path: Path) -> None:
    """A 0..1 EPSS score from classification lands on the FindingDTO."""
    payload = _nuclei_record()
    payload["info"]["classification"] = {
        "cve-id": ["CVE-2024-12345"],
        "cwe-id": ["CWE-79"],
        "cvss-score": 9.8,
        "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss-score": 0.97231,
    }
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].epss_score == 0.97231


def test_epss_score_out_of_range_drops_to_none(tmp_path: Path) -> None:
    """A negative / >1 EPSS score is rejected."""
    payload = _nuclei_record()
    payload["info"]["classification"] = {"epss-score": 5.0}
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].epss_score is None


# ---------------------------------------------------------------------------
# Reference URL handling
# ---------------------------------------------------------------------------


def test_references_dedup_and_sort_in_sidecar(tmp_path: Path) -> None:
    """References dedupe + sort for deterministic sidecar output."""
    rec = _nuclei_record(
        references=[
            "https://b.example/",
            "https://a.example/",
            "https://b.example/",
        ]
    )
    parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    [sidecar] = _read_sidecar(tmp_path)
    assert sidecar["references"] == ["https://a.example/", "https://b.example/"]


# ---------------------------------------------------------------------------
# Hard cap
# ---------------------------------------------------------------------------


def test_hard_cap_at_10000_findings(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The 10 000-finding cap fires + emits a structured WARNING."""
    payload = [
        _nuclei_record(template_id=f"tpl-{i:05d}", matched_at=f"https://x/{i}")
        for i in range(10_500)
    ]
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers.nuclei_parser"):
        findings = parse_nuclei_jsonl(
            stdout=_serialise(payload),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="nuclei",
        )
    assert len(findings) == 10_000
    assert any(
        getattr(rec, "event", "") == "nuclei_parser_cap_reached"
        for rec in caplog.records
    )


# ---------------------------------------------------------------------------
# Failure-mode robustness
# ---------------------------------------------------------------------------


def test_non_dict_jsonl_lines_silently_skipped(tmp_path: Path) -> None:
    """JSON arrays / scalars on a line are not nuclei records → skipped."""
    array_line = b"[1, 2, 3]"
    scalar_line = b'"a string"'
    null_line = b"null"
    valid = json.dumps(_nuclei_record(template_id="valid")).encode("utf-8")
    findings = parse_nuclei_jsonl(
        stdout=array_line + b"\n" + scalar_line + b"\n" + null_line + b"\n" + valid,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 1


def test_parse_does_not_raise_on_corrupt_classification_block(tmp_path: Path) -> None:
    """A non-dict ``classification`` is tolerated → sentinel CVSS, default CWE."""
    payload = _nuclei_record()
    payload["info"]["classification"] = "this-should-be-a-dict"
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == SENTINEL_CVSS_SCORE


def test_parse_does_not_raise_on_corrupt_info_block(tmp_path: Path) -> None:
    """A non-dict ``info`` is tolerated → defaults applied across the board."""
    payload = _nuclei_record()
    payload["info"] = "broken"
    findings = parse_nuclei_jsonl(
        stdout=_serialise([payload]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO


def test_request_response_truncated_at_4kib(tmp_path: Path) -> None:
    """Request / response blobs are truncated to keep evidence bounded."""
    big_blob = "X" * (8 * 1024)
    rec = _nuclei_record(request=big_blob, response=big_blob)
    parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    [sidecar] = _read_sidecar(tmp_path)
    assert len(sidecar["request"].encode("utf-8")) <= 8 * 1024
    assert sidecar["request"].endswith("...[truncated]")
    assert sidecar["response"].endswith("...[truncated]")


def test_path_traversal_in_artifacts_dir_blocked(tmp_path: Path) -> None:
    """A traversal-like segment in the canonical name path is refused."""
    # The parser's canonical-name lookup rejects any name containing ``/``,
    # ``\`` or ``..`` — verify that pre-creating such files does not leak.
    bad = tmp_path / "subdir"
    bad.mkdir()
    (bad / "nuclei.jsonl").write_bytes(_serialise([_nuclei_record()]))
    # We pass tmp_path as artifacts_dir; no nuclei.jsonl exists there, so the
    # parser falls through to stdout (which is empty).
    findings = parse_nuclei_jsonl(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Nuclei — additional coverage for normalisation edge cases
# ---------------------------------------------------------------------------


def test_cve_normaliser_drops_whitespace_only_and_garbage_tokens(
    tmp_path: Path,
) -> None:
    """Whitespace / non-conforming tokens are silently dropped."""
    record = _nuclei_record(template_id="cve-noise", severity="high", tags=["rce"])
    record["info"]["classification"] = {
        "cve-id": ["   ", "garbage", "CVE-1998-0001", "CVE-2024-9999"],
    }
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    # ``CVE-1998-0001`` is rejected (year < 1999) — that's the documented floor.
    assert sidecar[0]["cve"] == ["CVE-2024-9999"]


def test_cve_normaliser_handles_year_below_floor(tmp_path: Path) -> None:
    """Years < 1999 are rejected (CVE numbering started in 1999)."""
    record = _nuclei_record(template_id="cve-old", severity="high", tags=["rce"])
    record["info"]["classification"] = {"cve-id": ["CVE-1995-1234"]}
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert "cve" not in sidecar[0]


def test_cve_normaliser_handles_short_sequence(tmp_path: Path) -> None:
    """CVE sequence < 4 digits is rejected as malformed."""
    record = _nuclei_record(template_id="cve-short", severity="high", tags=["rce"])
    record["info"]["classification"] = {"cve-id": ["CVE-2024-12"]}
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert "cve" not in sidecar[0]


def test_cve_string_field_in_classification_is_accepted(tmp_path: Path) -> None:
    """``cve-id`` shipped as a single string (not a list) is honoured."""
    record = _nuclei_record(template_id="cve-str", severity="high", tags=["rce"])
    record["info"]["classification"] = {"cve-id": "CVE-2024-1234"}
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["cve"] == ["CVE-2024-1234"]


def test_cve_inline_string_is_accepted(tmp_path: Path) -> None:
    """A single-string inline ``info.cve`` field round-trips."""
    record = _nuclei_record(template_id="inline-cve", severity="high", tags=["rce"])
    record["info"]["classification"] = {}
    record["info"]["cve"] = "CVE-2024-5678"
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["cve"] == ["CVE-2024-5678"]


def test_cve_inline_list_with_non_strings_is_filtered(tmp_path: Path) -> None:
    """Non-string entries in the inline ``info.cve`` list are discarded."""
    record = _nuclei_record(template_id="mixed-cve", severity="high", tags=["rce"])
    record["info"]["classification"] = {}
    record["info"]["cve"] = ["CVE-2024-1111", 42, None, "CVE-2024-2222"]
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["cve"] == ["CVE-2024-1111", "CVE-2024-2222"]


def test_cwe_inline_int_is_accepted(tmp_path: Path) -> None:
    """A single integer inline ``info.cwe`` field is accepted."""
    record = _nuclei_record(template_id="cwe-int", severity="high", tags=["rce"])
    record["info"]["classification"] = {}
    record["info"]["cwe"] = 79
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert 79 in sidecar[0]["cwe"]


def test_cwe_inline_string_is_accepted(tmp_path: Path) -> None:
    """A single string inline ``info.cwe`` field is accepted."""
    record = _nuclei_record(template_id="cwe-str", severity="high", tags=["rce"])
    record["info"]["classification"] = {}
    record["info"]["cwe"] = "CWE-78"
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert 78 in sidecar[0]["cwe"]


def test_cwe_classification_string_is_accepted(tmp_path: Path) -> None:
    """``cwe-id`` shipped as a single string (not a list) round-trips."""
    record = _nuclei_record(template_id="cwe-clsstr", severity="high", tags=["rce"])
    record["info"]["classification"] = {"cwe-id": "CWE-89"}
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert 89 in sidecar[0]["cwe"]


def test_cwe_boolean_value_is_rejected(tmp_path: Path) -> None:
    """A boolean ``cwe-id`` value is dropped (Python booleans are ints).

    With only ``True`` / ``False`` in the list, the parser yields an empty
    CWE list and the FindingDTO inherits the per-category default — the
    sidecar then drops the field entirely (default-only ⇒ omitted by the
    sidecar's compact-shape rule).
    """
    record = _nuclei_record(template_id="cwe-bool", severity="high", tags=["rce"])
    record["info"]["classification"] = {"cwe-id": [True, False]}
    findings = parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 1
    assert all(isinstance(c, int) and not isinstance(c, bool) for c in findings[0].cwe)


def test_references_as_single_string_is_accepted(tmp_path: Path) -> None:
    """A reference shipped as a single string (not a list) is honoured."""
    record = _nuclei_record(template_id="ref-str", severity="high", tags=["rce"])
    record["info"]["reference"] = "https://example.test/refs/1"
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["references"] == ["https://example.test/refs/1"]


def test_references_garbage_type_yields_no_references(tmp_path: Path) -> None:
    """A non-string / non-list ``reference`` field is dropped silently."""
    record = _nuclei_record(template_id="ref-bad", severity="high", tags=["rce"])
    record["info"]["reference"] = 12345
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert "references" not in sidecar[0]


def test_cvss_score_as_invalid_string_is_dropped(tmp_path: Path) -> None:
    """A non-numeric string ``cvss-score`` falls back to the sentinel."""
    record = _nuclei_record(template_id="bad-cvss", severity="high", tags=["rce"])
    record["info"]["classification"] = {
        "cvss-score": "not-a-number",
        "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    findings = parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cvss_v3_score == SENTINEL_CVSS_SCORE


def test_cvss_score_boolean_is_rejected(tmp_path: Path) -> None:
    """A boolean ``cvss-score`` is rejected (treated as non-numeric)."""
    record = _nuclei_record(template_id="bool-cvss", severity="high", tags=["rce"])
    record["info"]["classification"] = {
        "cvss-score": True,
        "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    findings = parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cvss_v3_score == SENTINEL_CVSS_SCORE


def test_cvss_v4_vector_is_accepted(tmp_path: Path) -> None:
    """A ``CVSS:4.0`` vector is honoured (parser supports v3 + v4 prefixes)."""
    record = _nuclei_record(
        template_id="cvss4",
        severity="high",
        tags=["rce"],
        cvss_score=8.0,
        cvss_metrics="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    )
    findings = parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    assert findings[0].cvss_v3_vector.startswith("CVSS:4.0")


def test_canonical_jsonl_read_failure_falls_back_to_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An OSError reading the canonical file emits a warning + stdout fallback."""
    canonical = tmp_path / "nuclei.jsonl"
    canonical.write_bytes(_serialise([_nuclei_record(template_id="from-canonical")]))

    real_read = Path.read_bytes

    def _exploding_read(self: Path) -> bytes:
        if self.name == "nuclei.jsonl":
            raise PermissionError("denied")
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", _exploding_read)
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers.nuclei_parser"):
        findings = parse_nuclei_jsonl(
            stdout=_serialise([_nuclei_record(template_id="from-stdout")]),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="nuclei",
        )
    assert len(findings) == 1
    assert any(
        getattr(rec, "event", "") == "nuclei_parser_canonical_read_failed"
        for rec in caplog.records
    )


# ---------------------------------------------------------------------------
# Nikto parser
# ---------------------------------------------------------------------------


def test_nikto_parser_yields_finding_per_vulnerability(tmp_path: Path) -> None:
    """A canonical Nikto JSON envelope produces one finding per item."""
    payload = json.dumps(
        {
            "vulnerabilities": [
                {
                    "id": "001234",
                    "msg": "Server header leaks version",
                    "url": "/",
                    "method": "GET",
                    "host": "https://target.example",
                },
                {
                    "id": "005678",
                    "msg": "robots.txt contains sensitive entries",
                    "url": "/robots.txt",
                    "method": "GET",
                    "host": "https://target.example",
                },
            ]
        }
    ).encode("utf-8")
    findings = parse_nikto_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert len(findings) == 2
    sidecar = _read_sidecar(tmp_path)
    assert all(rec["tool_id"] == "nikto" for rec in sidecar)
    assert all(rec["template_id"].startswith("nikto-") for rec in sidecar)


def test_nikto_canonical_file_takes_precedence(tmp_path: Path) -> None:
    """``artifacts_dir/nikto.json`` short-circuits stdout."""
    canonical = tmp_path / "nikto.json"
    canonical.write_text(
        json.dumps({"vulnerabilities": [{"id": "1", "msg": "from canonical"}]}),
        encoding="utf-8",
    )
    findings = parse_nikto_json(
        stdout=json.dumps(
            {"vulnerabilities": [{"id": "2", "msg": "from stdout"}]}
        ).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert "from canonical" in sidecar[0]["name"]


def test_nikto_missing_vulnerabilities_block_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A payload without ``vulnerabilities`` emits a structured warning."""
    payload = json.dumps({"other": "shape"}).encode("utf-8")
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers.nuclei_parser"):
        findings = parse_nikto_json(
            stdout=payload,
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="nikto",
        )
    assert findings == []
    assert any(
        getattr(rec, "event", "") == "nuclei_parser_nikto_missing_vulnerabilities"
        for rec in caplog.records
    )


def test_nikto_skips_non_dict_items(tmp_path: Path) -> None:
    """Non-dict entries inside the ``vulnerabilities`` list are skipped."""
    payload = json.dumps(
        {
            "vulnerabilities": [
                "garbage",
                None,
                42,
                {"id": "valid", "msg": "valid finding", "url": "/"},
            ]
        }
    ).encode("utf-8")
    findings = parse_nikto_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert len(findings) == 1


def test_nikto_skips_items_without_msg(tmp_path: Path) -> None:
    """An item missing the ``msg`` field is silently dropped."""
    payload = json.dumps(
        {
            "vulnerabilities": [
                {"id": "no-msg", "url": "/"},
                {"id": "valid", "msg": "ok", "url": "/"},
            ]
        }
    ).encode("utf-8")
    findings = parse_nikto_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert len(findings) == 1


def test_nikto_synthesises_template_id_when_id_missing(tmp_path: Path) -> None:
    """An entry without ``id`` gets a deterministic synthesized template id."""
    payload = json.dumps(
        {
            "vulnerabilities": [
                {"msg": "header leaks", "url": "/"},
            ]
        }
    ).encode("utf-8")
    parse_nikto_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    [sidecar] = _read_sidecar(tmp_path)
    assert sidecar["template_id"].startswith("nikto-")
    assert sidecar["template_id"] != "nikto-"


def test_nikto_empty_payload_returns_empty_list(tmp_path: Path) -> None:
    """Empty stdout + no canonical file → ``[]`` + no sidecar."""
    findings = parse_nikto_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_nikto_malformed_json_returns_empty_list(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A non-JSON payload fail-softs to an empty list."""
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = parse_nikto_json(
            stdout=b"{not-json",
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="nikto",
        )
    assert findings == []


def test_nikto_top_level_array_is_rejected(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A top-level JSON array (not the expected envelope) emits a warning."""
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers.nuclei_parser"):
        findings = parse_nikto_json(
            stdout=b'[{"msg": "x"}]',
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="nikto",
        )
    assert findings == []
    assert any(
        getattr(rec, "event", "") == "nuclei_parser_stdout_not_object"
        for rec in caplog.records
    )


def test_nikto_canonical_array_is_rejected(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A canonical file with a top-level array warns + falls through to stdout."""
    canonical = tmp_path / "nikto.json"
    canonical.write_text("[1, 2, 3]", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers.nuclei_parser"):
        findings = parse_nikto_json(
            stdout=b"",
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="nikto",
        )
    assert findings == []
    assert any(
        getattr(rec, "event", "") == "nuclei_parser_canonical_not_object"
        for rec in caplog.records
    )


def test_nikto_canonical_read_error_falls_back_to_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An OSError on the canonical file warns + falls back to stdout."""
    canonical = tmp_path / "nikto.json"
    canonical.write_text(
        json.dumps({"vulnerabilities": [{"id": "x", "msg": "x", "url": "/"}]}),
        encoding="utf-8",
    )
    real_read = Path.read_bytes

    def _exploding_read(self: Path) -> bytes:
        if self.name == "nikto.json":
            raise PermissionError("denied")
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", _exploding_read)
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers.nuclei_parser"):
        findings = parse_nikto_json(
            stdout=json.dumps(
                {"vulnerabilities": [{"id": "y", "msg": "y", "url": "/"}]}
            ).encode("utf-8"),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="nikto",
        )
    assert len(findings) == 1
    assert any(
        getattr(rec, "event", "") == "nuclei_parser_canonical_read_failed"
        for rec in caplog.records
    )


# ---------------------------------------------------------------------------
# Wapiti parser
# ---------------------------------------------------------------------------


def test_wapiti_parser_yields_findings_grouped_by_category(tmp_path: Path) -> None:
    """A Wapiti envelope produces one finding per item in each category."""
    payload = json.dumps(
        {
            "vulnerabilities": {
                "SQL Injection": [
                    {
                        "method": "GET",
                        "path": "/login.php",
                        "info": "SQL error in id",
                        "parameter": "id",
                    }
                ],
                "Cross Site Scripting": [
                    {
                        "method": "POST",
                        "path": "/comment",
                        "info": "Reflected XSS in body",
                        "parameter": "comment",
                    }
                ],
                "Backup file": [
                    {
                        "method": "GET",
                        "path": "/index.php.bak",
                        "info": "Backup file exposed",
                    }
                ],
            }
        }
    ).encode("utf-8")
    findings = parse_wapiti_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert len(findings) == 3
    categories = {f.category for f in findings}
    assert FindingCategory.SQLI in categories
    assert FindingCategory.XSS in categories
    assert FindingCategory.MISCONFIG in categories


def test_wapiti_unknown_category_falls_back_to_other(tmp_path: Path) -> None:
    """A category outside :data:`_WAPITI_CATEGORY` defaults to OTHER."""
    payload = json.dumps(
        {
            "vulnerabilities": {
                "Some Brand-New Category": [
                    {"method": "GET", "path": "/", "info": "weird issue"}
                ]
            }
        }
    ).encode("utf-8")
    findings = parse_wapiti_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.OTHER
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_wapiti_known_category_carries_likely_confidence(tmp_path: Path) -> None:
    """Concrete vulnerability categories (SQLi, XSS, …) → LIKELY."""
    payload = json.dumps(
        {
            "vulnerabilities": {
                "SQL Injection": [{"method": "GET", "path": "/", "info": "x"}]
            }
        }
    ).encode("utf-8")
    findings = parse_wapiti_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_wapiti_missing_vulnerabilities_block_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A payload without a top-level ``vulnerabilities`` dict warns + ``[]``."""
    payload = json.dumps({"other": "shape"}).encode("utf-8")
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers.nuclei_parser"):
        findings = parse_wapiti_json(
            stdout=payload,
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="wapiti",
        )
    assert findings == []
    assert any(
        getattr(rec, "event", "") == "nuclei_parser_wapiti_missing_vulnerabilities"
        for rec in caplog.records
    )


def test_wapiti_skips_non_dict_items(tmp_path: Path) -> None:
    """Non-dict items inside a category list are silently skipped."""
    payload = json.dumps(
        {
            "vulnerabilities": {
                "SQL Injection": [
                    "junk",
                    None,
                    {"method": "GET", "path": "/", "info": "ok"},
                ]
            }
        }
    ).encode("utf-8")
    findings = parse_wapiti_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert len(findings) == 1


def test_wapiti_skips_non_string_categories(tmp_path: Path) -> None:
    """Non-string keys / non-list values inside ``vulnerabilities`` are skipped."""
    block = {
        "SQL Injection": "not-a-list",
        # JSON keys must be strings, but pythonised dicts can have any type.
    }
    payload = json.dumps({"vulnerabilities": block}).encode("utf-8")
    findings = parse_wapiti_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert findings == []


def test_wapiti_canonical_takes_precedence(tmp_path: Path) -> None:
    """``artifacts_dir/wapiti.json`` short-circuits stdout."""
    canonical = tmp_path / "wapiti.json"
    canonical.write_text(
        json.dumps(
            {
                "vulnerabilities": {
                    "SQL Injection": [{"method": "GET", "path": "/canon", "info": "c"}]
                }
            }
        ),
        encoding="utf-8",
    )
    findings = parse_wapiti_json(
        stdout=json.dumps(
            {
                "vulnerabilities": {
                    "SQL Injection": [{"method": "GET", "path": "/stdout", "info": "s"}]
                }
            }
        ).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert len(findings) == 1
    [sidecar] = _read_sidecar(tmp_path)
    assert "/canon" in sidecar["matched_at"]


def test_wapiti_empty_payload_returns_empty_list(tmp_path: Path) -> None:
    """Empty stdout + no canonical file → ``[]`` + no sidecar emitted."""
    findings = parse_wapiti_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_wapiti_records_carry_request_response_when_present(tmp_path: Path) -> None:
    """``http_request`` / ``http_response`` round-trip into the sidecar."""
    payload = json.dumps(
        {
            "vulnerabilities": {
                "Command execution": [
                    {
                        "method": "POST",
                        "path": "/api/run",
                        "info": "Command injection in cmd",
                        "parameter": "cmd",
                        "http_request": "POST /api/run HTTP/1.1\nHost: x",
                        "http_response": "HTTP/1.1 200 OK\n\nuid=0",
                    }
                ]
            }
        }
    ).encode("utf-8")
    parse_wapiti_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    [sidecar] = _read_sidecar(tmp_path)
    assert "POST /api/run" in sidecar["request"]
    assert "uid=0" in sidecar["response"]


def test_wapiti_top_level_array_is_rejected(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A top-level JSON array warns + returns empty (envelope must be an object)."""
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers.nuclei_parser"):
        findings = parse_wapiti_json(
            stdout=b"[1, 2, 3]",
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="wapiti",
        )
    assert findings == []
    assert any(
        getattr(rec, "event", "") == "nuclei_parser_stdout_not_object"
        for rec in caplog.records
    )


def test_cwe_inline_list_is_accepted(tmp_path: Path) -> None:
    """An inline ``info.cwe`` shipped as a list of ints / strings round-trips."""
    record = _nuclei_record(
        template_id="cwe-inline-list", severity="high", tags=["rce"]
    )
    record["info"]["classification"] = {}
    record["info"]["cwe"] = [79, "CWE-200"]
    parse_nuclei_jsonl(
        stdout=_serialise([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nuclei",
    )
    sidecar = _read_sidecar(tmp_path)
    assert 79 in sidecar[0]["cwe"]
    assert 200 in sidecar[0]["cwe"]


def test_sidecar_write_failure_is_logged_not_raised(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An OSError writing the sidecar is logged + parsing still returns findings."""
    real_open = Path.open

    def _exploding_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == EVIDENCE_SIDECAR_NAME:
            raise PermissionError("sidecar denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _exploding_open)
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers.nuclei_parser"):
        findings = parse_nuclei_jsonl(
            stdout=_serialise([_nuclei_record()]),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="nuclei",
        )
    assert len(findings) == 1, "sidecar failure must not drop the in-memory findings"
    assert any(
        getattr(rec, "event", "") == "nuclei_parser_evidence_sidecar_write_failed"
        for rec in caplog.records
    )


def test_safe_join_rejects_traversal_segments(tmp_path: Path) -> None:
    """Defensive ``_safe_join`` refuses any name with ``/``, ``\\`` or ``..``.

    The public ``parse_*`` APIs only call this with hardcoded canonical
    names so the gate is unreachable in normal flow — pinning it directly
    locks the contract for any future internal caller.
    """
    from src.sandbox.parsers import nuclei_parser as np_mod

    assert np_mod._safe_join(tmp_path, "../etc/passwd") is None
    assert np_mod._safe_join(tmp_path, "sub/dir/file") is None
    assert np_mod._safe_join(tmp_path, "sub\\windows\\file") is None
    assert np_mod._safe_join(tmp_path, "nuclei.jsonl") == tmp_path / "nuclei.jsonl"


# ---------------------------------------------------------------------------
# Nikto JSON minimal parser (Backlog/dev1_md §4.8 — shares ``_emit`` with
# nuclei). Each test pins one contract documented in the parser.
# ---------------------------------------------------------------------------


def test_nikto_happy_path_emits_misconfig_finding(tmp_path: Path) -> None:
    """Well-formed Nikto JSON yields one MISCONFIG finding per vulnerability."""
    payload = {
        "vulnerabilities": [
            {
                "id": "001234",
                "msg": "Server header leaks Apache/2.4.49 (vulnerable)",
                "url": "/",
                "method": "GET",
                "host": "target.example",
            },
            {
                "id": "999999",
                "msg": "/admin/ exposes admin login",
                "url": "/admin/",
                "method": "GET",
            },
        ]
    }
    findings = parse_nikto_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert len(findings) == 2
    for finding in findings:
        assert finding.category is FindingCategory.MISCONFIG
        assert finding.confidence is ConfidenceLevel.SUSPECTED
    sidecar = _read_sidecar(tmp_path)
    assert {entry["template_id"] for entry in sidecar} == {
        "nikto-001234",
        "nikto-999999",
    }
    assert all(entry["tool_id"] == "nikto" for entry in sidecar)


def test_nikto_missing_id_falls_back_to_synthetic_template_id(tmp_path: Path) -> None:
    """Records without ``id`` get a deterministic ``nikto-<hex>`` stub."""
    payload = {
        "vulnerabilities": [
            {"msg": "OSVDB-3268: /icons/ directory listing is enabled.", "url": "/"}
        ]
    }
    findings = parse_nikto_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert len(findings) == 1
    [entry] = _read_sidecar(tmp_path)
    assert entry["template_id"].startswith("nikto-")
    assert len(entry["template_id"]) > len("nikto-")


def test_nikto_records_without_msg_are_skipped(tmp_path: Path) -> None:
    """Items missing the canonical ``msg`` field are silently dropped."""
    payload = {
        "vulnerabilities": [
            {"id": "1", "url": "/"},
            {"id": "2", "msg": "real finding", "url": "/admin"},
            "not-a-dict",
        ]
    }
    findings = parse_nikto_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert len(findings) == 1


def test_nikto_missing_vulnerabilities_block_yields_no_findings(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Payload without a ``vulnerabilities`` list logs a warning and returns [].

    The parser must not crash on Nikto output that lacks the canonical
    block — operators sometimes pipe an empty wrapper from a wrapper
    script that swallows the body.
    """
    caplog.set_level(logging.WARNING)
    findings = parse_nikto_json(
        stdout=b'{"version": "2.5"}',
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert findings == []
    assert any(
        "nikto_missing_vulnerabilities" in record.message
        or "nikto_missing_vulnerabilities" in str(record)
        for record in caplog.records
    )


def test_nikto_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    """``artifacts_dir/nikto.json`` is consulted before stdout."""
    canonical_payload = {
        "vulnerabilities": [{"id": "C", "msg": "from canonical artifact", "url": "/c"}]
    }
    stdout_payload = {
        "vulnerabilities": [{"id": "S", "msg": "from stdout", "url": "/s"}]
    }
    (tmp_path / "nikto.json").write_text(
        json.dumps(canonical_payload), encoding="utf-8"
    )
    findings = parse_nikto_json(
        stdout=json.dumps(stdout_payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    [entry] = _read_sidecar(tmp_path)
    assert entry["template_id"] == "nikto-C"
    assert len(findings) == 1


def test_nikto_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    """Empty stdout + missing canonical artifact = clean empty result."""
    findings = parse_nikto_json(
        stdout=b"", stderr=b"", artifacts_dir=tmp_path, tool_id="nikto"
    )
    assert findings == []


def test_nikto_malformed_json_returns_no_findings(tmp_path: Path) -> None:
    """Garbage stdout fails JSON decoding silently — fail-soft contract."""
    findings = parse_nikto_json(
        stdout=b"<<<not-json>>>",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert findings == []


def test_nikto_top_level_array_is_rejected_by_loader(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Top-level JSON array (not object) logs a warning and returns []."""
    caplog.set_level(logging.WARNING)
    findings = parse_nikto_json(
        stdout=b"[1,2,3]",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nikto",
    )
    assert findings == []
    assert any("not_object" in str(rec) for rec in caplog.records)


# ---------------------------------------------------------------------------
# Wapiti JSON minimal parser (Backlog/dev1_md §4.8). Same shared pipeline.
# ---------------------------------------------------------------------------


def test_wapiti_routes_known_categories_to_finding_category(tmp_path: Path) -> None:
    """Known Wapiti category labels map to ``FindingCategory`` enum values."""
    payload = {
        "vulnerabilities": {
            "SQL Injection": [
                {
                    "method": "GET",
                    "path": "/login.php?id=1",
                    "info": "PostgreSQL error reflected",
                    "parameter": "id",
                    "http_request": "GET /login.php?id=1' HTTP/1.1",
                    "http_response": "HTTP/1.1 500 Internal Server Error",
                }
            ],
            "Reflected Cross Site Scripting": [
                {
                    "method": "GET",
                    "path": "/search?q=<script>alert(1)</script>",
                    "info": "<script> reflected",
                    "parameter": "q",
                }
            ],
            "Cross Site Request Forgery": [
                {"method": "POST", "path": "/profile/update", "info": "no token"}
            ],
            "Server Side Request Forgery": [
                {
                    "method": "POST",
                    "path": "/proxy",
                    "info": "metadata endpoint reachable",
                }
            ],
        }
    }
    findings = parse_wapiti_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    categories = {f.category for f in findings}
    assert {
        FindingCategory.SQLI,
        FindingCategory.XSS,
        FindingCategory.CSRF,
        FindingCategory.SSRF,
    } <= categories
    confidences = {f.confidence for f in findings}
    assert confidences == {ConfidenceLevel.LIKELY}


def test_wapiti_unknown_category_falls_back_to_other_with_suspected_confidence(
    tmp_path: Path,
) -> None:
    """Unmapped Wapiti label → :class:`FindingCategory.OTHER` + SUSPECTED."""
    payload = {
        "vulnerabilities": {
            "Some Brand New Category": [
                {"method": "GET", "path": "/foo", "info": "exotic"}
            ]
        }
    }
    findings = parse_wapiti_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.OTHER
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_wapiti_non_list_value_under_category_is_skipped(tmp_path: Path) -> None:
    """A category whose value is not a list is silently skipped."""
    payload = {
        "vulnerabilities": {
            "SQL Injection": [{"method": "GET", "path": "/ok", "info": "real"}],
            "Cross Site Scripting": "garbage-not-a-list",
        }
    }
    findings = parse_wapiti_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.SQLI


def test_wapiti_non_dict_item_inside_list_is_skipped(tmp_path: Path) -> None:
    """Rows that are not dicts inside the per-category list are skipped."""
    payload = {
        "vulnerabilities": {
            "SQL Injection": [
                "not-a-dict",
                {"method": "GET", "path": "/ok", "info": "real"},
                42,
            ]
        }
    }
    findings = parse_wapiti_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert len(findings) == 1


def test_wapiti_missing_vulnerabilities_block_yields_no_findings(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Payload without a ``vulnerabilities`` dict logs a warning and returns []."""
    caplog.set_level(logging.WARNING)
    findings = parse_wapiti_json(
        stdout=b'{"version": "3.1.7"}',
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert findings == []
    assert any("wapiti_missing_vulnerabilities" in str(rec) for rec in caplog.records)


def test_wapiti_request_response_truncated_in_sidecar(tmp_path: Path) -> None:
    """Oversized HTTP blobs are truncated to keep the sidecar bounded."""
    big = "Z" * (8 * 1024)
    payload = {
        "vulnerabilities": {
            "SQL Injection": [
                {
                    "method": "POST",
                    "path": "/login",
                    "info": "boom",
                    "parameter": "user",
                    "http_request": big,
                    "http_response": big,
                }
            ]
        }
    }
    parse_wapiti_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    [entry] = _read_sidecar(tmp_path)
    assert entry["request"].endswith("...[truncated]")
    assert entry["response"].endswith("...[truncated]")
    assert len(entry["request"].encode("utf-8")) <= 8 * 1024


def test_wapiti_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    """``artifacts_dir/wapiti.json`` is consulted before stdout."""
    canonical = {
        "vulnerabilities": {
            "Cross Site Scripting": [
                {"method": "GET", "path": "/canon", "info": "from disk"}
            ]
        }
    }
    stdout_payload = {
        "vulnerabilities": {
            "SQL Injection": [
                {"method": "GET", "path": "/stdout", "info": "from stdout"}
            ]
        }
    }
    (tmp_path / "wapiti.json").write_text(json.dumps(canonical), encoding="utf-8")
    findings = parse_wapiti_json(
        stdout=json.dumps(stdout_payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    [entry] = _read_sidecar(tmp_path)
    assert entry["matched_at"] == "GET /canon"
    assert findings[0].category is FindingCategory.XSS


def test_wapiti_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    """Empty stdout + no canonical artifact = clean empty result."""
    findings = parse_wapiti_json(
        stdout=b"", stderr=b"", artifacts_dir=tmp_path, tool_id="wapiti"
    )
    assert findings == []


def test_wapiti_top_level_array_is_rejected_by_loader(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Top-level JSON array (not object) logs a warning and returns []."""
    caplog.set_level(logging.WARNING)
    findings = parse_wapiti_json(
        stdout=b"[]",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    assert findings == []
    assert any("not_object" in str(rec) for rec in caplog.records)


# ---------------------------------------------------------------------------
# Wapiti — per-category severity mapping (M4: severity must NOT be hard-coded
# to ``medium`` for every category — informational fingerprints climb down,
# active injection / RCE classes climb up).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("category_name", "expected_severity"),
    [
        # Informational fingerprint surface — no exploit primitive.
        ("Fingerprint web technology", "info"),
        ("Fingerprint web application framework", "info"),
        ("Internal Server Error", "info"),
        # Missing-header / cookie-flag misconfig — disclosure-class.
        ("Strict-Transport-Security Header", "low"),
        ("Backup file", "low"),
        ("Content Security Policy Configuration", "low"),
        ("X-Frame-Options Header", "low"),
        # Mid-impact request-forgery / bypass primitives.
        ("Cross Site Request Forgery", "medium"),
        ("Open Redirect", "medium"),
        ("Htaccess Bypass", "medium"),
        # Direct injection / disclosure / SSRF — high.
        ("SQL Injection", "high"),
        ("Blind SQL Injection", "high"),
        ("Cross Site Scripting", "high"),
        ("XML External Entity", "high"),
        ("Server Side Request Forgery", "high"),
        ("Path Traversal", "high"),
        # OS command injection — most dangerous Wapiti class.
        ("Command execution", "critical"),
        ("Commands Execution", "critical"),
    ],
)
def test_wapiti_severity_per_category_matches_pinned_map(
    category_name: str, expected_severity: str, tmp_path: Path
) -> None:
    """Each Wapiti category lands on its pinned severity bucket.

    Regression guard for ARG-015 M4: prior implementation hard-coded
    ``severity="medium"`` for every category, which over-reported
    fingerprint findings (should be ``info``) and under-reported
    command-injection findings (should be ``critical``). The pinned map
    in :data:`_WAPITI_SEVERITY` is the source of truth.
    """
    payload = json.dumps(
        {
            "vulnerabilities": {
                category_name: [
                    {
                        "method": "GET",
                        "path": "/some/path",
                        "info": f"{category_name} probe",
                        "parameter": "p",
                    }
                ]
            }
        }
    ).encode("utf-8")
    parse_wapiti_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    [sidecar] = _read_sidecar(tmp_path)
    assert sidecar["severity"] == expected_severity, (
        f"{category_name}: expected severity {expected_severity!r}, "
        f"got {sidecar['severity']!r}"
    )


def test_wapiti_unknown_category_falls_back_to_default_medium(
    tmp_path: Path,
) -> None:
    """A Wapiti category not in the pinned map falls back to ``medium``."""
    payload = json.dumps(
        {
            "vulnerabilities": {
                "Brand New Future Wapiti Category": [
                    {"method": "POST", "path": "/x", "info": "novel finding"}
                ]
            }
        }
    ).encode("utf-8")
    parse_wapiti_json(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wapiti",
    )
    [sidecar] = _read_sidecar(tmp_path)
    assert sidecar["severity"] == "medium"


# ---------------------------------------------------------------------------
# Nikto — synthesized template_id determinism (M5: must use a stable
# digest, not Python's per-process-randomised ``hash()``).
# ---------------------------------------------------------------------------


def test_nikto_synthesised_template_id_is_deterministic_across_calls(
    tmp_path: Path,
) -> None:
    """Same Nikto fixture → byte-identical sidecar across repeated parses.

    Regression guard for ARG-015 M5: the prior implementation derived
    the synthesized ``template_id`` from ``hash(msg) & 0xFFFFFF``, which
    is randomised per Python process via ``PYTHONHASHSEED``. Two CI
    workers parsing the same fixture would produce different sidecars.
    A SHA-256-based digest must keep both runs identical.
    """
    payload = json.dumps(
        {
            "vulnerabilities": [
                {
                    "msg": "Server header reveals Apache/2.4.41 (Ubuntu)",
                    "url": "/",
                    "method": "GET",
                },
                {
                    "msg": "/admin/: Admin login page found.",
                    "url": "/admin/",
                    "method": "GET",
                },
            ]
        }
    ).encode("utf-8")
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    out_a.mkdir()
    out_b.mkdir()
    parse_nikto_json(stdout=payload, stderr=b"", artifacts_dir=out_a, tool_id="nikto")
    parse_nikto_json(stdout=payload, stderr=b"", artifacts_dir=out_b, tool_id="nikto")
    bytes_a = (out_a / EVIDENCE_SIDECAR_NAME).read_bytes()
    bytes_b = (out_b / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert bytes_a == bytes_b, (
        "Nikto sidecar bytes must be byte-identical across parser invocations "
        "(determinism gate for cross-process CI replay); diff suggests "
        "a non-stable hash leaked back into the synthesized template_id"
    )


def test_nikto_synthesised_template_id_matches_sha256_prefix(
    tmp_path: Path,
) -> None:
    """The synthesized ``template_id`` is the first 12 hex chars of SHA-256(msg).

    Pins the exact construction so anyone reviewing a sidecar can
    reproduce the identifier from the message text alone (operator
    debuggability) and so any future swap of the digest function
    (e.g. blake2b) lights up here in CI.
    """
    msg = "Server header leaks framework version"
    payload = json.dumps(
        {"vulnerabilities": [{"msg": msg, "url": "/v", "method": "GET"}]}
    ).encode("utf-8")
    parse_nikto_json(
        stdout=payload, stderr=b"", artifacts_dir=tmp_path, tool_id="nikto"
    )
    [sidecar] = _read_sidecar(tmp_path)

    import hashlib

    expected_suffix = hashlib.sha256(msg.encode("utf-8")).hexdigest()[:12]
    assert sidecar["template_id"] == f"nikto-{expected_suffix}"


# ---------------------------------------------------------------------------
# Cross-tool sidecar tagging — the sidecar carries ``tool_id`` so the
# downstream evidence pipeline can demultiplex.
# ---------------------------------------------------------------------------


def test_sidecar_records_carry_calling_tool_id(tmp_path: Path) -> None:
    """A nuclei JSONL parsed under ``nextjs_check`` stamps that tool_id."""
    rec = _nuclei_record()
    parse_nuclei_jsonl(
        stdout=_serialise([rec]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="nextjs_check",
    )
    [entry] = _read_sidecar(tmp_path)
    assert entry["tool_id"] == "nextjs_check"
