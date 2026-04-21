"""Unit tests for :mod:`src.sandbox.parsers.semgrep_parser` (Backlog/dev1_md §4.16 — ARG-018).

Each test pins one contract documented in the parser:

* ``parse_semgrep_json`` resolves ``artifacts_dir/semgrep.json`` first,
  then falls back to ``stdout``.
* Severity → ARGUS bucket via ``severity + (confidence|likelihood|impact)``:

  - ``ERROR`` + HIGH-anywhere → ``critical``;
  - ``ERROR``                  → ``high``;
  - ``WARNING`` + HIGH-anywhere → ``high``;
  - ``WARNING``                 → ``medium``;
  - ``INFO``                    → ``low``;
  - everything else             → ``info``.

* Confidence ladder: ``ERROR`` → ``LIKELY`` (always);
  ``WARNING`` + ``confidence=HIGH`` → ``LIKELY``; everything else
  → ``SUSPECTED``.
* Category resolution precedence: CWE → metadata.category (security
  only) → check_id substring → MISCONFIG default.
* Non-security ``category`` values (best-practice / correctness /
  maintainability) collapse to :class:`FindingCategory.INFO`.
* CWE list extracted from the canonical Semgrep registry shape
  (``"CWE-78: Improper Neutralization …"``) and from bare integers.
* OWASP-WSTG hints follow category, not the metadata.owasp tags
  (those land in the sidecar separately).
* Records collapse on a stable ``(check_id, path, start_line)`` dedup
  key — re-emitted multi-line matchers fold into one finding.
* Sorting is deterministic — severity desc → check_id → path → line.
* Records missing ``check_id`` or ``path`` are dropped with a structured
  ``WARNING semgrep_parser.result_missing_field`` event.
* ``errors[]`` (parse failures / rule errors) trigger one
  ``WARNING semgrep_parser.scan_errors`` event and never inflate the
  FindingDTO list.
* Malformed envelopes return ``[]`` after a structured WARNING.
* Sidecar JSONL ``semgrep_findings.jsonl`` carries one record per
  emitted finding stamped with ``tool_id=semgrep``.
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
from src.sandbox.parsers.semgrep_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_semgrep_json,
)


# ---------------------------------------------------------------------------
# Builders for canonical fixture shapes
# ---------------------------------------------------------------------------


def _result(
    *,
    check_id: str = "python.lang.security.audit.dangerous-subprocess",
    path: str = "src/utils.py",
    start_line: int = 42,
    end_line: int = 44,
    start_col: int = 9,
    end_col: int = 35,
    severity: str = "ERROR",
    message: str = "subprocess called with shell=True permits OS injection.",
    cwe: list[Any] | None = None,
    owasp: list[str] | None = None,
    category: str | None = "security",
    confidence: str | None = "HIGH",
    likelihood: str | None = "HIGH",
    impact: str | None = "HIGH",
    references: list[str] | None = None,
    technology: list[str] | None = None,
    subcategory: list[str] | None = None,
    lines: str = "subprocess.run(cmd, shell=True)",
    fingerprint: str = "deadbeefcafe",
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if cwe is not None:
        metadata["cwe"] = list(cwe)
    if owasp is not None:
        metadata["owasp"] = list(owasp)
    if category is not None:
        metadata["category"] = category
    if confidence is not None:
        metadata["confidence"] = confidence
    if likelihood is not None:
        metadata["likelihood"] = likelihood
    if impact is not None:
        metadata["impact"] = impact
    if references is not None:
        metadata["references"] = list(references)
    if technology is not None:
        metadata["technology"] = list(technology)
    if subcategory is not None:
        metadata["subcategory"] = list(subcategory)
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": start_line, "col": start_col, "offset": 1234},
        "end": {"line": end_line, "col": end_col, "offset": 1300},
        "extra": {
            "message": message,
            "severity": severity,
            "metadata": metadata,
            "lines": lines,
            "fingerprint": fingerprint,
            "metavars": {},
        },
    }


def _envelope(
    *,
    results: list[dict[str, Any]] | None = None,
    errors: list[dict[str, Any]] | None = None,
    version: str = "1.59.0",
) -> dict[str, Any]:
    return {
        "version": version,
        "results": list(results or []),
        "errors": list(errors or []),
        "paths": {"scanned": [], "skipped": []},
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def artifacts_dir(tmp_path: Path) -> Path:
    out = tmp_path / "artifacts"
    out.mkdir()
    return out


def _write_canonical(artifacts_dir: Path, payload: dict[str, Any]) -> None:
    (artifacts_dir / "semgrep.json").write_text(json.dumps(payload), encoding="utf-8")


def _read_sidecar(artifacts_dir: Path) -> list[dict[str, Any]]:
    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    if not sidecar.is_file():
        return []
    return [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ===========================================================================
# 1. Payload resolution
# ===========================================================================


def test_canonical_artifact_takes_precedence_over_stdout(
    artifacts_dir: Path,
) -> None:
    """``semgrep.json`` on disk wins over stdout."""
    canonical = _envelope(results=[_result(check_id="rule-canonical")])
    stdout_payload = _envelope(results=[_result(check_id="rule-stdout")])
    _write_canonical(artifacts_dir, canonical)
    parse_semgrep_json(
        stdout=json.dumps(stdout_payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["check_id"] == "rule-canonical"


def test_stdout_used_when_canonical_absent(artifacts_dir: Path) -> None:
    """When ``semgrep.json`` is missing, parser falls back to stdout."""
    payload = _envelope(results=[_result()])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert len(findings) == 1


def test_empty_input_returns_empty_list(artifacts_dir: Path) -> None:
    """No canonical artifact and empty stdout → empty result."""
    findings = parse_semgrep_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings == []
    assert not (artifacts_dir / EVIDENCE_SIDECAR_NAME).exists()


def test_envelope_not_dict_returns_empty(
    artifacts_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Top-level array (not a dict) is rejected with a WARNING."""
    caplog.set_level(logging.WARNING)
    findings = parse_semgrep_json(
        stdout=b"[]",
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings == []
    assert any("envelope_not_dict" in r.message for r in caplog.records)


# ===========================================================================
# 2. Severity → ARGUS bucket mapping
# ===========================================================================


def test_error_with_high_signal_maps_to_critical(
    artifacts_dir: Path,
) -> None:
    """ERROR + (confidence=HIGH | likelihood=HIGH | impact=HIGH) → critical."""
    payload = _envelope(
        results=[
            _result(
                severity="ERROR",
                confidence="HIGH",
                likelihood="MEDIUM",
                impact="MEDIUM",
            )
        ]
    )
    parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["severity"] == "critical"


def test_error_without_high_signal_maps_to_high(
    artifacts_dir: Path,
) -> None:
    """ERROR with all metadata MEDIUM → high (no escalation)."""
    payload = _envelope(
        results=[
            _result(
                severity="ERROR",
                confidence="MEDIUM",
                likelihood="MEDIUM",
                impact="MEDIUM",
            )
        ]
    )
    parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["severity"] == "high"


def test_warning_with_high_signal_maps_to_high(artifacts_dir: Path) -> None:
    """WARNING + HIGH-anywhere → high."""
    payload = _envelope(
        results=[
            _result(
                severity="WARNING",
                confidence="MEDIUM",
                likelihood="HIGH",
                impact="MEDIUM",
            )
        ]
    )
    parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["severity"] == "high"


def test_warning_without_high_signal_maps_to_medium(
    artifacts_dir: Path,
) -> None:
    """WARNING with no HIGH metadata → medium."""
    payload = _envelope(
        results=[
            _result(
                severity="WARNING",
                confidence="LOW",
                likelihood="LOW",
                impact="LOW",
            )
        ]
    )
    parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["severity"] == "medium"


def test_info_severity_maps_to_low(artifacts_dir: Path) -> None:
    """``INFO`` severity → low."""
    payload = _envelope(results=[_result(severity="INFO")])
    parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["severity"] == "low"


# ===========================================================================
# 3. Confidence ladder
# ===========================================================================


def test_error_severity_always_likely(artifacts_dir: Path) -> None:
    """ERROR → LIKELY regardless of metadata.confidence."""
    payload = _envelope(results=[_result(severity="ERROR", confidence="LOW")])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings[0].confidence == ConfidenceLevel.LIKELY


def test_warning_with_confidence_high_escalates_to_likely(
    artifacts_dir: Path,
) -> None:
    """WARNING + confidence=HIGH → LIKELY."""
    payload = _envelope(results=[_result(severity="WARNING", confidence="HIGH")])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings[0].confidence == ConfidenceLevel.LIKELY


def test_warning_without_confidence_high_stays_suspected(
    artifacts_dir: Path,
) -> None:
    """WARNING without confidence=HIGH → SUSPECTED."""
    payload = _envelope(results=[_result(severity="WARNING", confidence="MEDIUM")])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings[0].confidence == ConfidenceLevel.SUSPECTED


# ===========================================================================
# 4. Category resolution
# ===========================================================================


def test_cwe_routes_to_specific_category(artifacts_dir: Path) -> None:
    """CWE-89 lifts the record to SQLI even if check_id is generic."""
    payload = _envelope(
        results=[
            _result(
                check_id="rules.generic.taint",
                cwe=["CWE-89: SQL Injection"],
            )
        ]
    )
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings[0].category == FindingCategory.SQLI


def test_non_security_metadata_collapses_to_info(
    artifacts_dir: Path,
) -> None:
    """``metadata.category != 'security'`` collapses to INFO."""
    payload = _envelope(
        results=[
            _result(
                check_id="java.spring.dead-code-loop",
                category="best-practice",
                cwe=["CWE-89"],  # would normally route to SQLI
            )
        ]
    )
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings[0].category == FindingCategory.INFO


def test_check_id_fallback_routes_to_xss(artifacts_dir: Path) -> None:
    """No CWE / no category → check_id substring picks XSS."""
    payload = _envelope(
        results=[
            _result(
                check_id="js.express.xss.reflected",
                cwe=None,
                category=None,
            )
        ]
    )
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings[0].category == FindingCategory.XSS


def test_no_signal_defaults_to_misconfig(artifacts_dir: Path) -> None:
    """No CWE, no category, generic check_id → MISCONFIG fallback."""
    payload = _envelope(
        results=[
            _result(
                check_id="generic.something.else",
                cwe=None,
                category=None,
            )
        ]
    )
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings[0].category == FindingCategory.MISCONFIG


# ===========================================================================
# 5. CWE / OWASP extraction
# ===========================================================================


def test_cwe_parses_canonical_registry_shape(artifacts_dir: Path) -> None:
    """``"CWE-78: Improper Neutralization …"`` → 78."""
    payload = _envelope(
        results=[
            _result(
                cwe=["CWE-78: Improper Neutralization of OS Command"],
            )
        ]
    )
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings[0].cwe == [78]


def test_cwe_parses_mixed_int_and_string(artifacts_dir: Path) -> None:
    """Mix of ``CWE-79``, ``"611"``, and bare ``918`` → sorted unique list."""
    payload = _envelope(results=[_result(cwe=["CWE-79", "611", 918, "CWE-79"])])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings[0].cwe == [79, 611, 918]


def test_owasp_top10_lands_in_sidecar(artifacts_dir: Path) -> None:
    """``metadata.owasp`` strings flow into ``owasp_top10`` evidence."""
    payload = _envelope(results=[_result(owasp=["A03:2021 - Injection"])])
    parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["owasp_top10"] == ["A03:2021 - Injection"]


# ===========================================================================
# 6. Dedup + sort + sidecar
# ===========================================================================


def test_dedup_collapses_same_check_id_path_line(
    artifacts_dir: Path,
) -> None:
    """Same (check_id, path, start_line) → one finding."""
    r = _result(check_id="rule-A", path="src/a.py", start_line=10)
    payload = _envelope(results=[r, r.copy(), r.copy()])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert len(findings) == 1


def test_two_rules_at_same_line_stay_separate(artifacts_dir: Path) -> None:
    """Different check_ids at the same line are two distinct findings."""
    r1 = _result(check_id="rule-A", path="src/a.py", start_line=10)
    r2 = _result(check_id="rule-B", path="src/a.py", start_line=10)
    payload = _envelope(results=[r1, r2])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert len(findings) == 2


def test_dedup_distinguishes_same_start_line_different_end_line(
    artifacts_dir: Path,
) -> None:
    """Two findings of the same rule on the same start_line but different
    end_line MUST NOT collapse — they cover different AST node spans.

    Real-world shape: two semicolon-separated statements share a
    physical start_line but have distinct end_line spans; Semgrep
    emits one finding per AST node. A 3-tuple dedup key (without
    end_line) silently dropped one of them.
    """
    r1 = _result(
        check_id="python.lang.security.audit.dangerous-eval",
        path="src/foo.py",
        start_line=10,
        end_line=10,
    )
    r2 = _result(
        check_id="python.lang.security.audit.dangerous-eval",
        path="src/foo.py",
        start_line=10,
        end_line=12,
    )
    payload = _envelope(results=[r1, r2])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert len(findings) == 2
    sidecar = _read_sidecar(artifacts_dir)
    end_lines = sorted(rec["end_line"] for rec in sidecar)
    assert end_lines == [10, 12]


def test_dedup_collapses_identical_full_span(artifacts_dir: Path) -> None:
    """Same rule + path + start_line + end_line → one finding.

    Sister test to the 3-tuple regression: when ``end_line`` matches,
    the records are truly identical and must collapse (preserves the
    original dedup contract for genuine duplicates).
    """
    r = _result(
        check_id="python.lang.security.audit.dangerous-eval",
        path="src/foo.py",
        start_line=10,
        end_line=12,
    )
    payload = _envelope(results=[r, r.copy(), r.copy()])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert len(findings) == 1


def test_sort_is_severity_desc_then_check_id(artifacts_dir: Path) -> None:
    """Findings sort by severity desc, then check_id."""
    payload = _envelope(
        results=[
            _result(
                check_id="rule-A",
                severity="INFO",
                confidence=None,
                likelihood=None,
                impact=None,
            ),
            _result(check_id="rule-B", severity="ERROR", confidence="HIGH"),
            _result(
                check_id="rule-C",
                severity="WARNING",
                confidence="LOW",
                likelihood="LOW",
                impact="LOW",
            ),
        ]
    )
    parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    sidecar = _read_sidecar(artifacts_dir)
    severities = [r["severity"] for r in sidecar]
    assert severities == ["critical", "medium", "low"]


def test_sidecar_records_carry_tool_id_semgrep(
    artifacts_dir: Path,
) -> None:
    """Every sidecar record stamped with ``tool_id=semgrep``."""
    payload = _envelope(results=[_result()])
    parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["tool_id"] == "semgrep"


def test_sidecar_message_truncated_at_cap(artifacts_dir: Path) -> None:
    """Long messages are capped at the evidence byte cap."""
    huge = "x" * 8192
    payload = _envelope(results=[_result(message=huge)])
    parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["message"].endswith("...[truncated]")


# ===========================================================================
# 7. Failure modes — missing fields / scan errors / malformed JSON
# ===========================================================================


def test_missing_check_id_is_skipped(
    artifacts_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Result without ``check_id`` is dropped with a structured WARNING."""
    caplog.set_level(logging.WARNING)
    bad = _result()
    bad.pop("check_id")
    good = _result(check_id="rule-good")
    payload = _envelope(results=[bad, good])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert len(findings) == 1
    assert any("result_missing_field" in r.message for r in caplog.records)


def test_missing_path_is_skipped(
    artifacts_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Result without ``path`` is dropped with a structured WARNING."""
    caplog.set_level(logging.WARNING)
    bad = _result()
    bad.pop("path")
    payload = _envelope(results=[bad])
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings == []
    assert any("result_missing_field" in r.message for r in caplog.records)


def test_scan_errors_logged_but_not_a_finding(
    artifacts_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``errors[]`` triggers ``scan_errors`` log; never inflates findings."""
    caplog.set_level(logging.WARNING)
    payload = _envelope(
        results=[_result()],
        errors=[
            {"type": "MatchingError", "message": "rule failed"},
            {"type": "ParseError", "message": "could not parse"},
        ],
    )
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert len(findings) == 1
    assert any("scan_errors" in r.message for r in caplog.records)


def test_malformed_json_returns_empty(
    artifacts_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Garbage JSON returns ``[]`` after a structured WARNING."""
    caplog.set_level(logging.WARNING)
    findings = parse_semgrep_json(
        stdout=b"{garbage",
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings == []


def test_results_not_list_returns_empty(artifacts_dir: Path) -> None:
    """``results`` field absent / wrong type → ``[]``."""
    payload = {"version": "1.0.0", "results": {"oops": "dict"}}
    findings = parse_semgrep_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="semgrep",
    )
    assert findings == []
