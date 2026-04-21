"""Unit tests for :mod:`src.sandbox.parsers.ffuf_parser` (Backlog/dev1_md §4.5).

Each test pins exactly one contract documented in the parser:

* The three accepted shapes (ffuf single-object / feroxbuster JSONL /
  dirsearch single-object with hyphenated ``content-length``) all collapse
  to the same normalised ``(url, status)`` projection.
* Status-based confidence mapping (2xx/3xx → SUSPECTED, 401/403 → LIKELY,
  5xx → LIKELY, anything else → SUSPECTED).
* Records missing ``url`` or ``status`` are skipped (logged once).
* ``(url, status)`` is the dedup key — duplicate rows from
  ``-recursion`` collapse.
* The output ordering is deterministic (sort by ``(url, status)``).
* Malformed JSON is tolerated (returns ``[]``, no exception raised).
* The evidence sidecar is written to
  ``artifacts_dir / EVIDENCE_SIDECAR_NAME`` with one compact JSON record
  per emitted finding.
* Empty / whitespace stdout returns no findings (and no sidecar file).
* Per-tool OWASP WSTG hints differentiate path / parameter / vhost
  discovery (CWE-200 stays universal — CWE-200 is "Information Exposure").
* ``arjun`` parameter-discovery items collapse into the same projection.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, cast

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_SCORE,
    SENTINEL_CVSS_VECTOR,
    SENTINEL_UUID,
)
from src.sandbox.parsers.ffuf_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_ffuf_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ffuf_envelope(*results: dict[str, Any]) -> bytes:
    """Build an ffuf-style ``{"results": [...]}`` JSON envelope."""
    payload = {
        "commandline": "ffuf -u https://target/FUZZ -w /wordlists/common.txt",
        "config": {"verbose": False},
        "results": list(results),
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _feroxbuster_jsonl(*records: dict[str, Any]) -> bytes:
    """Build a feroxbuster JSONL stream of ``{"type": "response", ...}`` lines."""
    lines: list[str] = []
    for record in records:
        merged = {"type": "response", **record}
        lines.append(json.dumps(merged, sort_keys=True))
    return ("\n".join(lines)).encode("utf-8")


def _dirsearch_envelope(*results: dict[str, Any]) -> bytes:
    """Build a dirsearch-style envelope (uses ``content-length`` hyphenated)."""
    payload = {"info": {"version": "0.4.3"}, "results": list(results)}
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _read_sidecar(artifacts_dir: Path) -> list[dict[str, Any]]:
    """Return the evidence JSONL contents (empty if file is missing)."""
    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    if not sidecar.is_file():
        return []
    return [
        cast(dict[str, Any], json.loads(line))
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Empty / no-op inputs
# ---------------------------------------------------------------------------


def test_empty_results_envelope_yields_no_findings(tmp_path: Path) -> None:
    """An envelope with an empty ``results`` array yields zero findings."""
    findings = parse_ffuf_json(_ffuf_envelope(), b"", tmp_path, "ffuf_dir")
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_empty_stdout_yields_no_findings(tmp_path: Path) -> None:
    """``b""`` stdout never explodes and writes no sidecar."""
    findings = parse_ffuf_json(b"", b"", tmp_path, "ffuf_dir")
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_whitespace_only_stdout_yields_no_findings(tmp_path: Path) -> None:
    """Stdout that is whitespace-only is treated like an empty input."""
    findings = parse_ffuf_json(b"   \n\t  ", b"", tmp_path, "ffuf_dir")
    assert findings == []


# ---------------------------------------------------------------------------
# Happy-path: single record, status mapping
# ---------------------------------------------------------------------------


def test_single_200_record_produces_one_info_finding(tmp_path: Path) -> None:
    """A single 200 ffuf record emits one INFO finding with sentinel CVSS."""
    stdout = _ffuf_envelope(
        {
            "url": "https://target/admin",
            "status": 200,
            "length": 1234,
            "words": 64,
            "lines": 12,
            "content_type": "text/html",
        }
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, FindingDTO)
    assert finding.category is FindingCategory.INFO
    assert finding.cwe == [200]
    assert finding.owasp_wstg == ["WSTG-CONFIG-04", "WSTG-CONFIG-06"]
    assert finding.confidence is ConfidenceLevel.SUSPECTED
    assert finding.cvss_v3_vector == SENTINEL_CVSS_VECTOR
    assert finding.cvss_v3_score == SENTINEL_CVSS_SCORE
    assert finding.id == SENTINEL_UUID
    assert finding.tenant_id == SENTINEL_UUID
    assert finding.status is FindingStatus.NEW
    assert finding.ssvc_decision is SSVCDecision.TRACK


def test_redirect_301_yields_suspected_confidence(tmp_path: Path) -> None:
    """3xx redirects are catalogued as SUSPECTED INFO findings."""
    stdout = _ffuf_envelope(
        {
            "url": "https://target/old",
            "status": 301,
            "length": 0,
            "redirectlocation": "https://target/new",
        }
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


@pytest.mark.parametrize("status", [401, 403])
def test_auth_walls_promote_to_likely(tmp_path: Path, status: int) -> None:
    """401 and 403 are upgraded to LIKELY confidence (auth-wall signal)."""
    stdout = _ffuf_envelope(
        {"url": f"https://target/secret-{status}", "status": status, "length": 0}
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1
    assert findings[0].confidence is ConfidenceLevel.LIKELY


@pytest.mark.parametrize("status", [500, 502, 503])
def test_server_errors_promote_to_likely(tmp_path: Path, status: int) -> None:
    """5xx server errors during discovery promote to LIKELY confidence."""
    stdout = _ffuf_envelope({"url": f"https://target/buggy-{status}", "status": status})

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_mixed_status_codes_each_emit_one_finding(tmp_path: Path) -> None:
    """ffuf shape with mixed status codes emits one finding per record.

    Status -> confidence mapping (per ``_confidence_for_status``):
    * 200 / 301 / 418 -> SUSPECTED (no special promotion).
    * 401 / 403 / 5xx -> LIKELY.
    """
    stdout = _ffuf_envelope(
        {"url": "https://target/a", "status": 200},
        {"url": "https://target/b", "status": 301},
        {"url": "https://target/c", "status": 401},
        {"url": "https://target/d", "status": 500},
        {"url": "https://target/e", "status": 418},
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 5
    confidence_levels = [f.confidence for f in findings]
    # Sorted by (url, status) — alphabetical /a, /b, /c, /d, /e.
    assert confidence_levels == [
        ConfidenceLevel.SUSPECTED,  # /a 200
        ConfidenceLevel.SUSPECTED,  # /b 301
        ConfidenceLevel.LIKELY,  # /c 401
        ConfidenceLevel.LIKELY,  # /d 500
        ConfidenceLevel.SUSPECTED,  # /e 418 (teapot — no special promotion)
    ]


# ---------------------------------------------------------------------------
# Cross-shape compatibility
# ---------------------------------------------------------------------------


def test_feroxbuster_jsonl_shape_is_handled(tmp_path: Path) -> None:
    """Feroxbuster's JSONL stream collapses to the same projection as ffuf."""
    stdout = _feroxbuster_jsonl(
        {"url": "https://target/api", "status": 200, "content_length": 4096},
        {"url": "https://target/admin", "status": 403, "content_length": 0},
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "feroxbuster")

    assert len(findings) == 2
    sidecar = _read_sidecar(tmp_path)
    assert {row["url"] for row in sidecar} == {
        "https://target/api",
        "https://target/admin",
    }
    assert all(row["tool_id"] == "feroxbuster" for row in sidecar)


def test_feroxbuster_jsonl_drops_non_response_records(tmp_path: Path) -> None:
    """Feroxbuster mixes ``configuration`` / ``statistics`` records with responses."""
    stdout = (
        json.dumps({"type": "configuration", "version": "2.10.4"})
        + "\n"
        + json.dumps({"type": "scan", "url": "https://target/"})
        + "\n"
        + json.dumps(
            {
                "type": "response",
                "url": "https://target/api",
                "status": 200,
                "content_length": 100,
            }
        )
        + "\n"
        + json.dumps({"type": "statistics", "responses": 1, "errors": 0})
    ).encode("utf-8")

    findings = parse_ffuf_json(stdout, b"", tmp_path, "feroxbuster")

    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["url"] == "https://target/api"
    assert sidecar[0]["status"] == 200


def test_dirsearch_hyphenated_content_length_is_normalised(tmp_path: Path) -> None:
    """Dirsearch records use ``content-length`` (hyphenated) — must still parse."""
    stdout = _dirsearch_envelope(
        {
            "url": "https://target/login.php",
            "status": 200,
            "content-length": 8192,
            "content-type": "text/html; charset=UTF-8",
        }
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "dirsearch")

    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["length"] == 8192
    assert sidecar[0]["content_type"] == "text/html; charset=UTF-8"


def test_top_level_list_is_treated_as_results(tmp_path: Path) -> None:
    """A top-level JSON list is accepted as a flat result array."""
    stdout = json.dumps(
        [
            {"url": "https://target/a", "status": 200},
            {"url": "https://target/b", "status": 200},
        ],
        sort_keys=True,
    ).encode("utf-8")

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 2


def test_single_record_top_level_object_is_handled(tmp_path: Path) -> None:
    """A bare ``{"url": ..., "status": ...}`` object is treated as one record."""
    stdout = json.dumps(
        {"url": "https://target/lone", "status": 200, "length": 1}, sort_keys=True
    ).encode("utf-8")

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Dedup + ordering
# ---------------------------------------------------------------------------


def test_dedup_collapses_repeated_url_status_pairs(tmp_path: Path) -> None:
    """``(url, status)`` is the dedup key — repeated rows collapse to one."""
    stdout = _ffuf_envelope(
        {"url": "https://target/api", "status": 200, "length": 100},
        {"url": "https://target/api", "status": 200, "length": 200},
        {"url": "https://target/api", "status": 200, "length": 300},
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    # First wins: subsequent dup payloads are dropped without altering the
    # evidence record stored for the canonical key.
    assert sidecar[0]["length"] == 100


def test_same_url_different_status_are_distinct_findings(tmp_path: Path) -> None:
    """``(url, status)`` is the WHOLE key — distinct statuses do NOT collapse."""
    stdout = _ffuf_envelope(
        {"url": "https://target/api", "status": 200},
        {"url": "https://target/api", "status": 403},
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 2


def test_output_is_sorted_by_url_then_status(tmp_path: Path) -> None:
    """Findings are emitted in deterministic ``(url, status)`` order."""
    stdout = _ffuf_envelope(
        {"url": "https://target/zeta", "status": 200},
        {"url": "https://target/alpha", "status": 403},
        {"url": "https://target/alpha", "status": 200},
        {"url": "https://target/middle", "status": 500},
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")
    sidecar = _read_sidecar(tmp_path)

    assert len(findings) == 4
    # Sidecar mirrors the FindingDTO order — both sort by (url, status).
    assert [(row["url"], row["status"]) for row in sidecar] == [
        ("https://target/alpha", 200),
        ("https://target/alpha", 403),
        ("https://target/middle", 500),
        ("https://target/zeta", 200),
    ]


# ---------------------------------------------------------------------------
# Robustness: malformed / partial input
# ---------------------------------------------------------------------------


def test_records_missing_url_are_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Records without a ``url`` are dropped with a structured warning."""
    stdout = _ffuf_envelope(
        {"status": 200, "length": 100},
        {"url": "https://target/ok", "status": 200},
    )

    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers.ffuf_parser"):
        findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1
    # At least one structured warning about the incomplete record.
    assert any(
        "ffuf_parser_skip_incomplete_record" == getattr(rec, "event", "")
        or "ffuf_parser.skip_incomplete_record" in rec.getMessage()
        for rec in caplog.records
    )


def test_records_missing_status_are_skipped(tmp_path: Path) -> None:
    """Records without a numeric ``status`` are dropped (no FindingDTO)."""
    stdout = _ffuf_envelope(
        {"url": "https://target/no-status"},
        {"url": "https://target/bad-status", "status": "not-a-number"},
        {"url": "https://target/ok", "status": 200},
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1


def test_malformed_json_returns_empty_without_raising(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Malformed JSON is logged + dropped (parser is fail-soft by contract)."""
    stdout = b"this is not even close to JSON {{ broken"

    with caplog.at_level(logging.WARNING):
        findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_unsupported_top_level_type_returns_empty(tmp_path: Path) -> None:
    """A top-level JSON scalar is rejected without raising."""
    stdout = json.dumps("just a string").encode("utf-8")
    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")
    assert findings == []


def test_unrecognised_envelope_returns_empty(tmp_path: Path) -> None:
    """An object without ``results`` / ``url`` / ``type`` is dropped."""
    stdout = json.dumps({"meta": {"version": "0.0"}, "config": {}}).encode("utf-8")
    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")
    assert findings == []


def test_non_dict_records_are_silently_dropped(tmp_path: Path) -> None:
    """Records that are not dicts (lists, scalars) are skipped without raising."""
    payload = {
        "results": [
            "not-a-record",
            123,
            ["url", 200],
            {"url": "https://target/ok", "status": 200},
        ],
    }
    stdout = json.dumps(payload).encode("utf-8")

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1


def test_boolean_status_is_not_misinterpreted_as_int(tmp_path: Path) -> None:
    """``status: True`` must not be coerced to 1 — record is dropped instead."""
    stdout = _ffuf_envelope({"url": "https://target/x", "status": True})
    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")
    assert findings == []


# ---------------------------------------------------------------------------
# Per-tool semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool_id", "expected_owasp"),
    [
        ("ffuf_dir", ["WSTG-CONFIG-04", "WSTG-CONFIG-06"]),
        ("feroxbuster", ["WSTG-CONFIG-04", "WSTG-CONFIG-06"]),
        ("dirsearch", ["WSTG-CONFIG-04", "WSTG-CONFIG-06"]),
        ("kiterunner", ["WSTG-CONFIG-04", "WSTG-CONFIG-06"]),
        ("ffuf_param", ["WSTG-INPV-04"]),
        ("arjun", ["WSTG-INPV-04"]),
        ("paramspider", ["WSTG-INPV-04"]),
        ("wfuzz", ["WSTG-INPV-04"]),
        ("ffuf_vhost", ["WSTG-INFO-04"]),
    ],
)
def test_owasp_wstg_hints_per_tool_id(
    tmp_path: Path, tool_id: str, expected_owasp: list[str]
) -> None:
    """Each tool_id receives its declared OWASP WSTG hint set."""
    stdout = _ffuf_envelope({"url": "https://target/x", "status": 200})

    findings = parse_ffuf_json(stdout, b"", tmp_path, tool_id)

    assert len(findings) == 1
    assert findings[0].owasp_wstg == expected_owasp
    assert findings[0].cwe == [200]


def test_unknown_tool_id_falls_back_to_config_04_hint(tmp_path: Path) -> None:
    """An unmapped tool_id receives the fallback ``WSTG-CONFIG-04`` only."""
    stdout = _ffuf_envelope({"url": "https://target/x", "status": 200})

    findings = parse_ffuf_json(stdout, b"", tmp_path, "future_unknown_tool")

    assert len(findings) == 1
    assert findings[0].owasp_wstg == ["WSTG-CONFIG-04"]


# ---------------------------------------------------------------------------
# arjun parameter-discovery shape
# ---------------------------------------------------------------------------


def test_arjun_items_envelope_is_projected(tmp_path: Path) -> None:
    """Real arjun ``-oJ`` output (``{url: [param_dicts]}``) collapses to status=200.

    Pins the contract that the arjun adapter consumes the production
    ``arjun -oJ`` shape (top-level dict keyed by URL with a list of
    parameter dicts), NOT the synthetic ``{"items": [...]}`` envelope
    that earlier iterations of this parser used as a stand-in.
    """
    payload = {
        "https://target/api/users": [
            {"name": "user_id", "method": "GET", "type": "Form"},
            {"name": "page", "method": "GET", "type": "Form"},
        ]
    }
    stdout = json.dumps(payload).encode("utf-8")

    findings = parse_ffuf_json(stdout, b"", tmp_path, "arjun")

    # Both parameters share the same (url, status=200) dedup key — collapse to 1.
    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["url"] == "https://target/api/users"
    assert sidecar[0]["status"] == 200
    # First record wins under the dedup key (status=200 collapses both).
    assert sidecar[0]["parameter_name"] == "user_id"
    assert sidecar[0]["method"] == "GET"


def test_arjun_multiple_urls_each_emit_one_finding(tmp_path: Path) -> None:
    """Distinct URL keys in arjun output produce distinct findings."""
    payload = {
        "https://target/api/users": [
            {"name": "user_id", "method": "GET"},
        ],
        "https://target/api/posts": [
            {"name": "post_id", "method": "POST"},
        ],
    }
    stdout = json.dumps(payload).encode("utf-8")

    findings = parse_ffuf_json(stdout, b"", tmp_path, "arjun")

    assert len(findings) == 2
    sidecar = _read_sidecar(tmp_path)
    assert {row["url"] for row in sidecar} == {
        "https://target/api/users",
        "https://target/api/posts",
    }
    methods_by_url = {row["url"]: row["method"] for row in sidecar}
    assert methods_by_url["https://target/api/users"] == "GET"
    assert methods_by_url["https://target/api/posts"] == "POST"


def test_arjun_items_with_invalid_records_are_dropped(tmp_path: Path) -> None:
    """arjun records with invalid URL keys, non-list values, or non-dict params
    are silently dropped.  Only well-formed (URL → list[dict]) entries survive.
    """
    payload = {
        "https://target/api": [
            {"name": "ok", "method": "GET"},
            "not-a-dict",  # skipped — non-dict param record
            {"name": "second", "method": "POST"},
        ],
        "https://target/skip": "not-a-list",  # skipped — value is not a list
        "not-a-url-key": [{"name": "x", "method": "GET"}],  # skipped — bad key
    }
    stdout = json.dumps(payload).encode("utf-8")

    findings = parse_ffuf_json(stdout, b"", tmp_path, "arjun")

    # Two valid params for the same URL collapse via dedup → 1 finding.
    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["url"] == "https://target/api"


# ---------------------------------------------------------------------------
# Evidence sidecar
# ---------------------------------------------------------------------------


def test_evidence_sidecar_is_written_with_one_record_per_finding(
    tmp_path: Path,
) -> None:
    """The sidecar has exactly one JSON line per emitted FindingDTO."""
    stdout = _ffuf_envelope(
        {"url": "https://target/a", "status": 200, "length": 100},
        {"url": "https://target/b", "status": 200, "length": 200},
    )

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")
    sidecar_lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()

    assert len(findings) == 2
    assert len(sidecar_lines) == 2
    parsed = [json.loads(line) for line in sidecar_lines]
    assert all(row["tool_id"] == "ffuf_dir" for row in parsed)
    assert {row["url"] for row in parsed} == {
        "https://target/a",
        "https://target/b",
    }


def test_evidence_sidecar_drops_empty_optional_fields(tmp_path: Path) -> None:
    """The sidecar JSON omits keys whose value is None / empty string."""
    stdout = _ffuf_envelope({"url": "https://target/x", "status": 200})

    parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")
    sidecar = _read_sidecar(tmp_path)

    assert len(sidecar) == 1
    record = sidecar[0]
    # Only the populated keys survive.
    assert "url" in record
    assert "status" in record
    assert "tool_id" in record
    assert "length" not in record
    assert "words" not in record
    assert "lines" not in record
    assert "content_type" not in record
    assert "redirect_location" not in record
    assert "parameter_name" not in record
    assert "method" not in record


def test_sidecar_failure_does_not_break_parser(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An OSError when writing the sidecar is logged but does not raise."""
    # Simulate an unwritable artifacts_dir by using a path whose parent is
    # actually a regular file.  ``mkdir`` then fails with FileExistsError /
    # NotADirectoryError, the parser swallows it, returns the findings.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    artifacts_dir = blocker / "artifacts"

    stdout = _ffuf_envelope({"url": "https://target/x", "status": 200})

    with caplog.at_level(logging.WARNING):
        findings = parse_ffuf_json(stdout, b"", artifacts_dir, "ffuf_dir")

    assert len(findings) == 1
    assert any(
        "ffuf_parser_evidence_sidecar_write_failed" == getattr(rec, "event", "")
        or "ffuf_parser.evidence_sidecar_write_failed" in rec.getMessage()
        for rec in caplog.records
    )


# ---------------------------------------------------------------------------
# Stress: large recursion run + cap behaviour
# ---------------------------------------------------------------------------


def test_thousand_unique_records_emit_thousand_findings(tmp_path: Path) -> None:
    """A 1k-record payload (all unique) emits 1000 findings without truncation."""
    records = [
        {"url": f"https://target/path-{i:04d}", "status": 200, "length": i}
        for i in range(1000)
    ]
    stdout = _ffuf_envelope(*records)

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1000


def test_dedup_under_thousand_repeats_collapses_to_one(tmp_path: Path) -> None:
    """A 1k-record payload that's all the same row collapses to ONE finding."""
    records = [{"url": "https://target/spam", "status": 200} for _ in range(1000)]
    stdout = _ffuf_envelope(*records)

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 1


def test_cap_on_max_findings_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When more than ``_MAX_FINDINGS`` unique records are emitted, the parser
    truncates and logs ``ffuf_parser.cap_reached`` exactly once."""
    from src.sandbox.parsers import ffuf_parser as ffuf_parser_mod

    monkeypatch.setattr(ffuf_parser_mod, "_MAX_FINDINGS", 5)
    records = [{"url": f"https://target/p-{i:02d}", "status": 200} for i in range(20)]
    stdout = _ffuf_envelope(*records)

    with caplog.at_level(logging.WARNING):
        findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    assert len(findings) == 5
    assert any(
        "ffuf_parser_cap_reached" == getattr(rec, "event", "")
        or "ffuf_parser.cap_reached" in rec.getMessage()
        for rec in caplog.records
    )


def test_jsonl_detector_rejects_lines_not_starting_with_brace(
    tmp_path: Path,
) -> None:
    """A multi-line payload whose lines don't all start with ``{`` is parsed as
    a single document (or fails cleanly), NOT as JSONL."""
    # Two non-empty lines, but the first is an array. The detector rejects
    # this immediately because the first line does not start with ``{``.
    stdout = b"[1, 2, 3]\nplain text trailing line\n"

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    # No envelope match -> empty.
    assert findings == []


def test_jsonl_detector_rejects_when_first_line_is_malformed(
    tmp_path: Path,
) -> None:
    """If the first ``{``-prefixed line is not parseable as JSON, the detector
    falls through and the whole blob is treated as a single document."""
    # Lines look like JSONL (start with ``{``) but the first is broken.
    stdout = b'{not-valid-json}\n{"url": "https://target/", "status": 200}\n'

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    # Detector returned False -> safe_load_json fails -> empty list.
    assert findings == []


def test_jsonl_detector_rejects_when_first_line_is_a_list(
    tmp_path: Path,
) -> None:
    """A line-prefixed list (``[ ... ]``) on the first line still rejects JSONL
    even if it parses, because the parsed value is not a dict."""
    stdout = b"{}\n[1, 2, 3]\n"

    findings = parse_ffuf_json(stdout, b"", tmp_path, "ffuf_dir")

    # Detector should bail on the second line (not starting with ``{``)
    # OR (depending on order) on the parsed list.  Either way, no findings.
    assert findings == []
