"""Unit tests for :mod:`src.sandbox.parsers.katana_parser` (Backlog/dev1_md §4.6).

Each test pins exactly one contract documented in the parser:

* Native katana JSONL records collapse to ``(endpoint, method)``-keyed
  ``FindingDTO`` instances with ``FindingCategory.INFO`` semantics and
  CWE-200 / WSTG-INFO-06 hints.
* Records without an ``endpoint`` are skipped (logged once); records
  without a ``method`` default to ``"GET"``.
* ``(endpoint, method)`` is the dedup key — running katana with
  ``-rl 50`` legitimately re-discovers the same path multiple times.
* Dedup + output ordering is deterministic (sort by ``(endpoint, method)``).
* Malformed JSONL lines are tolerated — the malformed line is logged
  once, the rest of the stream still parses.
* Non-dict JSONL payloads (lists, scalars) are silently skipped (per
  ``safe_load_jsonl`` contract) — defence in-depth against tools that
  occasionally emit comments / progress lines mixed into JSONL streams.
* Empty / whitespace-only stdout returns ``[]`` and writes no sidecar.
* The ``katana_findings.jsonl`` sidecar carries one compact record per
  emitted finding (sorted, with the source ``tool_id`` stamped on each
  record so the downstream evidence pipeline can route per-tool).
* The parser hard-caps at 5 000 records — defence in-depth against a
  runaway crawl against a wildcard CDN.
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
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_SCORE,
    SENTINEL_CVSS_VECTOR,
    SENTINEL_UUID,
)
from src.sandbox.parsers.katana_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_gau_jsonl,
    parse_gospider_jsonl,
    parse_katana_jsonl,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _katana_record(
    endpoint: str,
    *,
    method: str = "GET",
    status_code: int | None = 200,
    content_length: int | None = 1234,
    content_type: str | None = "text/html",
    source: str | None = "form",
) -> dict[str, Any]:
    """Build a single katana JSONL record matching the documented shape."""
    request: dict[str, Any] = {"endpoint": endpoint, "method": method}
    if source is not None:
        request["tag"] = source
    response: dict[str, Any] = {}
    if status_code is not None:
        response["status_code"] = status_code
    if content_length is not None:
        response["content_length"] = content_length
    if content_type is not None:
        response["content_type"] = content_type
    return {
        "timestamp": "2026-04-18T10:00:00Z",
        "request": request,
        "response": response,
    }


def _katana_jsonl(*records: dict[str, Any]) -> bytes:
    """Build a katana-style JSONL stream from the supplied records."""
    return ("\n".join(json.dumps(record, sort_keys=True) for record in records)).encode(
        "utf-8"
    )


def _read_sidecar(artifacts_dir: Path) -> list[dict[str, Any]]:
    """Return the evidence JSONL contents (empty if the file is missing)."""
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


def test_empty_stdout_yields_no_findings(tmp_path: Path) -> None:
    """``b""`` stdout never explodes and writes no sidecar."""
    findings = parse_katana_jsonl(b"", b"", tmp_path, "katana")
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_whitespace_only_stdout_yields_no_findings(tmp_path: Path) -> None:
    """Stdout that is whitespace-only is treated like an empty input."""
    findings = parse_katana_jsonl(b"   \n\t  \n  ", b"", tmp_path, "katana")
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


# ---------------------------------------------------------------------------
# Happy path: single record
# ---------------------------------------------------------------------------


def test_single_record_emits_info_finding_with_correct_metadata(
    tmp_path: Path,
) -> None:
    """A single katana record produces one INFO/CWE-200/WSTG-INFO-06 finding."""
    raw = _katana_jsonl(_katana_record("https://target.example/api/v1/users"))

    findings = parse_katana_jsonl(raw, b"", tmp_path, "katana")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == FindingCategory.INFO
    assert finding.cwe == [200]
    assert "WSTG-INFO-06" in finding.owasp_wstg
    assert "WSTG-INFO-07" in finding.owasp_wstg
    assert finding.confidence == ConfidenceLevel.SUSPECTED
    assert finding.cvss_v3_vector == SENTINEL_CVSS_VECTOR
    assert finding.cvss_v3_score == SENTINEL_CVSS_SCORE
    assert finding.ssvc_decision == SSVCDecision.TRACK
    # Identity fields are sentinel placeholders — the normaliser overrides them.
    assert finding.id == SENTINEL_UUID
    assert finding.tenant_id == SENTINEL_UUID
    assert finding.scan_id == SENTINEL_UUID
    assert finding.asset_id == SENTINEL_UUID
    assert finding.tool_run_id == SENTINEL_UUID


def test_single_record_writes_sidecar_with_compact_evidence(tmp_path: Path) -> None:
    """One emitted finding produces one sidecar record carrying tool_id."""
    raw = _katana_jsonl(
        _katana_record(
            "https://target.example/api",
            method="POST",
            status_code=201,
            content_length=42,
            content_type="application/json",
            source="form",
        )
    )

    parse_katana_jsonl(raw, b"", tmp_path, "katana")

    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    record = sidecar[0]
    assert record["tool_id"] == "katana"
    assert record["endpoint"] == "https://target.example/api"
    assert record["method"] == "POST"
    assert record["status_code"] == 201
    assert record["content_length"] == 42
    assert record["content_type"] == "application/json"
    assert record["source"] == "form"


# ---------------------------------------------------------------------------
# Dedup + ordering
# ---------------------------------------------------------------------------


def test_duplicate_endpoint_method_pairs_are_collapsed(tmp_path: Path) -> None:
    """Same ``(endpoint, method)`` only emits a single finding regardless of count."""
    raw = _katana_jsonl(
        _katana_record("https://target/users", method="GET"),
        _katana_record("https://target/users", method="GET"),
        _katana_record("https://target/users", method="GET"),
    )

    findings = parse_katana_jsonl(raw, b"", tmp_path, "katana")

    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1


def test_same_endpoint_different_method_are_distinct(tmp_path: Path) -> None:
    """``GET /users`` and ``POST /users`` are two distinct findings."""
    raw = _katana_jsonl(
        _katana_record("https://target/users", method="GET"),
        _katana_record("https://target/users", method="POST"),
        _katana_record("https://target/users", method="DELETE"),
    )

    findings = parse_katana_jsonl(raw, b"", tmp_path, "katana")

    assert len(findings) == 3


def test_findings_sorted_by_endpoint_then_method(tmp_path: Path) -> None:
    """Output ordering is deterministic regardless of input ordering."""
    raw = _katana_jsonl(
        _katana_record("https://target/zebra", method="GET"),
        _katana_record("https://target/alpha", method="POST"),
        _katana_record("https://target/alpha", method="GET"),
        _katana_record("https://target/middle", method="GET"),
    )

    parse_katana_jsonl(raw, b"", tmp_path, "katana")

    sidecar = _read_sidecar(tmp_path)
    keys = [(rec["endpoint"], rec["method"]) for rec in sidecar]
    assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# Defaulting / missing fields
# ---------------------------------------------------------------------------


def test_missing_method_defaults_to_get(tmp_path: Path) -> None:
    """A record with ``request.method`` absent is treated as a GET."""
    raw = _katana_jsonl(
        {
            "request": {"endpoint": "https://target/search"},
            "response": {"status_code": 200},
        }
    )

    parse_katana_jsonl(raw, b"", tmp_path, "katana")

    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    assert sidecar[0]["method"] == "GET"


def test_method_is_normalised_to_uppercase(tmp_path: Path) -> None:
    """Lowercase / mixed-case methods are normalised before dedup."""
    raw = _katana_jsonl(
        _katana_record("https://target/users", method="get"),
        _katana_record("https://target/users", method="GET"),
        _katana_record("https://target/users", method="GeT"),
    )

    findings = parse_katana_jsonl(raw, b"", tmp_path, "katana")

    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["method"] == "GET"


def test_missing_endpoint_is_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Records with no ``request.endpoint`` are skipped silently."""
    caplog.set_level(logging.WARNING)
    raw = _katana_jsonl(
        {"request": {"method": "GET"}, "response": {"status_code": 200}},
        _katana_record("https://target/keep"),
    )

    findings = parse_katana_jsonl(raw, b"", tmp_path, "katana")

    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["endpoint"] == "https://target/keep"


# ---------------------------------------------------------------------------
# Robustness: malformed input
# ---------------------------------------------------------------------------


def test_malformed_jsonl_line_is_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A malformed JSON line does not abort parsing of the rest of the stream."""
    caplog.set_level(logging.WARNING)
    good_record = json.dumps(_katana_record("https://target/ok"), sort_keys=True)
    raw = (good_record + "\n{not json at all\n" + good_record + "\n").encode("utf-8")

    findings = parse_katana_jsonl(raw, b"", tmp_path, "katana")

    assert len(findings) == 1  # both good records collapse on dedup
    assert any("parsers.jsonl.malformed" in record.message for record in caplog.records)


def test_non_dict_jsonl_payload_is_skipped(tmp_path: Path) -> None:
    """A JSONL payload that is a list / scalar (not dict) is silently skipped."""
    good_record = json.dumps(_katana_record("https://target/ok"), sort_keys=True)
    raw = (good_record + '\n[1,2,3]\n42\n"naked string"\n' + good_record + "\n").encode(
        "utf-8"
    )

    findings = parse_katana_jsonl(raw, b"", tmp_path, "katana")

    assert len(findings) == 1


def test_request_or_response_not_dict_is_skipped(tmp_path: Path) -> None:
    """Records with non-dict ``request``/``response`` are skipped."""
    raw = _katana_jsonl(
        {"request": "not-a-dict", "response": {}},
        {"request": {"endpoint": "https://target/x"}, "response": "not-a-dict"},
        _katana_record("https://target/keep"),
    )

    findings = parse_katana_jsonl(raw, b"", tmp_path, "katana")

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Sidecar persistence semantics
# ---------------------------------------------------------------------------


def test_sidecar_contains_one_record_per_finding(tmp_path: Path) -> None:
    """Sidecar JSONL has one line per emitted finding (post-dedup)."""
    raw = _katana_jsonl(
        _katana_record("https://target/a"),
        _katana_record("https://target/b"),
        _katana_record("https://target/a"),  # duplicate
        _katana_record("https://target/c"),
    )

    parse_katana_jsonl(raw, b"", tmp_path, "katana")

    sidecar = _read_sidecar(tmp_path)
    assert {record["endpoint"] for record in sidecar} == {
        "https://target/a",
        "https://target/b",
        "https://target/c",
    }


def test_sidecar_records_are_compact_no_empty_fields(tmp_path: Path) -> None:
    """Sidecar records omit None / empty fields to keep evidence small."""
    raw = _katana_jsonl(
        _katana_record(
            "https://target/x",
            method="GET",
            status_code=None,
            content_length=None,
            content_type=None,
            source=None,
        )
    )

    parse_katana_jsonl(raw, b"", tmp_path, "katana")

    sidecar = _read_sidecar(tmp_path)
    record = sidecar[0]
    assert "status_code" not in record
    assert "content_length" not in record
    assert "content_type" not in record
    assert "source" not in record
    assert record["tool_id"] == "katana"
    assert record["endpoint"] == "https://target/x"


def test_sidecar_write_failure_is_swallowed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An OSError while persisting the sidecar is logged but not raised."""
    caplog.set_level(logging.WARNING)

    real_mkdir = Path.mkdir

    def boom_mkdir(self: Path, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        if self == tmp_path / "broken":
            raise PermissionError("nope")
        real_mkdir(self, parents=True, exist_ok=True)

    monkeypatch.setattr(Path, "mkdir", boom_mkdir)

    raw = _katana_jsonl(_katana_record("https://target/x"))
    findings = parse_katana_jsonl(raw, b"", tmp_path / "broken", "katana")

    assert len(findings) == 1
    assert any(
        "katana_parser.evidence_sidecar_write_failed" in record.message
        for record in caplog.records
    )


# ---------------------------------------------------------------------------
# Hard cap
# ---------------------------------------------------------------------------


def test_runaway_crawl_is_capped_at_5000_records(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Inputs above the 5 000 record cap stop processing and emit a WARNING."""
    caplog.set_level(logging.WARNING)
    records = [_katana_record(f"https://target/page-{i}") for i in range(5_500)]
    raw = _katana_jsonl(*records)

    findings = parse_katana_jsonl(raw, b"", tmp_path, "katana")

    assert len(findings) == 5_000
    assert any(
        "katana_parser.cap_reached" in record.message for record in caplog.records
    )


# ---------------------------------------------------------------------------
# Cross-tool coverage — exercise the gospider / gau public entry points
# from the katana test module so the module-level coverage gate (≥90 %
# on ``katana_parser.py``) does not depend on running the sister test
# suites. Each test pins exactly one normaliser-shape contract.
# ---------------------------------------------------------------------------


def _gospider_jsonl(*records: dict[str, Any]) -> bytes:
    """Build a gospider-style JSONL stream from the supplied records."""
    return ("\n".join(json.dumps(record, sort_keys=True) for record in records)).encode(
        "utf-8"
    )


def _gau_jsonl(*records: dict[str, Any]) -> bytes:
    """Build a gau-style JSONL stream from the supplied records."""
    return ("\n".join(json.dumps(record, sort_keys=True) for record in records)).encode(
        "utf-8"
    )


def test_parse_gospider_jsonl_normalises_output_and_string_stat(
    tmp_path: Path,
) -> None:
    """A gospider record collapses onto the canonical FindingDTO shape.

    Pins the public symbol path through ``parse_gospider_jsonl`` →
    ``_parse_jsonl_common`` → ``_iter_gospider_records`` so the module
    coverage gate (≥90 %) does not depend on the gospider test module.
    """
    raw = _gospider_jsonl(
        {
            "output": "https://target.example/api/users",
            "url": "https://target.example",
            "source": "scan",
            "type": "url",
            "stat": "200",
            "length": 4321,
        }
    )

    findings = parse_gospider_jsonl(raw, b"", tmp_path, "gospider")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == FindingCategory.INFO
    assert finding.cwe == [200]
    assert finding.confidence == ConfidenceLevel.SUSPECTED

    sidecar = list(_read_sidecar(tmp_path))
    assert len(sidecar) == 1
    record = sidecar[0]
    assert record["tool_id"] == "gospider"
    assert record["endpoint"] == "https://target.example/api/users"
    assert record["method"] == "GET"
    assert record["status_code"] == 200
    assert record["content_length"] == 4321
    assert record["source"] == "scan"


def test_parse_gospider_jsonl_skips_record_without_output_or_url(
    tmp_path: Path,
) -> None:
    """A gospider record with no URL field at all is silently dropped."""
    raw = _gospider_jsonl(
        {"source": "scan", "type": "url", "stat": "200"},
        {"output": "https://target/keep", "stat": "200"},
    )

    findings = parse_gospider_jsonl(raw, b"", tmp_path, "gospider")

    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["endpoint"] == "https://target/keep"


def test_parse_gospider_jsonl_drops_non_numeric_stat_string(
    tmp_path: Path,
) -> None:
    """A non-numeric ``stat`` string degrades to no ``status_code``.

    Exercises the ``_string_field(stat).isdigit()`` fall-back branch.
    """
    raw = _gospider_jsonl(
        {"output": "https://target/x", "stat": "error", "source": "scan"}
    )

    parse_gospider_jsonl(raw, b"", tmp_path, "gospider")

    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    assert "status_code" not in sidecar[0]


def test_parse_gau_jsonl_minimal_url_record_yields_info_finding(
    tmp_path: Path,
) -> None:
    """A bare ``{"url": "..."}`` gau record produces one INFO finding.

    Pins the public symbol path through ``parse_gau_jsonl`` →
    ``_parse_jsonl_common`` → ``_iter_gau_records`` so the module
    coverage gate (≥90 %) does not depend on the gau test module.
    """
    raw = _gau_jsonl({"url": "https://target.example/admin"})

    findings = parse_gau_jsonl(raw, b"", tmp_path, "gau")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == FindingCategory.INFO
    assert finding.cwe == [200]

    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    record = sidecar[0]
    assert record["tool_id"] == "gau"
    assert record["endpoint"] == "https://target.example/admin"
    assert record["method"] == "GET"
    assert record["source"] == "wayback"


def test_parse_gau_jsonl_skips_record_without_url(tmp_path: Path) -> None:
    """A gau record with neither ``url`` nor ``endpoint`` is silently dropped."""
    raw = _gau_jsonl(
        {"status_code": 200},
        {"url": "https://target/keep"},
    )

    findings = parse_gau_jsonl(raw, b"", tmp_path, "gau")

    assert len(findings) == 1


def test_parse_gau_jsonl_preserves_zero_content_length_over_fallback_length(
    tmp_path: Path,
) -> None:
    """LOW-3 regression: ``content_length=0`` must survive the fall-back chain.

    The naive ``_int_field(record, "content_length") or _int_field(record,
    "length")`` chain drops a legit ``0`` (HEAD / 204 / 304 responses) and
    falls through to ``length=99``. The ``_first_int`` helper resolves
    "first non-``None``" instead of "first truthy" and preserves the ``0``.

    This test pins the contract: ``content_length=0`` AND ``length=99`` →
    sidecar carries ``content_length=0`` (the ``0`` is filtered out of the
    compact JSON because it falls under the empty/zero filter, but the
    important part is that ``99`` does NOT show up).
    """
    raw = _gau_jsonl(
        {
            "url": "https://target/empty-204",
            "content_length": 0,
            "length": 99,
        }
    )

    parse_gau_jsonl(raw, b"", tmp_path, "gau")

    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    record = sidecar[0]
    # The compact evidence builder filters out ``0`` / ``None`` values to
    # keep the sidecar tight, so the ``content_length`` key is *absent*.
    # The critical regression assertion is that the fallback ``99`` did
    # NOT silently take its place — that would be the LOW-3 bug.
    assert record.get("content_length") != 99, (
        "fallback length=99 must not shadow the legit content_length=0 — "
        "see LOW-3 in ARG-013 reviewer findings"
    )


def test_parse_gau_jsonl_preserves_first_non_zero_length_when_content_length_missing(
    tmp_path: Path,
) -> None:
    """LOW-3 sibling: when ``content_length`` is absent, ``length`` wins.

    Confirms the ``_first_int`` helper still falls through to the second
    key when the first is ``None`` (vs. the LOW-3 case where the first is
    ``0`` and must NOT fall through).
    """
    raw = _gau_jsonl(
        {
            "url": "https://target/with-fallback",
            "length": 8765,
        }
    )

    parse_gau_jsonl(raw, b"", tmp_path, "gau")

    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    assert sidecar[0]["content_length"] == 8765


def test_parse_gau_jsonl_drops_boolean_status_code_field(tmp_path: Path) -> None:
    """``True`` / ``False`` in numeric fields is dropped (bool ≢ int).

    Pins the ``isinstance(value, bool)`` guard in ``_int_field``: in
    Python ``bool`` is a subclass of ``int``, so a careless extractor
    would silently coerce ``True`` to ``1``. The guard returns ``None``
    so the bogus value never reaches the sidecar / FindingDTO.
    """
    raw = _gau_jsonl(
        {
            "url": "https://target/bool-status",
            "status_code": True,  # caller bug; must not silently become 1
        }
    )

    parse_gau_jsonl(raw, b"", tmp_path, "gau")

    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    record = sidecar[0]
    assert "status_code" not in record, (
        "boolean values must be dropped — bool ≢ int even though "
        "issubclass(bool, int) is True"
    )
