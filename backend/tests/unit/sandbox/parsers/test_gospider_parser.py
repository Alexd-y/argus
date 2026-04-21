"""Unit tests for :func:`src.sandbox.parsers.katana_parser.parse_gospider_jsonl`.

Gospider's ``--json`` shape differs from katana's:

* The discovered URL lives in ``output`` (not ``request.endpoint``).
* The status is a *string* in ``stat`` (not an int in ``response.status_code``).
* There is no per-record HTTP method — every gospider crawl request is GET
  by construction; the parser fills the method as ``"GET"``.

Each test pins exactly one contract:

* Gospider records normalise onto the same ``(endpoint, method)``-keyed
  ``FindingDTO`` shape as katana.
* The shared sidecar (``katana_findings.jsonl``) carries the source
  ``tool_id="gospider"``.
* Records without ``output`` (and without a fallback ``url``) are skipped.
* String ``stat`` values are coerced to int when numeric, dropped otherwise.
* Dedup + sort semantics mirror the katana parser.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.katana_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_gospider_jsonl,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _gospider_record(
    output: str,
    *,
    source: str = "scan",
    record_type: str = "url",
    stat: str | None = "200",
    length: int | None = 1234,
) -> dict[str, Any]:
    """Build a single gospider JSONL record matching the documented shape."""
    record: dict[str, Any] = {
        "output": output,
        "url": "https://target.example",
        "source": source,
        "type": record_type,
    }
    if stat is not None:
        record["stat"] = stat
    if length is not None:
        record["length"] = length
    return record


def _gospider_jsonl(*records: dict[str, Any]) -> bytes:
    """Build a gospider JSONL stream from the supplied records."""
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
# Empty input
# ---------------------------------------------------------------------------


def test_empty_stdout_yields_no_findings(tmp_path: Path) -> None:
    """Empty stdout returns ``[]`` and writes no sidecar."""
    findings = parse_gospider_jsonl(b"", b"", tmp_path, "gospider")
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_single_gospider_record_normalises_to_info_finding(tmp_path: Path) -> None:
    """A gospider record produces one INFO/CWE-200 finding with method=GET."""
    raw = _gospider_jsonl(
        _gospider_record("https://target.example/api/users", stat="200")
    )

    findings = parse_gospider_jsonl(raw, b"", tmp_path, "gospider")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == FindingCategory.INFO
    assert finding.cwe == [200]
    assert finding.confidence == ConfidenceLevel.SUSPECTED


def test_sidecar_carries_gospider_tool_id(tmp_path: Path) -> None:
    """The shared sidecar stamps each record with the originating ``tool_id``."""
    raw = _gospider_jsonl(_gospider_record("https://target/page"))

    parse_gospider_jsonl(raw, b"", tmp_path, "gospider")

    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    record = sidecar[0]
    assert record["tool_id"] == "gospider"
    assert record["endpoint"] == "https://target/page"
    assert record["method"] == "GET"
    assert record["status_code"] == 200


# ---------------------------------------------------------------------------
# Status coercion
# ---------------------------------------------------------------------------


def test_string_stat_is_coerced_to_int(tmp_path: Path) -> None:
    """Numeric string ``stat`` values are coerced to int in the sidecar."""
    raw = _gospider_jsonl(
        _gospider_record("https://target/a", stat="200"),
        _gospider_record("https://target/b", stat="403"),
        _gospider_record("https://target/c", stat="500"),
    )

    parse_gospider_jsonl(raw, b"", tmp_path, "gospider")

    sidecar = _read_sidecar(tmp_path)
    statuses = {record["endpoint"]: record["status_code"] for record in sidecar}
    assert statuses == {
        "https://target/a": 200,
        "https://target/b": 403,
        "https://target/c": 500,
    }


def test_non_numeric_stat_is_dropped(tmp_path: Path) -> None:
    """Non-numeric ``stat`` values do not crash and are absent from the sidecar."""
    raw = _gospider_jsonl(
        _gospider_record("https://target/x", stat="error"),
    )

    parse_gospider_jsonl(raw, b"", tmp_path, "gospider")

    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    assert "status_code" not in sidecar[0]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_record_without_output_falls_back_to_url(tmp_path: Path) -> None:
    """When ``output`` is absent, the parser falls back to the ``url`` field."""
    raw = _gospider_jsonl(
        {"url": "https://target/fallback", "source": "robots", "type": "url"}
    )

    findings = parse_gospider_jsonl(raw, b"", tmp_path, "gospider")

    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["endpoint"] == "https://target/fallback"


def test_record_without_output_or_url_is_skipped(tmp_path: Path) -> None:
    """A record without any URL field is silently skipped."""
    raw = _gospider_jsonl(
        {"source": "scan", "type": "url", "stat": "200"},
        _gospider_record("https://target/keep"),
    )

    findings = parse_gospider_jsonl(raw, b"", tmp_path, "gospider")

    assert len(findings) == 1


def test_duplicate_urls_are_collapsed_across_sources(tmp_path: Path) -> None:
    """The same URL discovered via sitemap + scan + robots collapses on dedup."""
    raw = _gospider_jsonl(
        _gospider_record("https://target/page", source="sitemap"),
        _gospider_record("https://target/page", source="scan"),
        _gospider_record("https://target/page", source="robots"),
    )

    findings = parse_gospider_jsonl(raw, b"", tmp_path, "gospider")

    assert len(findings) == 1
