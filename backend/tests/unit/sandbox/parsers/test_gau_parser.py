"""Unit tests for :func:`src.sandbox.parsers.katana_parser.parse_gau_jsonl`.

gau ``--json`` produces minimal records — usually just ``{"url": "..."}``
— but some wrappers add HTTP metadata. The parser tolerates both shapes;
the only required field is ``url``.

Each test pins exactly one contract:

* Minimal records (just ``url``) produce INFO/CWE-200 findings with
  method=GET and the source ``"wayback"``.
* Records carrying optional HTTP metadata (status_code, content_length)
  fold into the sidecar.
* Records without ``url`` are skipped.
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
    parse_gau_jsonl,
)


def _gau_jsonl(*records: dict[str, Any]) -> bytes:
    """Build a gau-style JSONL stream from the supplied records."""
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
# Minimal record shape
# ---------------------------------------------------------------------------


def test_minimal_url_record_produces_info_finding(tmp_path: Path) -> None:
    """A bare ``{"url": "..."}`` record produces one INFO finding."""
    raw = _gau_jsonl(
        {"url": "https://target.example/api/users"},
        {"url": "https://target.example/admin"},
    )

    findings = parse_gau_jsonl(raw, b"", tmp_path, "gau")

    assert len(findings) == 2
    for finding in findings:
        assert finding.category == FindingCategory.INFO
        assert finding.cwe == [200]
        assert finding.confidence == ConfidenceLevel.SUSPECTED


def test_minimal_record_sidecar_defaults_method_and_source(tmp_path: Path) -> None:
    """Sidecar records default method to ``GET`` and source to ``wayback``."""
    raw = _gau_jsonl({"url": "https://target/page"})

    parse_gau_jsonl(raw, b"", tmp_path, "gau")

    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    record = sidecar[0]
    assert record["tool_id"] == "gau"
    assert record["endpoint"] == "https://target/page"
    assert record["method"] == "GET"
    assert record["source"] == "wayback"


# ---------------------------------------------------------------------------
# Optional metadata
# ---------------------------------------------------------------------------


def test_record_with_status_and_length_is_preserved(tmp_path: Path) -> None:
    """Optional HTTP metadata (status_code, content_length) is folded in."""
    raw = _gau_jsonl(
        {
            "url": "https://target/page",
            "status_code": 200,
            "content_length": 9876,
        }
    )

    parse_gau_jsonl(raw, b"", tmp_path, "gau")

    sidecar = _read_sidecar(tmp_path)
    record = sidecar[0]
    assert record["status_code"] == 200
    assert record["content_length"] == 9876


# ---------------------------------------------------------------------------
# Skipping malformed records
# ---------------------------------------------------------------------------


def test_record_without_url_is_skipped(tmp_path: Path) -> None:
    """A record with no ``url``/``endpoint`` field is silently skipped."""
    raw = _gau_jsonl(
        {"status_code": 200},  # no url → drop
        {"url": "https://target/keep"},
    )

    findings = parse_gau_jsonl(raw, b"", tmp_path, "gau")

    assert len(findings) == 1


def test_duplicate_urls_collapse_to_single_finding(tmp_path: Path) -> None:
    """gau historically returns duplicates from different archive sources."""
    raw = _gau_jsonl(
        {"url": "https://target/page"},
        {"url": "https://target/page", "source": "common-crawl"},
        {"url": "https://target/page", "source": "alienvault"},
    )

    findings = parse_gau_jsonl(raw, b"", tmp_path, "gau")

    assert len(findings) == 1
