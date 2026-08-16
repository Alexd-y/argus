"""Unit tests for :mod:`src.sandbox.parsers.curl_parser` (Backlog/dev1_md §4.4 — F-M03).

Pinned contracts:

* Resolves ``artifacts_dir/curl_headers.txt`` before falling back to
  ``stdout``.
* Only server / framework / language disclosure headers yield findings;
  transport / caching / security headers are ignored.
* Category — every finding is ``INFO`` with CWE ``[200]``.
* Confidence — every finding → ``CONFIRMED`` (the header was observed).
* Dedup — composite ``(header_name_lower, value)``; a banner repeated
  across redirect hops collapses to one finding.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.curl_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_curl,
)


def _headers(*lines: str) -> bytes:
    return "\n".join(lines).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_curl(b"", b"", tmp_path, "curl") == []


def test_server_header_yields_info_finding(tmp_path: Path) -> None:
    findings = parse_curl(
        _headers("HTTP/1.1 200 OK", "Server: nginx/1.18.0"),
        b"",
        tmp_path,
        "curl",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.confidence is ConfidenceLevel.CONFIRMED
    assert finding.cwe == [200]


def test_multiple_disclosure_headers_in_one_block(tmp_path: Path) -> None:
    findings = parse_curl(
        _headers(
            "HTTP/2 200",
            "server: Apache/2.4.41 (Ubuntu)",
            "x-powered-by: PHP/7.4.3",
            "x-aspnet-version: 4.0.30319",
            "Content-Type: text/html",
            "Date: Mon, 27 Jul 2026 00:00:00 GMT",
        ),
        b"",
        tmp_path,
        "curl",
    )
    assert len(findings) == 3


def test_non_disclosure_headers_are_ignored(tmp_path: Path) -> None:
    findings = parse_curl(
        _headers(
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=utf-8",
            "Cache-Control: no-cache",
            "Strict-Transport-Security: max-age=31536000",
            "Location: https://target/",
        ),
        b"",
        tmp_path,
        "curl",
    )
    assert findings == []


def test_same_banner_across_hops_collapses(tmp_path: Path) -> None:
    findings = parse_curl(
        _headers(
            "HTTP/1.1 301 Moved Permanently",
            "Server: nginx/1.18.0",
            "",
            "HTTP/1.1 200 OK",
            "Server: nginx/1.18.0",
        ),
        b"",
        tmp_path,
        "curl",
    )
    assert len(findings) == 1


def test_different_banner_values_kept_separate(tmp_path: Path) -> None:
    findings = parse_curl(
        _headers(
            "HTTP/1.1 301 Moved Permanently",
            "Server: cloudflare",
            "",
            "HTTP/1.1 200 OK",
            "Server: nginx/1.18.0",
        ),
        b"",
        tmp_path,
        "curl",
    )
    assert len(findings) == 2


def test_header_matching_is_case_insensitive(tmp_path: Path) -> None:
    findings = parse_curl(
        _headers("HTTP/2 200", "X-Powered-By: Express"),
        b"",
        tmp_path,
        "curl",
    )
    assert len(findings) == 1


def test_evidence_records_header_and_value(tmp_path: Path) -> None:
    parse_curl(
        _headers("HTTP/2 200", "x-powered-by: PHP/7.4.3"),
        b"",
        tmp_path,
        "curl",
    )
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["kind"] == "http_tech_disclosure"
    assert blob["header"] == "x-powered-by"
    assert blob["value"] == "PHP/7.4.3"
    assert blob["tool_id"] == "curl"


def test_canonical_file_preferred_over_stdout(tmp_path: Path) -> None:
    (tmp_path / "curl_headers.txt").write_bytes(
        _headers("HTTP/2 200", "Server: canonical-nginx")
    )
    decoy = _headers("HTTP/2 200", "Server: stdout-apache")
    parse_curl(decoy, b"", tmp_path, "curl")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["value"] == "canonical-nginx"


def test_header_without_value_is_skipped(tmp_path: Path) -> None:
    findings = parse_curl(
        _headers("HTTP/1.1 200 OK", "Server:"),
        b"",
        tmp_path,
        "curl",
    )
    assert findings == []
