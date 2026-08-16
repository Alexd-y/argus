"""Unit tests for :mod:`src.sandbox.parsers.commix_parser` (Backlog/dev1_md §4.9 — F-M03).

Pinned contracts:

* Resolves ``artifacts_dir/commix_output.txt`` before falling back to
  ``stdout``.
* Only positive detection lines ("vulnerable to" / "injectable") yield
  findings; progress / warning chatter is ignored.
* Category — every emitted finding is ``CMDI`` with CWE ``[77, 78]`` and a
  critical CVSS base score.
* Confidence — every commix hit → ``CONFIRMED``.
* Dedup — composite ``(param_lower, method)``; multiple techniques on the
  same parameter collapse to one finding.
* A URL-level detection is only emitted when no parameter-level finding was
  seen.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.commix_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_commix,
)

_GET_ADDR_RESULTS = (
    "[+] The (GET) 'addr' parameter is vulnerable to (results-based) "
    "command injection technique."
)
_GET_ADDR_TIME = (
    "[+] The (GET) 'addr' parameter is vulnerable to (time-based) "
    "command injection technique."
)
_POST_NAME = (
    "[+] The (POST) 'name' parameter is vulnerable to (time-based) "
    "command injection technique."
)
_URL_LEVEL = "[+] The target URL appears to be vulnerable to command injection attacks."


def _stdout(*lines: str) -> bytes:
    return "\n".join(lines).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_commix(b"", b"", tmp_path, "commix") == []


def test_get_parameter_detection(tmp_path: Path) -> None:
    findings = parse_commix(_stdout(_GET_ADDR_RESULTS), b"", tmp_path, "commix")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.CMDI
    assert finding.confidence is ConfidenceLevel.CONFIRMED
    assert finding.cwe == [77, 78]
    assert finding.cvss_v3_score == 9.8


def test_evidence_records_param_and_method(tmp_path: Path) -> None:
    parse_commix(_stdout(_POST_NAME), b"", tmp_path, "commix")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["kind"] == "commix_cmdi"
    assert blob["param"] == "name"
    assert blob["method"] == "POST"
    assert blob["technique"] == "time-based"
    assert blob["tool_id"] == "commix"


def test_multiple_techniques_same_param_collapse(tmp_path: Path) -> None:
    findings = parse_commix(
        _stdout(_GET_ADDR_RESULTS, _GET_ADDR_TIME), b"", tmp_path, "commix"
    )
    assert len(findings) == 1


def test_distinct_parameters_kept_separate(tmp_path: Path) -> None:
    findings = parse_commix(
        _stdout(_GET_ADDR_RESULTS, _POST_NAME), b"", tmp_path, "commix"
    )
    assert len(findings) == 2


def test_url_level_only_emits_one_finding(tmp_path: Path) -> None:
    findings = parse_commix(_stdout(_URL_LEVEL), b"", tmp_path, "commix")
    assert len(findings) == 1
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["url_level"] is True


def test_url_level_suppressed_when_param_level_present(tmp_path: Path) -> None:
    findings = parse_commix(
        _stdout(_GET_ADDR_RESULTS, _URL_LEVEL), b"", tmp_path, "commix"
    )
    assert len(findings) == 1
    rows = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    ]
    assert all(not row.get("url_level") for row in rows)


def test_progress_and_warning_chatter_ignored(tmp_path: Path) -> None:
    noise = _stdout(
        "[*] Testing the (results-based) command injection technique.",
        "[!] Warning: unable to connect to the target URL.",
        "[i] Powered by commix.",
    )
    assert parse_commix(noise, b"", tmp_path, "commix") == []


def test_canonical_file_preferred_over_stdout(tmp_path: Path) -> None:
    (tmp_path / "commix_output.txt").write_bytes(_stdout(_POST_NAME))
    decoy = _stdout(_GET_ADDR_RESULTS)
    parse_commix(decoy, b"", tmp_path, "commix")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["param"] == "name"


def test_parenthesised_quote_variant_is_parsed(tmp_path: Path) -> None:
    line = (
        "[+] The ('user') POST parameter appears to be injectable via "
        "(time-based) command injection technique."
    )
    parse_commix(_stdout(line), b"", tmp_path, "commix")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["param"] == "user"
    assert blob["method"] == "POST"
