"""Unit tests for :mod:`src.sandbox.parsers.sqlmap_parser` (Backlog/dev1_md §4.9).

Each test pins one contract documented in the parser:

* ``parse_sqlmap_output`` resolves canonical per-host log files first
  (``artifacts_dir/sqlmap*/<host>/log``) and falls back to ``stdout``.
* ``Parameter: <name> (<location>)`` blocks become CONFIRMED SQLi
  findings tagged with CWE-89 and WSTG-INPV-05.
* Multiple ``Type:`` / ``Title:`` / ``Payload:`` lines in the same
  parameter block fold into a single FindingDTO; every technique is
  preserved inside the evidence sidecar.
* Records collapse on a stable ``(target_url, parameter, location)``
  dedup key — running sqlmap twice on the same site emits one
  finding per unique ``(url, param, location)`` triple.
* Output ordering is deterministic — sorted by the dedup key.
* Hard cap at 5 000 findings — defends the worker against a runaway
  scan that surfaces hundreds of injectable parameters.
* Malformed / empty inputs return ``[]`` without crashing the worker
  and without writing a sidecar.
* Sidecar JSONL ``sqlmap_findings.jsonl`` carries one compact record
  per emitted finding, stamped with the source ``tool_id`` so the
  downstream evidence pipeline can route per-tool.
* Stdout-only runs (no canonical log dir) still parse correctly.
* Path-traversal-shaped host directory names are skipped defensively
  when walking the canonical log tree.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers._base import SENTINEL_UUID
from src.sandbox.parsers.sqlmap_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_sqlmap_output,
)


# ---------------------------------------------------------------------------
# Builders for canonical fixture shapes
# ---------------------------------------------------------------------------


def _sqlmap_block(
    *,
    param: str = "id",
    location: str = "GET",
    typ: str = "boolean-based blind",
    title: str = "AND boolean-based blind - WHERE or HAVING clause",
    payload: str = "id=1 AND 1=1",
) -> str:
    """Render one sqlmap ``Parameter: ...`` block (no leading URL line)."""
    return (
        f"Parameter: {param} ({location})\n"
        f"    Type: {typ}\n"
        f"    Title: {title}\n"
        f"    Payload: {payload}\n"
    )


def _sqlmap_log(
    *,
    target_url: str = "https://target.test/index.php?id=1",
    dbms: str | None = "MySQL",
    blocks: list[str] | None = None,
) -> str:
    """Render a sqlmap log preamble + concatenated parameter blocks."""
    lines: list[str] = []
    lines.append(
        f"[12:34:56] [INFO] testing connection to the target URL {target_url}",
    )
    if dbms:
        lines.append(f"[12:34:57] [INFO] back-end DBMS is {dbms}")
    lines.append("")
    body = "\n".join(blocks or [_sqlmap_block()])
    return "\n".join(lines) + "\n" + body


def _write_canonical_log(
    artifacts_dir: Path,
    *,
    host: str = "target.test",
    log_text: str,
    out_dir_name: str = "sqlmap",
) -> Path:
    """Materialise ``artifacts_dir/<out_dir_name>/<host>/log``."""
    log_path = artifacts_dir / out_dir_name / host / "log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(log_text.encode("utf-8"))
    return log_path


# ---------------------------------------------------------------------------
# Resolution: canonical log dir vs stdout fallback
# ---------------------------------------------------------------------------


def test_parse_sqlmap_canonical_log_takes_precedence_over_stdout(
    tmp_path: Path,
) -> None:
    """Canonical log dir wins; stdout is ignored when both are set."""
    canonical_log = _sqlmap_log(
        blocks=[_sqlmap_block(param="canonical_param", payload="id=2 AND 2=2")],
    )
    _write_canonical_log(tmp_path, log_text=canonical_log)

    stdout_log = _sqlmap_log(
        blocks=[_sqlmap_block(param="should_not_appear", payload="id=99")],
    )
    findings = parse_sqlmap_output(
        stdout=stdout_log.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical_param" in sidecar
    assert "should_not_appear" not in sidecar


def test_parse_sqlmap_stdout_fallback_when_canonical_missing(
    tmp_path: Path,
) -> None:
    """No canonical → fall back to stdout."""
    log_text = _sqlmap_log(blocks=[_sqlmap_block(param="q", location="POST")])
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.SQLI
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_parse_sqlmap_canonical_confirm_dir_is_also_picked_up(
    tmp_path: Path,
) -> None:
    """``sqlmap_confirm`` writes under ``sqlmap_confirm/<host>/log`` — both glob."""
    log_text = _sqlmap_log(
        blocks=[_sqlmap_block(param="user", payload="user=admin' OR '1'='1")],
    )
    _write_canonical_log(
        tmp_path,
        host="confirm.test",
        log_text=log_text,
        out_dir_name="sqlmap_confirm",
    )
    findings = parse_sqlmap_output(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_confirm",
    )
    assert len(findings) == 1


def test_parse_sqlmap_multiple_host_dirs_are_concatenated_lexicographically(
    tmp_path: Path,
) -> None:
    """Two host dirs under ``sqlmap/`` parse deterministically in lex order."""
    _write_canonical_log(
        tmp_path,
        host="bbb.test",
        log_text=_sqlmap_log(
            target_url="https://bbb.test/?id=1",
            blocks=[_sqlmap_block(param="id_b")],
        ),
    )
    _write_canonical_log(
        tmp_path,
        host="aaa.test",
        log_text=_sqlmap_log(
            target_url="https://aaa.test/?id=1",
            blocks=[_sqlmap_block(param="id_a")],
        ),
    )
    findings = parse_sqlmap_output(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# FindingDTO classification
# ---------------------------------------------------------------------------


def test_parse_sqlmap_block_classifies_as_confirmed_sqli(tmp_path: Path) -> None:
    """Every sqlmap block → SQLI / CONFIRMED with CWE-89, WSTG-INPV-05."""
    log_text = _sqlmap_log(blocks=[_sqlmap_block()])
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.SQLI
    assert finding.confidence is ConfidenceLevel.CONFIRMED
    assert 89 in finding.cwe
    assert "WSTG-INPV-05" in finding.owasp_wstg
    assert finding.tenant_id == SENTINEL_UUID


# ---------------------------------------------------------------------------
# Multi-technique folding
# ---------------------------------------------------------------------------


def test_parse_sqlmap_multiple_techniques_fold_into_one_finding(
    tmp_path: Path,
) -> None:
    """Same ``Parameter:`` block twice (different Type lines) → one finding,
    techniques captured in sidecar."""
    log_text = _sqlmap_log(
        blocks=[
            _sqlmap_block(
                param="id",
                typ="boolean-based blind",
                title="AND boolean-based blind",
                payload="id=1 AND 1=1",
            ),
            _sqlmap_block(
                param="id",
                typ="time-based blind",
                title="MySQL >= 5.0.12 time-based blind (SLEEP)",
                payload="id=1 AND SLEEP(5)",
            ),
        ],
    )
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 1  # collapsed by (url, param, location)

    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sorted(sidecar["techniques"]) == [
        "boolean-based blind",
        "time-based blind",
    ]
    assert any("SLEEP" in p for p in sidecar["payloads"])


def test_parse_sqlmap_dbms_carries_into_evidence(tmp_path: Path) -> None:
    """The scan-scoped DBMS line lands inside every block's evidence."""
    log_text = _sqlmap_log(
        dbms="PostgreSQL 15.4",
        blocks=[_sqlmap_block(param="id")],
    )
    parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["dbms"] == "PostgreSQL 15.4"


def test_parse_sqlmap_target_url_persists_across_blocks(tmp_path: Path) -> None:
    """``URL: ...`` / ``testing connection to the target URL`` is scan-scoped."""
    log_text = (
        "[12:34:56] [INFO] testing connection to the target URL "
        "https://t.test/api?q=x\n"
        "[12:34:57] [INFO] back-end DBMS is MySQL\n"
        "\n"
        + _sqlmap_block(param="q", location="GET")
        + "\n"
        + _sqlmap_block(param="q2", location="GET")
    )
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 2
    sidecar_lines = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert {r["target_url"] for r in sidecar_lines} == {"https://t.test/api?q=x"}


# ---------------------------------------------------------------------------
# Dedup / sort / cap
# ---------------------------------------------------------------------------


def test_parse_sqlmap_dedup_collapses_duplicate_blocks(tmp_path: Path) -> None:
    """Two identical ``Parameter:`` blocks fold into one finding."""
    block = _sqlmap_block(param="id", location="GET")
    log_text = _sqlmap_log(blocks=[block, block])
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 1


def test_parse_sqlmap_output_ordering_is_deterministic(tmp_path: Path) -> None:
    """Two runs of the parser on the same payload produce identical sidecars."""
    log_text = _sqlmap_log(
        blocks=[
            _sqlmap_block(param="z_param"),
            _sqlmap_block(param="a_param"),
            _sqlmap_block(param="m_param"),
        ],
    )
    sidecar_path = tmp_path / EVIDENCE_SIDECAR_NAME

    parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    first = sidecar_path.read_text(encoding="utf-8")
    sidecar_path.unlink()

    parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    second = sidecar_path.read_text(encoding="utf-8")
    assert first == second


def test_parse_sqlmap_caps_at_5000_findings(tmp_path: Path) -> None:
    """A pathological scan with >5 000 unique parameter blocks is hard-capped."""
    blocks = [_sqlmap_block(param=f"p{i:05d}", location="GET") for i in range(5_500)]
    log_text = _sqlmap_log(blocks=blocks)
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 5_000


# ---------------------------------------------------------------------------
# Sidecar contract
# ---------------------------------------------------------------------------


def test_parse_sqlmap_sidecar_records_carry_tool_id(tmp_path: Path) -> None:
    """Every sidecar record is stamped with the source ``tool_id``."""
    log_text = _sqlmap_log(blocks=[_sqlmap_block(param="x")])
    parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_confirm",
    )
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["tool_id"] == "sqlmap_confirm"
    assert sidecar["kind"] == "sqlmap_injection"
    assert sidecar["parameter"] == "x"
    assert sidecar["location"] == "GET"
    assert "synthetic_id" in sidecar


def test_parse_sqlmap_sidecar_only_written_when_findings_exist(
    tmp_path: Path,
) -> None:
    """No findings → no sidecar artifact (avoid confusing empty companions)."""
    findings = parse_sqlmap_output(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_parse_sqlmap_sidecar_write_failure_swallowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """OSError on the sidecar path is logged, parser still returns findings."""
    log_text = _sqlmap_log(blocks=[_sqlmap_block(param="id")])

    real_open = Path.open

    def _raise(self: Path, *args: object, **kwargs: object) -> object:
        if self.name == EVIDENCE_SIDECAR_NAME:
            raise PermissionError("simulated sidecar failure")
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", _raise)
    with caplog.at_level(logging.WARNING):
        findings = parse_sqlmap_output(
            stdout=log_text.encode("utf-8"),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="sqlmap_safe",
        )
    assert len(findings) == 1
    assert any(
        getattr(r, "event", "") == "sqlmap_parser_evidence_sidecar_write_failed"
        for r in caplog.records
    )


# ---------------------------------------------------------------------------
# Edge / fail-soft
# ---------------------------------------------------------------------------


def test_parse_sqlmap_empty_inputs_return_empty(tmp_path: Path) -> None:
    """Empty stdout + missing canonical → ``[]`` and no sidecar."""
    findings = parse_sqlmap_output(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_parse_sqlmap_garbage_input_returns_empty(tmp_path: Path) -> None:
    """Random non-sqlmap text → ``[]``; no parameters surface."""
    findings = parse_sqlmap_output(
        stdout=b"this output has no Parameter: lines whatsoever\n" * 10,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert findings == []


def test_parse_sqlmap_unsafe_host_dir_segment_is_skipped(tmp_path: Path) -> None:
    """A host dir named with ``..`` is rejected; valid sibling still parses."""
    valid_log = _sqlmap_log(blocks=[_sqlmap_block(param="ok")])
    _write_canonical_log(tmp_path, host="legit.test", log_text=valid_log)

    # Create an evil sibling with a traversal-shaped name. mkdir() refuses
    # forbidden NTFS chars on Windows; we simulate the unsafe segment via
    # a directly named subfolder.
    evil = tmp_path / "sqlmap" / "..evil"
    evil.mkdir(parents=True, exist_ok=True)
    (evil / "log").write_bytes(b"[INFO] Parameter: evil (GET)\n")

    findings = parse_sqlmap_output(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert len(findings) == 1
    assert "evil" not in sidecar


def test_parse_sqlmap_canonical_unreadable_falls_back_to_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An OSError on the canonical log → log warning + fall back to stdout."""
    canonical = _write_canonical_log(
        tmp_path,
        log_text=_sqlmap_log(blocks=[_sqlmap_block(param="canonical")]),
    )

    real_read_bytes = Path.read_bytes

    def _raise(self: Path) -> bytes:
        if self == canonical:
            raise PermissionError("simulated read failure")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _raise)

    stdout_log = _sqlmap_log(blocks=[_sqlmap_block(param="from_stdout")])
    with caplog.at_level(logging.WARNING):
        findings = parse_sqlmap_output(
            stdout=stdout_log.encode("utf-8"),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="sqlmap_safe",
        )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "from_stdout" in sidecar
    assert "canonical" not in sidecar
    assert any(
        getattr(r, "event", "") == "sqlmap_parser_canonical_read_failed"
        for r in caplog.records
    )


def test_parse_sqlmap_log_with_timestamp_and_level_prefixes_parses(
    tmp_path: Path,
) -> None:
    """Real sqlmap log format with ``[HH:MM:SS] [INFO]`` prefixes parses."""
    log_text = (
        "[14:01:23] [INFO] testing connection to the target URL "
        "https://example.test/?id=1\n"
        "[14:01:24] [INFO] heuristic (basic) test shows that GET parameter "
        "'id' might be injectable\n"
        "[14:01:25] [INFO] back-end DBMS is MySQL\n"
        "\n"
        "[14:01:26] [INFO] sqlmap identified the following injection point(s) "
        "with a total of 56 HTTP(s) requests:\n"
        "---\n"
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
        "    Payload: id=1 AND 9999=9999\n"
        "---\n"
    )
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 1
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["target_url"] == "https://example.test/?id=1"
    assert sidecar["dbms"] == "MySQL"
    assert sidecar["techniques"] == ["boolean-based blind"]


def test_parse_sqlmap_param_block_without_url_uses_empty_target(
    tmp_path: Path,
) -> None:
    """A bare block with no URL still produces a finding (target_url=``"" )."""
    log_text = _sqlmap_block(param="orphan", location="POST")
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 1
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar.get("target_url", "") == "" or "target_url" not in sidecar
    assert sidecar["parameter"] == "orphan"
    assert sidecar["location"] == "POST"


def test_parse_sqlmap_stderr_is_ignored(tmp_path: Path) -> None:
    """``stderr`` carries banners only; no findings should leak from it."""
    findings = parse_sqlmap_output(
        stdout=b"",
        stderr=b"Parameter: from_stderr (GET)\nType: stderr-only\n",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Defensive coverage — log-tree IO failures + payload truncation
# ---------------------------------------------------------------------------


def test_parse_sqlmap_payload_over_evidence_cap_is_truncated(
    tmp_path: Path,
) -> None:
    """A 10 KiB payload string is truncated in the sidecar evidence (4 KiB cap)."""
    huge = "A" * 10_000
    log_text = _sqlmap_log(blocks=[_sqlmap_block(param="big", payload=huge)])
    parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["payloads"]
    assert all(p.endswith("...[truncated]") for p in sidecar["payloads"])


def test_parse_sqlmap_canonical_glob_failure_falls_back_to_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An OSError thrown from ``Path.glob`` is logged + fall back to stdout."""

    real_glob = Path.glob

    def _raise(self: Path, pattern: str) -> object:
        if self == tmp_path and pattern.startswith("sqlmap"):
            raise PermissionError("simulated glob failure")
        return real_glob(self, pattern)

    monkeypatch.setattr(Path, "glob", _raise)

    stdout_log = _sqlmap_log(blocks=[_sqlmap_block(param="from_stdout_after_glob")])
    with caplog.at_level(logging.WARNING):
        findings = parse_sqlmap_output(
            stdout=stdout_log.encode("utf-8"),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="sqlmap_safe",
        )
    assert len(findings) == 1
    assert any(
        getattr(r, "event", "") == "sqlmap_parser_canonical_glob_failed"
        for r in caplog.records
    )


# ---------------------------------------------------------------------------
# CVSS scoring (ARG-016/017 reviewer H1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("technique", "expected_score"),
    [
        ("stacked queries", 9.5),
        ("UNION query", 9.1),
        ("error-based", 8.8),
        ("boolean-based blind", 8.5),
        ("time-based blind", 8.5),
        ("inline queries", 8.5),
    ],
)
def test_parse_sqlmap_technique_to_cvss_score(
    tmp_path: Path,
    technique: str,
    expected_score: float,
) -> None:
    """Each documented sqlmap technique lifts ``cvss_v3_score`` per H1 map.

    Sqlmap only reports parameters once it has confirmed a working
    injection — every emitted FindingDTO must therefore carry a
    non-sentinel CVSS so :class:`Prioritizer` does not flatten verified
    SQLi to :attr:`PriorityTier.P4_INFO`.
    """
    log_text = _sqlmap_log(
        blocks=[_sqlmap_block(param=f"p_{technique[:3]}", typ=technique)],
    )
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == expected_score


def test_parse_sqlmap_unknown_technique_falls_back_to_default_cvss(
    tmp_path: Path,
) -> None:
    """An unrecognised technique → conservative confirmed-SQLi baseline (8.5)."""
    log_text = _sqlmap_log(
        blocks=[_sqlmap_block(param="weird", typ="some-unknown-technique")],
    )
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == 8.5


def test_parse_sqlmap_multi_technique_picks_max_cvss(tmp_path: Path) -> None:
    """When several techniques fold onto one finding, the highest CVSS wins."""
    log_text = _sqlmap_log(
        blocks=[
            _sqlmap_block(
                param="id",
                typ="boolean-based blind",
                title="AND boolean-based blind",
                payload="id=1 AND 1=1",
            ),
            _sqlmap_block(
                param="id",
                typ="stacked queries",
                title="MySQL >= 5.0.12 stacked queries",
                payload="id=1; INSERT INTO logs VALUES(0)",
            ),
        ],
    )
    findings = parse_sqlmap_output(
        stdout=log_text.encode("utf-8"),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="sqlmap_safe",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == 9.5
