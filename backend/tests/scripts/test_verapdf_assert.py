"""C7-T02 / ARG-058-followup — unit tests for ``scripts/_verapdf_assert.py``.

The script is the production CI gate that replaces the brittle
``grep 'isCompliant="false"'`` shell pipeline shipped with B6-T01.
Its contract — empty / malformed report → fail, warnings outside the
allow-list → fail, allow-list entries MUST link to a tracked ticket —
is enforced exclusively by these tests; the script has no callers in
the application code path, so a regression here only surfaces when the
PDF/A workflow actually fires on a PR.

Test architecture
-----------------
* All XML fixtures are inline Python strings written via ``tmp_path``;
  no XML files are committed to ``backend/tests/scripts/`` so the
  fixture set stays version-control-friendly and self-documenting.
* Each section maps 1:1 to a public function in ``_verapdf_assert``:
  ``_parse_allow_list`` (Section A), ``_load_report`` (Section B),
  ``_collect_offences`` (Section C), and ``main()`` end-to-end
  (Section D).
* Exit codes from ``main()`` are asserted on the int return value
  (the contract guarantees ``return 0/1/2`` for everything except a
  bad CLI invocation, which leaks an ``argparse.SystemExit`` straight
  through ``_parse_args`` — those cases use ``pytest.raises``).
* ``capsys`` captures the structured ``::error::`` annotations the
  script writes to stdout / stderr so the assertions exercise the
  exact contract the GitHub Actions PR check consumes.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from scripts._verapdf_assert import (
    _AllowEntry,
    _RuleOffence,
    _collect_offences,
    _load_report,
    _parse_allow_list,
    main,
)


# Stable URL prefix — keeps every allow-list entry well-formed without
# hard-coding the ARGUS ticket tracker hostname into a dozen test bodies.
_TICKET_BASE = "https://argus.example.com/tickets"


def _write_xml(tmp_path: Path, body: str, *, name: str = "report.xml") -> Path:
    """Materialise *body* as a UTF-8 XML file under ``tmp_path``."""
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ===========================================================================
# Section A — _parse_allow_list
# ===========================================================================


def test_parse_allow_list_empty_returns_empty() -> None:
    """No ``--allow-warnings`` flags ⇒ empty list, not ``None``."""
    assert _parse_allow_list([]) == []


def test_parse_allow_list_single_csv_entry_parsed() -> None:
    raw = [f"6.1.5:{_TICKET_BASE}/ARG-099"]
    result = _parse_allow_list(raw)

    assert result == [
        _AllowEntry(rule_id="6.1.5", ticket_url=f"{_TICKET_BASE}/ARG-099")
    ]


def test_parse_allow_list_csv_split_on_single_arg() -> None:
    """Comma-separated entries inside ONE ``--allow-warnings`` arg ⇒ all parsed."""
    raw = [
        f"6.1.5:{_TICKET_BASE}/ARG-099,6.2.7:{_TICKET_BASE}/ARG-100"
    ]
    result = _parse_allow_list(raw)

    assert result == [
        _AllowEntry(rule_id="6.1.5", ticket_url=f"{_TICKET_BASE}/ARG-099"),
        _AllowEntry(rule_id="6.2.7", ticket_url=f"{_TICKET_BASE}/ARG-100"),
    ]


def test_parse_allow_list_appended_args_all_parsed() -> None:
    """Repeated ``--allow-warnings`` (action='append') ⇒ every entry kept."""
    raw = [
        f"6.1.5:{_TICKET_BASE}/ARG-099",
        f"6.2.7:{_TICKET_BASE}/ARG-100",
        f"7.1.2:{_TICKET_BASE}/ARG-101",
    ]
    result = _parse_allow_list(raw)

    assert [e.rule_id for e in result] == ["6.1.5", "6.2.7", "7.1.2"]
    assert all(e.ticket_url.startswith(f"{_TICKET_BASE}/") for e in result)


def test_parse_allow_list_bare_rule_id_rejected() -> None:
    """Bare ``rule_id`` (no ``:url``) ⇒ exit-2 SystemExit."""
    with pytest.raises(SystemExit) as exc:
        _parse_allow_list(["6.1.5"])

    msg = str(exc.value)
    assert "6.1.5" in msg
    assert "rule_id" in msg or "shape" in msg
    assert "exit-2" in msg


def test_parse_allow_list_relative_url_rejected() -> None:
    """Ticket URL must be absolute (http:// or https://)."""
    with pytest.raises(SystemExit) as exc:
        _parse_allow_list(["6.1.5:/relative/tickets/ARG-099"])

    msg = str(exc.value)
    assert "absolute" in msg
    assert "exit-2" in msg


def test_parse_allow_list_whitespace_only_token_ignored() -> None:
    """Empty / whitespace tokens between commas are skipped, not errors."""
    raw = [
        f"6.1.5:{_TICKET_BASE}/ARG-099, , 6.2.7:{_TICKET_BASE}/ARG-100",
        "   ,   ",
    ]
    result = _parse_allow_list(raw)

    assert [e.rule_id for e in result] == ["6.1.5", "6.2.7"]


# ===========================================================================
# Section B — _load_report
# ===========================================================================


def test_load_report_missing_file_raises(tmp_path: Path) -> None:
    """Non-existent path ⇒ SystemExit mentioning ``missing``."""
    target = tmp_path / "does-not-exist.xml"

    with pytest.raises(SystemExit) as exc:
        _load_report(target)

    assert "missing" in str(exc.value)


def test_load_report_empty_file_raises(tmp_path: Path) -> None:
    """Zero-byte file ⇒ SystemExit mentioning ``empty`` (verapdf OOM guard)."""
    p = tmp_path / "empty.xml"
    p.write_bytes(b"")

    with pytest.raises(SystemExit) as exc:
        _load_report(p)

    assert "empty" in str(exc.value)


def test_load_report_malformed_xml_raises(tmp_path: Path) -> None:
    """Unparseable XML ⇒ SystemExit mentioning ``well-formed``."""
    p = _write_xml(tmp_path, "not even xml at all just plain text <<<")

    with pytest.raises(SystemExit) as exc:
        _load_report(p)

    assert "well-formed" in str(exc.value)


def test_load_report_wrong_root_raises(tmp_path: Path) -> None:
    """Well-formed XML but wrong root ⇒ SystemExit naming ``validationReport``."""
    p = _write_xml(tmp_path, "<foo/>")

    with pytest.raises(SystemExit) as exc:
        _load_report(p)

    msg = str(exc.value)
    assert "validationReport" in msg
    assert "foo" in msg


def test_load_report_valid_returns_root_element(tmp_path: Path) -> None:
    """Happy path ⇒ returns the parsed root with ``isCompliant`` intact."""
    p = _write_xml(tmp_path, '<validationReport isCompliant="true"/>')

    root = _load_report(p)

    assert isinstance(root, ET.Element)
    assert root.tag == "validationReport"
    assert root.attrib.get("isCompliant") == "true"


# ===========================================================================
# Section C — _collect_offences
# ===========================================================================


def _root(xml: str) -> ET.Element:
    """Small helper — keeps test bodies focused on the offence assertions."""
    return ET.fromstring(xml)


def test_collect_offences_all_passed_returns_empty() -> None:
    """A clean report (only ``status='passed'`` rules) ⇒ no offences."""
    root = _root(
        '<validationReport isCompliant="true">'
        '<rule status="passed" specification="6.1.5" '
        'clause="6.1.5" failedChecks="0"/>'
        '<rule status="passed" specification="6.2.7" '
        'clause="6.2.7" failedChecks="0"/>'
        "</validationReport>"
    )

    assert _collect_offences(root, frozenset(), strict_warnings=True) == []


def test_collect_offences_failed_rule_always_offence() -> None:
    """Hard ``failed`` rule is non-negotiable, regardless of strict mode."""
    root = _root(
        '<validationReport isCompliant="false">'
        '<rule status="failed" specification="7.2" '
        'clause="7.2" failedChecks="3"/>'
        "</validationReport>"
    )

    offences = _collect_offences(root, frozenset(), strict_warnings=True)

    assert len(offences) == 1
    only = offences[0]
    assert only == _RuleOffence(
        status="failed", rule_id="7.2", clause="7.2", count=3
    )


def test_collect_offences_warning_strict_not_allowlisted_is_offence() -> None:
    """``strict_warnings=True`` + warning NOT on allow-list ⇒ blocks the gate."""
    root = _root(
        '<validationReport isCompliant="true">'
        '<rule status="warning" specification="6.1.5" '
        'clause="6.1.5" failedChecks="1"/>'
        "</validationReport>"
    )

    offences = _collect_offences(root, frozenset(), strict_warnings=True)

    assert len(offences) == 1
    assert offences[0].status == "warning"
    assert offences[0].rule_id == "6.1.5"


def test_collect_offences_warning_strict_allowlisted_is_silent() -> None:
    """Operator-owned warning (rule id in allow-list) ⇒ no offence."""
    root = _root(
        '<validationReport isCompliant="true">'
        '<rule status="warning" specification="6.1.5" '
        'clause="6.1.5" failedChecks="1"/>'
        "</validationReport>"
    )

    offences = _collect_offences(
        root, frozenset({"6.1.5"}), strict_warnings=True
    )

    assert offences == []


def test_collect_offences_warning_non_strict_is_silent() -> None:
    """``--no-strict-warnings`` ⇒ warnings are informational only."""
    root = _root(
        '<validationReport isCompliant="true">'
        '<rule status="warning" specification="6.1.5" '
        'clause="6.1.5" failedChecks="1"/>'
        "</validationReport>"
    )

    offences = _collect_offences(root, frozenset(), strict_warnings=False)

    assert offences == []


def test_collect_offences_unknown_status_surfaces_as_unknown_offence() -> None:
    """Unknown verapdf status ⇒ flagged as ``unknown:<status>`` (defence-in-depth)."""
    root = _root(
        '<validationReport isCompliant="true">'
        '<rule status="skipped" specification="9.9" '
        'clause="9.9" failedChecks="0"/>'
        "</validationReport>"
    )

    offences = _collect_offences(root, frozenset(), strict_warnings=True)

    assert len(offences) == 1
    assert offences[0].status == "unknown:skipped"
    assert offences[0].rule_id == "9.9"


def test_collect_offences_mixed_failed_and_warnings() -> None:
    """2 failed + 1 allow-listed warning + 1 fresh warning ⇒ 3 offences."""
    root = _root(
        '<validationReport isCompliant="false">'
        '<rule status="failed" specification="A.1" '
        'clause="A.1" failedChecks="2"/>'
        '<rule status="failed" specification="A.2" '
        'clause="A.2" failedChecks="1"/>'
        '<rule status="warning" specification="WARN-A" '
        'clause="WARN-A" failedChecks="1"/>'
        '<rule status="warning" specification="WARN-B" '
        'clause="WARN-B" failedChecks="1"/>'
        "</validationReport>"
    )

    offences = _collect_offences(
        root, frozenset({"WARN-A"}), strict_warnings=True
    )

    assert len(offences) == 3
    assert sorted(o.status for o in offences) == ["failed", "failed", "warning"]
    assert sorted(o.rule_id for o in offences) == ["A.1", "A.2", "WARN-B"]


# ===========================================================================
# Section D — main() end-to-end via tmp_path
# ===========================================================================


def test_main_compliant_no_warnings_returns_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Fully-conformant report with no warnings ⇒ exit 0 + ``PASSED`` line."""
    p = _write_xml(
        tmp_path,
        '<validationReport isCompliant="true">'
        '<rule status="passed" specification="6.1.5" '
        'clause="6.1.5" failedChecks="0"/>'
        "</validationReport>",
    )

    code = main(["--report", str(p)])
    captured = capsys.readouterr()

    assert code == 0
    assert "PASSED" in captured.out
    assert "::error::" not in captured.err


def test_main_non_compliant_returns_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``isCompliant='false'`` ⇒ exit 1 + structured NON-CONFORMANT annotation."""
    p = _write_xml(
        tmp_path,
        '<validationReport isCompliant="false">'
        '<rule status="failed" specification="7.2" '
        'clause="7.2" failedChecks="3"/>'
        "</validationReport>",
    )

    code = main(["--report", str(p)])
    captured = capsys.readouterr()

    assert code == 1
    assert "NON-CONFORMANT" in captured.err
    assert "PDF/A FAILED" in captured.out  # _emit_offence annotation


def test_main_compliant_with_unallowed_warning_returns_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Compliant verdict but a fresh warning + no allow-list ⇒ exit 1."""
    p = _write_xml(
        tmp_path,
        '<validationReport isCompliant="true">'
        '<rule status="warning" specification="6.1.5" '
        'clause="6.1.5" failedChecks="1"/>'
        "</validationReport>",
    )

    code = main(["--report", str(p)])
    captured = capsys.readouterr()

    assert code == 1
    assert "PDF/A WARNING" in captured.out
    assert "blocked the gate" in captured.err


def test_main_compliant_with_allowlisted_warning_returns_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Same warning, but rule on the allow-list ⇒ exit 0 (clean PASSED)."""
    p = _write_xml(
        tmp_path,
        '<validationReport isCompliant="true">'
        '<rule status="warning" specification="6.1.5" '
        'clause="6.1.5" failedChecks="1"/>'
        "</validationReport>",
    )

    code = main(
        [
            "--report",
            str(p),
            "--allow-warnings",
            f"6.1.5:{_TICKET_BASE}/ARG-099",
        ]
    )
    captured = capsys.readouterr()

    assert code == 0
    assert "PASSED" in captured.out
    assert "6.1.5" in captured.out


def test_main_missing_report_flag_argparse_exits_two() -> None:
    """argparse owns ``--report``; missing flag ⇒ SystemExit(2) leaks out."""
    with pytest.raises(SystemExit) as exc:
        main([])

    assert exc.value.code == 2


def test_main_no_strict_warnings_lets_warning_pass(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Soft mode (``--no-strict-warnings``) ⇒ warning does NOT block exit 0."""
    p = _write_xml(
        tmp_path,
        '<validationReport isCompliant="true">'
        '<rule status="warning" specification="6.1.5" '
        'clause="6.1.5" failedChecks="1"/>'
        "</validationReport>",
    )

    code = main(["--report", str(p), "--no-strict-warnings"])
    captured = capsys.readouterr()

    assert code == 0
    assert "PASSED" in captured.out


def test_main_bad_allow_warnings_shape_returns_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--allow-warnings rule_only`` ⇒ exit 2 (tooling bug, not PDF bug)."""
    p = _write_xml(
        tmp_path,
        '<validationReport isCompliant="true"/>',
    )

    code = main(["--report", str(p), "--allow-warnings", "rule_only"])
    captured = capsys.readouterr()

    assert code == 2
    # Diagnostic should name the offending token AND point at the
    # required shape so the operator can fix the CLI invocation.
    assert "rule_only" in captured.err
    assert "exit-2" in captured.err
