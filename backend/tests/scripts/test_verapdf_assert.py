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
* **Real verapdf MRR XML fixtures** committed under
  ``backend/tests/scripts/fixtures/`` drive the integration-style
  end-to-end tests. The fixture provenance (live ``verapdf-cli`` 1.28.1
  capture vs. hand-crafted-against-the-real-schema) is documented in
  the fixtures' README. The CI workflow pins ``verapdf-cli 1.24.1`` —
  schema is stable across the 1.24.x → 1.30.x range, verified via the
  module docstring of ``_verapdf_assert``.
* **In-memory XML strings** are kept ONLY for the negative-path /
  defensive-code unit tests (malformed XML, empty file, wrong root,
  missing inner ``<validationReport>``) — those exercise the parser's
  guards, not the schema, so a tiny synthetic snippet is the right
  shape there.
* Each section maps 1:1 to a public function in ``_verapdf_assert``:
  ``_parse_allow_list`` (Section A), ``_load_report`` (Section B),
  ``_collect_offences`` (Section C), and ``main()`` end-to-end with
  real fixtures (Section D).
* Exit codes from ``main()`` are asserted on the int return value
  (the contract guarantees ``return 0/1/2`` for everything except a
  bad CLI invocation, which leaks an ``argparse.SystemExit`` straight
  through ``_parse_args`` — those cases use ``pytest.raises``).
* ``capsys`` captures the structured ``::error::`` annotations the
  script writes to stdout / stderr so the assertions exercise the
  exact contract the GitHub Actions PR check consumes.

Trust boundary
--------------
The fixture XMLs live inside the test suite and are loaded with stdlib
``xml.etree.ElementTree``. They are NOT user-supplied input. If
``_verapdf_assert`` is ever reused outside the trusted CI runner
context, the parser MUST switch to ``defusedxml.ElementTree`` to
mitigate XML-bomb / external-entity attacks.
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

# Real-schema fixture directory, resolved relative to THIS test file so
# the suite still works under ``pytest --rootdir=...`` and IDE runners
# that may not start in ``backend/``.
_FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _write_xml(tmp_path: Path, body: str, *, name: str = "report.xml") -> Path:
    """Materialise *body* as a UTF-8 XML file under ``tmp_path``."""
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def _real_fixture(name: str) -> Path:
    """Return the absolute path to a committed real-schema fixture.

    Fails loud if the file is missing — better than silently degrading
    integration coverage when a contributor accidentally deletes a
    fixture.
    """
    p = _FIXTURES_DIR / name
    assert p.exists(), (
        f"missing real-schema verapdf fixture: {p}; see "
        f"{_FIXTURES_DIR / 'README.md'} for provenance + regeneration"
    )
    return p


def _load_real_validation_report(name: str) -> ET.Element:
    """Load a real fixture and return the inner <validationReport> element.

    Reuses the production loader so the helper exercises the same code
    path the unit tests are pinning.
    """
    return _load_report(_real_fixture(name))


# ===========================================================================
# Section A — _parse_allow_list (pure unit tests; schema-agnostic)
# ===========================================================================


def test_parse_allow_list_empty_returns_empty() -> None:
    """No ``--allow-warnings`` flags ⇒ empty list, not ``None``."""
    assert _parse_allow_list([]) == []


def test_parse_allow_list_single_csv_entry_parsed() -> None:
    raw = [f"6.1.5-3:{_TICKET_BASE}/ARG-099"]
    result = _parse_allow_list(raw)

    assert result == [
        _AllowEntry(rule_id="6.1.5-3", ticket_url=f"{_TICKET_BASE}/ARG-099")
    ]


def test_parse_allow_list_csv_split_on_single_arg() -> None:
    """Comma-separated entries inside ONE ``--allow-warnings`` arg ⇒ all parsed."""
    raw = [
        f"6.1.5-3:{_TICKET_BASE}/ARG-099,6.2.7-1:{_TICKET_BASE}/ARG-100"
    ]
    result = _parse_allow_list(raw)

    assert result == [
        _AllowEntry(rule_id="6.1.5-3", ticket_url=f"{_TICKET_BASE}/ARG-099"),
        _AllowEntry(rule_id="6.2.7-1", ticket_url=f"{_TICKET_BASE}/ARG-100"),
    ]


def test_parse_allow_list_appended_args_all_parsed() -> None:
    """Repeated ``--allow-warnings`` (action='append') ⇒ every entry kept."""
    raw = [
        f"6.1.5-3:{_TICKET_BASE}/ARG-099",
        f"6.2.7-1:{_TICKET_BASE}/ARG-100",
        f"7.1.2-2:{_TICKET_BASE}/ARG-101",
    ]
    result = _parse_allow_list(raw)

    assert [e.rule_id for e in result] == ["6.1.5-3", "6.2.7-1", "7.1.2-2"]
    assert all(e.ticket_url.startswith(f"{_TICKET_BASE}/") for e in result)


def test_parse_allow_list_bare_rule_id_rejected() -> None:
    """Bare ``rule_id`` (no ``:url``) ⇒ exit-2 SystemExit."""
    with pytest.raises(SystemExit) as exc:
        _parse_allow_list(["6.1.5-3"])

    msg = str(exc.value)
    assert "6.1.5-3" in msg
    assert "rule_id" in msg or "shape" in msg
    assert "exit-2" in msg


def test_parse_allow_list_relative_url_rejected() -> None:
    """Ticket URL must be absolute (https://)."""
    with pytest.raises(SystemExit) as exc:
        _parse_allow_list(["6.1.5-3:/relative/tickets/ARG-099"])

    msg = str(exc.value)
    assert "absolute" in msg
    assert "exit-2" in msg


def test_parse_allow_list_whitespace_only_token_ignored() -> None:
    """Empty / whitespace tokens between commas are skipped, not errors."""
    raw = [
        f"6.1.5-3:{_TICKET_BASE}/ARG-099, , 6.2.7-1:{_TICKET_BASE}/ARG-100",
        "   ,   ",
    ]
    result = _parse_allow_list(raw)

    assert [e.rule_id for e in result] == ["6.1.5-3", "6.2.7-1"]


# ===========================================================================
# Section B — _load_report (defensive paths use synthetic XML)
# ===========================================================================
#
# The defensive-code branches (file missing / empty / malformed / wrong
# root / missing inner <validationReport>) are unit tests of the
# parser's guards. A 200-byte synthetic snippet is the right shape
# here — committing a real fixture for "empty file" or "wrong root tag"
# would be misleading.


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


def test_load_report_wrong_outer_root_raises(tmp_path: Path) -> None:
    """Well-formed XML but wrong outer root ⇒ SystemExit naming ``report``."""
    p = _write_xml(tmp_path, "<foo/>")

    with pytest.raises(SystemExit) as exc:
        _load_report(p)

    msg = str(exc.value)
    assert "<report>" in msg
    assert "foo" in msg


def test_load_report_missing_inner_validation_report_raises(
    tmp_path: Path,
) -> None:
    """Outer ``<report>`` present but no inner ``<validationReport>`` ⇒ SystemExit."""
    p = _write_xml(
        tmp_path,
        "<report><buildInformation/><jobs><job><item><name>x.pdf</name></item></job></jobs></report>",
    )

    with pytest.raises(SystemExit) as exc:
        _load_report(p)

    msg = str(exc.value)
    assert "<validationReport>" in msg


def test_load_report_task_exception_forwards_verapdf_message(
    tmp_path: Path,
) -> None:
    """Inner ``<taskException>`` ⇒ SystemExit forwards verapdf's exceptionMessage.

    The real fixture
    ``backend/tests/scripts/fixtures/verapdf_real_parse_failure.xml`` is
    a live capture of this case from a malformed PDF; the inline XML
    here is a focused regression test for the diagnostic forwarding.
    """
    p = _write_xml(
        tmp_path,
        '<report><jobs><job><item><name>x.pdf</name></item>'
        '<taskException type="PARSE" isExecuted="true" isSuccess="false">'
        "<exceptionMessage>boom: encrypted PDF</exceptionMessage>"
        "</taskException></job></jobs></report>",
    )

    with pytest.raises(SystemExit) as exc:
        _load_report(p)

    msg = str(exc.value)
    assert "boom: encrypted PDF" in msg
    assert "<validationReport>" in msg


def test_load_report_real_compliant_returns_inner_validation_report() -> None:
    """Real compliant fixture ⇒ returns the inner ``<validationReport>`` element."""
    inner = _load_real_validation_report("verapdf_real_compliant.xml")

    assert isinstance(inner, ET.Element)
    assert inner.tag == "validationReport"
    assert inner.attrib.get("isCompliant") == "true"
    assert inner.attrib.get("profileName") == "PDF/A-2U validation profile"


def test_load_report_real_noncompliant_returns_inner_validation_report() -> None:
    """Real noncompliant fixture ⇒ inner element with ``isCompliant='false'``."""
    inner = _load_real_validation_report("verapdf_real_noncompliant.xml")

    assert inner.tag == "validationReport"
    assert inner.attrib.get("isCompliant") == "false"
    # The real fixture has 4 failed rules (matches the live capture).
    failed_rules = [
        r for r in inner.iter("rule")
        if r.attrib.get("status") == "failed"
    ]
    assert len(failed_rules) == 4


def test_load_report_real_parse_failure_forwards_verapdf_message() -> None:
    """Real parse-failure fixture ⇒ verapdf's exceptionMessage is forwarded."""
    with pytest.raises(SystemExit) as exc:
        _load_report(_real_fixture("verapdf_real_parse_failure.xml"))

    msg = str(exc.value)
    assert "can not locate xref table" in msg


# ===========================================================================
# Section C — _collect_offences (real fixtures + targeted synthetic)
# ===========================================================================


def _root(xml: str) -> ET.Element:
    """Parse ``xml`` and return the inner <validationReport> element.

    Mirrors what :func:`_load_report` returns so the defensive-path
    unit tests below feed ``_collect_offences`` the same shape.
    """
    parsed = ET.fromstring(xml)
    if parsed.tag == "validationReport":
        return parsed
    inner = parsed.find(".//validationReport")
    assert inner is not None, f"test XML missing <validationReport>: {xml!r}"
    return inner


def test_collect_offences_real_compliant_returns_empty() -> None:
    """Real compliant fixture ⇒ no failed/warning rules ⇒ no offences."""
    inner = _load_real_validation_report("verapdf_real_compliant.xml")

    assert _collect_offences(inner, frozenset(), strict_warnings=True) == []


def test_collect_offences_real_noncompliant_returns_four_failed() -> None:
    """Real noncompliant fixture ⇒ exactly 4 failed offences (matches live capture)."""
    inner = _load_real_validation_report("verapdf_real_noncompliant.xml")

    offences = _collect_offences(inner, frozenset(), strict_warnings=True)

    assert len(offences) == 4
    assert all(o.status == "failed" for o in offences)
    # Rule IDs are derived from clause + testNumber; the exact values
    # come from the real verapdf-cli 1.28.1 output.
    assert sorted(o.rule_id for o in offences) == [
        "6.1.7.1-2",
        "6.2.11.4.1-1",
        "6.2.4.3-4",
        "6.6.2.1-1",
    ]


def test_collect_offences_real_warning_strict_is_offence() -> None:
    """Real warning fixture + strict mode + no allow-list ⇒ 1 offence."""
    inner = _load_real_validation_report("verapdf_real_warning.xml")

    offences = _collect_offences(inner, frozenset(), strict_warnings=True)

    assert len(offences) == 1
    only = offences[0]
    assert only.status == "warning"
    assert only.rule_id == "6.1.5-3"  # clause-testNumber from the fixture
    assert only.clause == "6.1.5"


def test_collect_offences_real_warning_allowlisted_is_silent() -> None:
    """Real warning fixture + rule on allow-list ⇒ no offence."""
    inner = _load_real_validation_report("verapdf_real_warning.xml")

    offences = _collect_offences(
        inner, frozenset({"6.1.5-3"}), strict_warnings=True
    )

    assert offences == []


def test_collect_offences_real_warning_non_strict_is_silent() -> None:
    """Real warning fixture + ``--no-strict-warnings`` ⇒ informational only."""
    inner = _load_real_validation_report("verapdf_real_warning.xml")

    offences = _collect_offences(inner, frozenset(), strict_warnings=False)

    assert offences == []


def test_collect_offences_failed_rule_carries_failed_checks_count() -> None:
    """One real failed rule has ``failedChecks=2`` — assert it propagates."""
    inner = _load_real_validation_report("verapdf_real_noncompliant.xml")

    offences = _collect_offences(inner, frozenset(), strict_warnings=True)

    by_id = {o.rule_id: o for o in offences}
    # Clause 6.2.4.3 testNumber=4 has failedChecks=1 in the live capture
    # (single DeviceGray reference; only one PDDeviceGray object emitted).
    assert by_id["6.2.4.3-4"].count == 1
    # The other three each have 1 failed check.
    assert by_id["6.6.2.1-1"].count == 1
    assert by_id["6.2.11.4.1-1"].count == 1
    assert by_id["6.1.7.1-2"].count == 1


def test_collect_offences_unknown_status_surfaces_as_unknown_offence() -> None:
    """Unknown verapdf status ⇒ ``unknown:<status>`` (defensive guard).

    Synthesised against the real schema (outer <report> envelope) so
    the offence path is exercised end-to-end through the same loader.
    """
    inner = _root(
        "<report><jobs><job><validationReport isCompliant=\"true\">"
        "<details>"
        '<rule specification="ISO 19005-2:2011" clause="9.9" '
        'testNumber="1" status="skipped" failedChecks="0"/>'
        "</details></validationReport></job></jobs></report>"
    )

    offences = _collect_offences(inner, frozenset(), strict_warnings=True)

    assert len(offences) == 1
    assert offences[0].status == "unknown:skipped"
    assert offences[0].rule_id == "9.9-1"


def test_collect_offences_mixed_failed_and_warnings() -> None:
    """Real-schema mix: 2 failed + 1 allow-listed warning + 1 fresh warning ⇒ 3 offences."""
    inner = _root(
        '<report><jobs><job><validationReport isCompliant="false">'
        "<details>"
        '<rule specification="ISO 19005-2:2011" clause="A.1" '
        'testNumber="1" status="failed" failedChecks="2"/>'
        '<rule specification="ISO 19005-2:2011" clause="A.2" '
        'testNumber="1" status="failed" failedChecks="1"/>'
        '<rule specification="ISO 19005-2:2011" clause="WARN-A" '
        'testNumber="1" status="warning" failedChecks="1"/>'
        '<rule specification="ISO 19005-2:2011" clause="WARN-B" '
        'testNumber="1" status="warning" failedChecks="1"/>'
        "</details></validationReport></job></jobs></report>"
    )

    offences = _collect_offences(
        inner, frozenset({"WARN-A-1"}), strict_warnings=True
    )

    assert len(offences) == 3
    assert sorted(o.status for o in offences) == ["failed", "failed", "warning"]
    assert sorted(o.rule_id for o in offences) == ["A.1-1", "A.2-1", "WARN-B-1"]


def test_collect_offences_returns_rule_offence_dataclass() -> None:
    """Type contract: every entry is a :class:`_RuleOffence` instance."""
    inner = _load_real_validation_report("verapdf_real_noncompliant.xml")

    offences = _collect_offences(inner, frozenset(), strict_warnings=True)

    assert all(isinstance(o, _RuleOffence) for o in offences)


# ===========================================================================
# Section D — main() end-to-end against real fixtures
# ===========================================================================


def test_main_real_compliant_returns_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Real compliant fixture ⇒ exit 0 + ``PASSED`` line."""
    code = main(["--report", str(_real_fixture("verapdf_real_compliant.xml"))])
    captured = capsys.readouterr()

    assert code == 0
    assert "PASSED" in captured.out
    assert "::error::" not in captured.err


def test_main_real_noncompliant_returns_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Real noncompliant fixture ⇒ exit 1 + 4 failed annotations."""
    code = main(
        ["--report", str(_real_fixture("verapdf_real_noncompliant.xml"))]
    )
    captured = capsys.readouterr()

    assert code == 1
    assert "NON-CONFORMANT" in captured.err
    # 4 distinct PDF/A FAILED annotations from the live verapdf capture.
    for rule_id in ("6.6.2.1-1", "6.2.11.4.1-1", "6.1.7.1-2", "6.2.4.3-4"):
        assert f"PDF/A FAILED ({rule_id})" in captured.out


def test_main_real_warning_strict_returns_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Real warning fixture + default strict mode ⇒ exit 1."""
    code = main(["--report", str(_real_fixture("verapdf_real_warning.xml"))])
    captured = capsys.readouterr()

    assert code == 1
    assert "PDF/A WARNING" in captured.out
    assert "blocked the gate" in captured.err


def test_main_real_warning_allowlisted_returns_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Real warning fixture + rule on allow-list ⇒ exit 0 (clean PASSED)."""
    code = main(
        [
            "--report",
            str(_real_fixture("verapdf_real_warning.xml")),
            "--allow-warnings",
            f"6.1.5-3:{_TICKET_BASE}/ARG-099",
        ]
    )
    captured = capsys.readouterr()

    assert code == 0
    assert "PASSED" in captured.out
    assert "6.1.5-3" in captured.out


def test_main_real_warning_no_strict_returns_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Real warning fixture + ``--no-strict-warnings`` ⇒ warning ignored."""
    code = main(
        [
            "--report",
            str(_real_fixture("verapdf_real_warning.xml")),
            "--no-strict-warnings",
        ]
    )
    captured = capsys.readouterr()

    assert code == 0
    assert "PASSED" in captured.out


def test_main_real_parse_failure_returns_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Real parse-failure fixture ⇒ exit 1 with verapdf's message forwarded."""
    code = main(
        ["--report", str(_real_fixture("verapdf_real_parse_failure.xml"))]
    )
    captured = capsys.readouterr()

    assert code == 1
    assert "can not locate xref table" in captured.err


def test_main_missing_report_flag_argparse_exits_two() -> None:
    """argparse owns ``--report``; missing flag ⇒ SystemExit(2) leaks out."""
    with pytest.raises(SystemExit) as exc:
        main([])

    assert exc.value.code == 2


def test_main_bad_allow_warnings_shape_returns_two(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--allow-warnings rule_only`` ⇒ exit 2 (tooling bug, not PDF bug)."""
    code = main(
        [
            "--report",
            str(_real_fixture("verapdf_real_compliant.xml")),
            "--allow-warnings",
            "rule_only",
        ]
    )
    captured = capsys.readouterr()

    assert code == 2
    # Diagnostic should name the offending token AND point at the
    # required shape so the operator can fix the CLI invocation.
    assert "rule_only" in captured.err
    assert "exit-2" in captured.err


# ===========================================================================
# Section E — defensive code branches (push coverage on rare paths)
# ===========================================================================


def test_main_missing_iscompliant_attr_returns_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``<validationReport>`` without ``isCompliant`` ⇒ exit 1 + diagnostic.

    Real verapdf always emits the attribute; this guard exists for
    defence-in-depth in case a future schema bump makes it optional.
    """
    p = _write_xml(
        tmp_path,
        "<report><jobs><job><validationReport>"
        "<details></details></validationReport></job></jobs></report>",
    )

    code = main(["--report", str(p)])
    captured = capsys.readouterr()

    assert code == 1
    assert "isCompliant verdict" in captured.err


def test_collect_offences_clause_only_rule_id() -> None:
    """``<rule>`` with no testNumber ⇒ rule_id falls back to clause only."""
    inner = _root(
        '<report><jobs><job><validationReport isCompliant="false">'
        "<details>"
        '<rule clause="6.1.5" status="failed" failedChecks="1"/>'
        "</details></validationReport></job></jobs></report>"
    )

    offences = _collect_offences(inner, frozenset(), strict_warnings=True)

    assert len(offences) == 1
    assert offences[0].rule_id == "6.1.5"


def test_collect_offences_test_number_only_rule_id() -> None:
    """``<rule>`` with no clause ⇒ rule_id derived from testNumber alone."""
    inner = _root(
        '<report><jobs><job><validationReport isCompliant="false">'
        "<details>"
        '<rule testNumber="7" status="failed" failedChecks="1"/>'
        "</details></validationReport></job></jobs></report>"
    )

    offences = _collect_offences(inner, frozenset(), strict_warnings=True)

    assert len(offences) == 1
    assert offences[0].rule_id == "test-7"


def test_collect_offences_no_clause_no_test_number_rule_id_unknown() -> None:
    """``<rule>`` missing both clause AND testNumber ⇒ ``"unknown"``."""
    inner = _root(
        '<report><jobs><job><validationReport isCompliant="false">'
        "<details>"
        '<rule status="failed" failedChecks="1"/>'
        "</details></validationReport></job></jobs></report>"
    )

    offences = _collect_offences(inner, frozenset(), strict_warnings=True)

    assert len(offences) == 1
    assert offences[0].rule_id == "unknown"


def test_collect_offences_non_integer_failed_checks_falls_back_to_zero() -> None:
    """Garbage ``failedChecks`` value ⇒ count=0 (no crash on schema drift)."""
    inner = _root(
        '<report><jobs><job><validationReport isCompliant="false">'
        "<details>"
        '<rule clause="6.1.5" testNumber="1" status="failed" '
        'failedChecks="not-a-number"/>'
        "</details></validationReport></job></jobs></report>"
    )

    offences = _collect_offences(inner, frozenset(), strict_warnings=True)

    assert len(offences) == 1
    assert offences[0].count == 0


def test_main_non_compliant_with_no_offences_still_returns_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``isCompliant=false`` + no rules listed ⇒ exit 1 (verdict trumps).

    Real verapdf always lists the failed rule(s) when ``isCompliant=false``;
    this guard exists for the pathological case where the verdict and
    the rule list disagree.
    """
    p = _write_xml(
        tmp_path,
        '<report><jobs><job><validationReport isCompliant="false">'
        "<details></details></validationReport></job></jobs></report>",
    )

    code = main(["--report", str(p)])
    captured = capsys.readouterr()

    assert code == 1
    assert "NON-CONFORMANT" in captured.err
