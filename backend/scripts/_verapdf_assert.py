"""ARG-058-followup / C7-T02 — verapdf XML assertion with warning enforcement.

Replaces the brittle ``grep 'isCompliant="false"'`` shell pipeline that
shipped with B6-T01 with a deterministic XML parser. The B6-T01 gate
only failed on hard non-conformance; this hardening also blocks any
``warningRules`` entry not on an explicit allow-list — so a regression
that downgrades a clean PDF/A-2u output to "compliant with warnings"
cannot silently land on ``main``.

Design invariants
-----------------
* **Stdlib only.** ``xml.etree.ElementTree`` is enough; we deliberately
  avoid ``lxml`` so the assertion script can run on a vanilla
  ubuntu-latest runner without an extra ``pip install`` step.
* **Allow-list MUST link to a tracked ticket.** Every entry in
  ``--allow-warnings`` is parsed as ``<rule_id>:<ticket_url>``. A bare
  rule id is rejected — operators must explicitly take ownership of
  every accepted warning, with a paper trail.
* **Empty / malformed report → fail.** A zero-byte XML, a parse error,
  or a missing ``<validationReport>`` root is treated as a CI blocker
  rather than "no findings"; otherwise a verapdf failure mode that
  produces no output (e.g. OOM) would silently mark the gate green.
* **Structured failure summary.** Every failed / warned rule is printed
  on its own ``::error::`` annotation line with the rule id, profile
  clause, and a count, so the GitHub Actions PR check shows a pivotable
  list — operators don't have to ``cat`` the raw XML to triage.
* **No mutation of the report file.** The script reads the XML and
  exits; the artefact upload step keeps the raw report alongside the
  PDF for forensic review.

Exit codes
----------
``0`` — PDF is fully PDF/A-conformant AND has no warning rules outside
        the allow-list.
``1`` — PDF is non-conformant OR has warnings not on the allow-list, OR
        the report is empty / malformed / missing the verdict element.
        A structured ``::error::`` line is written to stdout for every
        offence so the GitHub Actions PR checks are pivotable.
``2`` — Bad CLI arguments (unknown allow-list entry shape, missing
        ``--report``, etc.). Distinguishing "tooling problem" from
        "PDF problem" prevents engineers from chasing ghosts when the
        XML schema upstream changes.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from xml.etree import ElementTree as ET

#: verapdf's XML report uses no namespace prefixes for the elements we
#: care about (``validationReport``, ``rule``, ``check``); pin a literal
#: empty namespace to keep XPath queries simple. If verapdf upgrades to
#: namespaced elements in a future release the parser fails fast on the
#: missing root, and the upgrade procedure documented in
#: ``ai_docs/develop/architecture/pdfa-acceptance.md`` kicks in.
_REPORT_ROOT: Final[str] = "validationReport"

#: Status attribute values verapdf emits on each ``<rule>`` block; we
#: refuse anything we don't recognise so a schema bump doesn't silently
#: degrade the gate.
_STATUS_PASSED: Final[str] = "passed"
_STATUS_FAILED: Final[str] = "failed"
_STATUS_WARNING: Final[str] = "warning"
_KNOWN_STATUSES: Final[frozenset[str]] = frozenset(
    {_STATUS_PASSED, _STATUS_FAILED, _STATUS_WARNING}
)


@dataclass(frozen=True, slots=True)
class _RuleOffence:
    """One rule entry that contributes to a failure verdict.

    Carries enough context to print a pivotable error annotation
    (rule id, clause, status, count) without needing to re-parse the
    XML downstream.
    """

    status: str
    rule_id: str
    clause: str
    count: int


@dataclass(frozen=True, slots=True)
class _AllowEntry:
    """Allow-listed warning rule + the ticket that justifies the carve-out."""

    rule_id: str
    ticket_url: str


def _parse_allow_list(raw: Sequence[str]) -> list[_AllowEntry]:
    """Parse ``--allow-warnings`` CSV entries (``rule:url`` pairs).

    Every entry MUST have the ``<rule_id>:<ticket_url>`` shape — a bare
    rule id is rejected so operators cannot quietly accept warnings
    without a paper trail. A malformed entry exits with code 2 (tooling
    problem), which is distinct from a PDF non-conformance (code 1).
    """
    if not raw:
        return []
    entries: list[_AllowEntry] = []
    for raw_entry in raw:
        for token in raw_entry.split(","):
            token = token.strip()
            if not token:
                continue
            head, sep, tail = token.partition(":")
            if not sep or not head.strip() or not tail.strip():
                raise SystemExit(
                    f"--allow-warnings entry {token!r} must use the shape "
                    "'<rule_id>:<ticket_url>' (e.g. "
                    "'6.1.5:https://argus.example.com/tickets/ARG-099'); "
                    "exit-2"
                )
            if not (
                tail.startswith("http://") or tail.startswith("https://")
            ):
                raise SystemExit(
                    f"--allow-warnings entry {token!r} ticket URL must be "
                    "absolute (http:// or https://); exit-2"
                )
            entries.append(_AllowEntry(rule_id=head.strip(), ticket_url=tail.strip()))
    return entries


def _load_report(path: Path) -> ET.Element:
    """Return the verapdf root element; raise on empty / malformed input."""
    if not path.exists():
        raise SystemExit(f"verapdf report missing: {path}; exit-1")
    if path.stat().st_size == 0:
        raise SystemExit(f"verapdf report is empty: {path}; exit-1")
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise SystemExit(
            f"verapdf report at {path} is not well-formed XML: "
            f"{exc.__class__.__name__}; exit-1"
        ) from None
    root = tree.getroot()
    if root is None or root.tag != _REPORT_ROOT:
        raise SystemExit(
            f"verapdf report at {path} is missing the <{_REPORT_ROOT}> "
            f"root (got <{root.tag if root is not None else 'EMPTY'}>); "
            "exit-1"
        )
    return root


def _is_compliant(root: ET.Element) -> bool | None:
    """Return the explicit ``isCompliant`` verdict or ``None`` if missing.

    verapdf emits ``isCompliant="true"|"false"`` on a child element
    (``<jobs><job><validationReport>``); the attribute is the
    authoritative verdict and a missing attribute should never happen
    with a well-formed report.
    """
    raw = root.attrib.get("isCompliant")
    if raw == "true":
        return True
    if raw == "false":
        return False
    return None


def _collect_offences(
    root: ET.Element, allow_ids: frozenset[str], strict_warnings: bool
) -> list[_RuleOffence]:
    """Walk ``<rule>`` entries and return everything that should fail the gate.

    A rule is an "offence" if:

    * status == "failed" (always blocks).
    * status == "warning" AND ``strict_warnings`` is on AND the rule is
      not in ``allow_ids``.

    Unknown statuses surface as offences too — better to fail loudly
    than to silently mis-classify a future verapdf release.
    """
    offences: list[_RuleOffence] = []
    for rule in root.iter("rule"):
        status = rule.attrib.get("status", "").strip().lower()
        rule_id = (
            rule.attrib.get("specification", "").strip()
            or rule.attrib.get("clause", "").strip()
            or rule.attrib.get("id", "").strip()
            or "unknown"
        )
        clause = rule.attrib.get("clause", "").strip() or rule_id
        count_attr = rule.attrib.get("failedChecks", "0")
        try:
            count = int(count_attr)
        except ValueError:
            count = 0

        if status == _STATUS_PASSED:
            continue
        if status == _STATUS_FAILED:
            offences.append(
                _RuleOffence(
                    status=_STATUS_FAILED,
                    rule_id=rule_id,
                    clause=clause,
                    count=count,
                )
            )
            continue
        if status == _STATUS_WARNING:
            if strict_warnings and rule_id not in allow_ids:
                offences.append(
                    _RuleOffence(
                        status=_STATUS_WARNING,
                        rule_id=rule_id,
                        clause=clause,
                        count=count,
                    )
                )
            continue
        if status not in _KNOWN_STATUSES:
            offences.append(
                _RuleOffence(
                    status=f"unknown:{status or 'missing'}",
                    rule_id=rule_id,
                    clause=clause,
                    count=count,
                )
            )
    return offences


def _emit_offence(off: _RuleOffence) -> None:
    """Print one ``::error::`` annotation line that GitHub Actions will surface."""
    print(
        f"::error title=PDF/A {off.status.upper()} ({off.rule_id})::"
        f"clause={off.clause} status={off.status} failedChecks={off.count}"
    )


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="_verapdf_assert",
        description=(
            "Assert a verapdf XML report is fully PDF/A-conformant with "
            "no warnings outside the explicit allow-list (C7-T02)."
        ),
    )
    parser.add_argument(
        "--report",
        type=Path,
        required=True,
        help="Path to the verapdf XML report file.",
    )
    parser.add_argument(
        "--allow-warnings",
        action="append",
        default=[],
        help=(
            "Allow-listed warning rules. Each entry has the shape "
            "'<rule_id>:<ticket_url>'. May be repeated; values are "
            "also CSV-split on ',' for convenience. Empty by default."
        ),
    )
    strict = parser.add_mutually_exclusive_group()
    strict.add_argument(
        "--strict-warnings",
        dest="strict_warnings",
        action="store_true",
        default=True,
        help=(
            "Treat warning rules NOT in the allow-list as failures "
            "(default). The C7-T02 acceptance criterion (b) requires "
            "this for the production gate."
        ),
    )
    strict.add_argument(
        "--no-strict-warnings",
        dest="strict_warnings",
        action="store_false",
        help=(
            "Soft mode — only fail on hard non-conformance. Provided "
            "for local development; CI MUST run with --strict-warnings."
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        allow = _parse_allow_list(args.allow_warnings)
    except SystemExit as exc:
        sys.stderr.write(f"{exc}\n")
        return 2

    try:
        root = _load_report(args.report)
    except SystemExit as exc:
        sys.stderr.write(f"{exc}\n")
        return 1

    verdict = _is_compliant(root)
    if verdict is None:
        sys.stderr.write(
            "::error::verapdf XML report does not carry an isCompliant verdict\n"
        )
        return 1

    allow_ids = frozenset(entry.rule_id for entry in allow)
    offences = _collect_offences(root, allow_ids, args.strict_warnings)

    if not verdict:
        sys.stderr.write(
            "::error title=PDF/A NON-CONFORMANCE::"
            "verapdf reports the PDF as NON-CONFORMANT to the requested flavour\n"
        )

    if offences:
        for off in offences:
            _emit_offence(off)
        sys.stderr.write(
            f"::error::{len(offences)} verapdf rule(s) blocked the gate "
            f"(strict_warnings={args.strict_warnings}, "
            f"allow_listed={sorted(allow_ids)})\n"
        )
        return 1

    if not verdict:
        return 1

    print(
        "verapdf gate PASSED — PDF is fully conformant with no warnings "
        f"outside the allow-list (allow_listed={sorted(allow_ids)})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
