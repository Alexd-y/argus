"""ARG-058-followup / C7-T02 — verapdf XML assertion with warning enforcement.

Replaces the brittle ``grep 'isCompliant="false"'`` shell pipeline that
shipped with B6-T01 with a deterministic XML parser. The B6-T01 gate
only failed on hard non-conformance; this hardening also blocks any
``warning`` rule not on an explicit allow-list — so a regression that
downgrades a clean PDF/A-2u output to "compliant with warnings" cannot
silently land on ``main``.

verapdf XML schema (Machine-Readable Report, MRR)
-------------------------------------------------
Targets ``verapdf-cli 1.24.1`` (CI workflow pin) and forward-compatible
with at least 1.28.x and 1.30.x — verified against real fixtures
captured under ``backend/tests/scripts/fixtures/``. The MRR layout is::

    <report>
      <buildInformation>
        <releaseDetails id="core" version="1.28.1" .../>
        ...
      </buildInformation>
      <jobs>
        <job>
          <item size="..."><name>/data/sample.pdf</name></item>
          <validationReport jobEndStatus="normal"
                            profileName="PDF/A-2U validation profile"
                            statement="..."
                            isCompliant="true|false">
            <details passedRules="N" failedRules="M"
                     passedChecks="..." failedChecks="...">
              <rule specification="ISO 19005-2:2011" clause="6.6.2.1"
                    testNumber="1" status="failed|passed|warning"
                    failedChecks="1">
                <description>...</description>
                <object>PDDocument</object>
                <test>containsMetadata == true</test>
                <check status="failed">
                  <context>root/document[0]</context>
                  <errorMessage>...</errorMessage>
                </check>
              </rule>
              ...
            </details>
          </validationReport>
          <!-- OR <taskException> on parse failure -->
        </job>
      </jobs>
      <batchSummary totalJobs="1" failedToParse="0" encrypted="0"
                    outOfMemory="0" veraExceptions="0">
        <validationReports compliant="0" nonCompliant="1"
                           failedJobs="0">1</validationReports>
        ...
      </batchSummary>
    </report>

Schema source: official verapdf MRR documented at
https://github.com/veraPDF/veraPDF-library/wiki/Machine-Readable-Reports
and cross-checked against a live ``verapdf-cli`` 1.28.1 run captured
into ``backend/tests/scripts/fixtures/verapdf_real_noncompliant.xml``.

Design invariants
-----------------
* **Stdlib only.** ``xml.etree.ElementTree`` is enough; we deliberately
  avoid ``lxml`` so the assertion script can run on a vanilla
  ubuntu-latest runner without an extra ``pip install`` step.
* **Allow-list MUST link to a tracked ticket.** Every entry in
  ``--allow-warnings`` is parsed as ``<rule_id>:<ticket_url>``. A bare
  rule id is rejected — operators must explicitly take ownership of
  every accepted warning, with a paper trail. The rule_id format is
  ``<clause>-<testNumber>`` (e.g. ``6.1.7.1-2``) — derived from the
  verapdf ``<rule>`` element's ``clause`` and ``testNumber`` attributes.
* **Empty / malformed report → fail.** A zero-byte XML, a parse error,
  a wrong root tag, or a missing inner ``<validationReport>`` element
  is treated as a CI blocker rather than "no findings"; otherwise a
  verapdf failure mode that produces no output (e.g. OOM, parse
  failure) would silently mark the gate green.
* **Structured failure summary.** Every failed / warned rule is printed
  on its own ``::error::`` annotation line with the rule id, profile
  clause, and a count, so the GitHub Actions PR check shows a pivotable
  list — operators don't have to ``cat`` the raw XML to triage.
* **No mutation of the report file.** The script reads the XML and
  exits; the artefact upload step keeps the raw report alongside the
  PDF for forensic review.

Trust boundary
--------------
The input XML is **trusted**: it is the stdout of ``verapdf-cli`` running
inside the GitHub Actions runner that this script is invoked from
(see ``.github/workflows/pdfa-validation.yml`` — ``Run verapdf-cli``
step pipes the report into ``build/verapdf/<fixture>.verapdf.xml``,
then this script reads it). The XML is therefore produced and consumed
inside the same security boundary; we use ``xml.etree.ElementTree``
without any XXE / billion-laughs hardening.

If this script is reused in any context where the XML originates from
**outside** the CI runner (e.g. an operator pasting an attachment from
a vendor, or a webhook receiving uploads), swap the parser to
``defusedxml.ElementTree`` (drop-in API) and add the ``defusedxml``
package to the install step. ``ET.parse`` and ``ET.fromstring`` calls
are localised to ``_load_report`` for that reason.

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
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

# C7-T02 follow-up (DEBUG-4): the compliance gate's audit trail MUST be
# transport-secure. Allow-list entries point at internal ticket trackers
# (Argus, GitHub) — accepting plaintext http:// would let a tampered
# response (e.g. captive proxy injecting a "ticket exists" page) pass the
# audit step. Restrict to TLS only; future-proof by reading from a single
# allow-set instead of inlining "https" everywhere.
_ALLOWED_TICKET_URL_SCHEMES: Final[frozenset[str]] = frozenset({"https"})

#: verapdf's XML report (Machine-Readable Report / MRR) uses no
#: namespace prefixes for the elements we care about (``report``,
#: ``validationReport``, ``rule``, ``check``); we keep XPath queries
#: literal so a verapdf upgrade that adds a namespace fails fast on
#: the missing root rather than silently mis-parsing the new format.
#:
#: The OUTER root is ``<report>``. The actual validation verdict lives
#: at ``report/jobs/job/validationReport`` — see :func:`_load_report`
#: for the lookup logic and the module docstring for the full schema.
_REPORT_ROOT: Final[str] = "report"

#: Inner element carrying the ``isCompliant`` verdict + the ``<rule>``
#: list. Located via ``root.find(f".//{_VALIDATION_REPORT_TAG}")`` to
#: tolerate verapdf inserting additional wrappers between ``<job>`` and
#: ``<validationReport>`` in a future release.
_VALIDATION_REPORT_TAG: Final[str] = "validationReport"

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

    URL scheme policy (C7-T02 follow-up, DEBUG-4):
        Only ``https://`` is accepted. Plaintext ``http://`` is rejected
        because the compliance audit trail must be transport-secure — a
        tampered response over plain HTTP could falsify the existence /
        contents of the linked ticket. Other schemes (``file://``,
        ``ftp://``, ``javascript:``, etc.) are rejected for the same
        reason and to remove a phishing surface from CI logs.
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
            ticket_url = tail.strip()
            # urlsplit handles edge cases regex cannot: scheme
            # case-insensitivity (HTTP:// == http://), userinfo segments
            # (https://user:pass@host), and ipv6 hosts ([::1]). It never
            # raises - returns empty fields for nonsense input.
            split = urlsplit(ticket_url)
            if not split.scheme or not split.netloc:
                raise SystemExit(
                    f"--allow-warnings entry {token!r} ticket URL must be "
                    "absolute (https://host/path); exit-2"
                )
            scheme = split.scheme.lower()
            if scheme not in _ALLOWED_TICKET_URL_SCHEMES:
                allowed = ", ".join(sorted(_ALLOWED_TICKET_URL_SCHEMES))
                raise SystemExit(
                    f"--allow-warnings entry {token!r} uses scheme "
                    f"{scheme!r}; only {allowed} is accepted to keep the "
                    "compliance audit trail transport-secure; exit-2"
                )
            entries.append(_AllowEntry(rule_id=head.strip(), ticket_url=ticket_url))
    return entries


def _load_report(path: Path) -> ET.Element:
    """Return the inner ``<validationReport>`` element from a verapdf MRR file.

    The verapdf-cli MRR layout (verified against a live 1.28.1 run, and
    documented in the module docstring) places the verdict-bearing
    ``<validationReport>`` element at ``report/jobs/job/validationReport``
    — NOT at the XML root. The B6-T01 implementation assumed the
    inverted layout and silently failed every real run; the fix below
    walks the real schema explicitly and surfaces a precise diagnostic
    when the structure deviates.

    Failure modes (all exit-1, with a structured stderr message):

    * File missing / zero-byte (covers verapdf OOM where the redirect
      target is created but never written).
    * Non-well-formed XML (covers truncated / interrupted runs).
    * Wrong outer root tag (covers a verapdf upgrade that renames
      ``<report>`` to something else).
    * Inner ``<validationReport>`` missing — usually because verapdf
      hit a ``<taskException>`` (parse failure / encrypted / OOM); the
      inner exception message is forwarded so the operator sees the
      verapdf reason instead of "unknown".

    Returning the inner element keeps the downstream helpers
    (:func:`_is_compliant`, :func:`_collect_offences`) agnostic about
    the surrounding envelope — the verapdf MRR can grow new sibling
    blocks (build info, batch summary) without us having to chase them.
    """
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
    validation_report = root.find(f".//{_VALIDATION_REPORT_TAG}")
    if validation_report is None:
        # Diagnose the most common cause: verapdf could not parse the
        # PDF and emitted <taskException> instead of <validationReport>.
        # Forward the upstream message so the operator sees "encrypted",
        # "can not locate xref table", etc., instead of just "missing".
        task_exc = root.find(".//taskException")
        if task_exc is not None:
            inner = (
                task_exc.findtext("exceptionMessage") or "no exceptionMessage"
            ).strip()
            raise SystemExit(
                f"verapdf report at {path} contains no "
                f"<{_VALIDATION_REPORT_TAG}> — verapdf raised "
                f"{inner!r}; exit-1"
            )
        raise SystemExit(
            f"verapdf report at {path} contains no "
            f"<{_VALIDATION_REPORT_TAG}> element under <{_REPORT_ROOT}>; "
            "exit-1"
        )
    return validation_report


def _is_compliant(validation_report: ET.Element) -> bool | None:
    """Return the explicit ``isCompliant`` verdict or ``None`` if missing.

    The attribute lives on the inner ``<validationReport>`` element
    located by :func:`_load_report` (NOT on the outer ``<report>``
    root). A missing attribute should never happen with a well-formed
    report and surfaces as ``None`` so the caller can fail loud.
    """
    raw = validation_report.attrib.get("isCompliant")
    if raw == "true":
        return True
    if raw == "false":
        return False
    return None


def _rule_id(rule: ET.Element) -> str:
    """Derive a stable rule id from a verapdf ``<rule>`` element.

    verapdf does not emit a single ``id`` attribute; the canonical PDF/A
    rule identifier is the pair ``(clause, testNumber)`` (e.g. clause
    ``6.1.7.1`` test ``2`` ⇒ ``6.1.7.1-2``). We render it as
    ``<clause>-<testNumber>`` so both halves of an allow-list entry
    (``rule_id:ticket_url``) and the structured ``::error::`` annotation
    pivot on the same canonical identifier.

    Falls back gracefully when one half is missing — clause-only,
    then testNumber-only, then ``"unknown"`` — so a future schema bump
    that drops one attribute does not make the entire collector
    silently classify rules as ``"unknown"``.
    """
    clause = rule.attrib.get("clause", "").strip()
    test_number = rule.attrib.get("testNumber", "").strip()
    if clause and test_number:
        return f"{clause}-{test_number}"
    if clause:
        return clause
    if test_number:
        return f"test-{test_number}"
    return "unknown"


def _collect_offences(
    validation_report: ET.Element,
    allow_ids: frozenset[str],
    strict_warnings: bool,
) -> list[_RuleOffence]:
    """Walk ``<rule>`` entries and return everything that should fail the gate.

    Operates on the inner ``<validationReport>`` returned by
    :func:`_load_report`. The verapdf MRR places ``<rule>`` elements
    flat under ``<details>`` (NOT grouped under ``<failedRules>`` /
    ``<passedRules>`` — that's a documentation myth from older verapdf
    docs); ``iter("rule")`` walks them in document order.

    A rule is an "offence" if:

    * ``status == "failed"`` (always blocks; PDF/A profiles use this for
      every non-conformance regardless of strict mode).
    * ``status == "warning"`` AND ``strict_warnings`` is on AND the
      rule_id is not in ``allow_ids``. The standard PDF/A profiles in
      verapdf 1.28.x rarely emit ``"warning"`` (it shows up mostly in
      policy / WCAG profiles) — but we handle it defensively because a
      future verapdf release could add warning-tier checks to PDF/A.

    Unknown statuses surface as ``"unknown:<status>"`` offences — better
    to fail loudly than to silently mis-classify a future verapdf
    release that adds (e.g.) ``"skipped"`` or ``"manual"``.
    """
    offences: list[_RuleOffence] = []
    for rule in validation_report.iter("rule"):
        status = rule.attrib.get("status", "").strip().lower()
        rule_id = _rule_id(rule)
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
        validation_report = _load_report(args.report)
    except SystemExit as exc:
        sys.stderr.write(f"{exc}\n")
        return 1

    verdict = _is_compliant(validation_report)
    if verdict is None:
        sys.stderr.write(
            "::error::verapdf XML report does not carry an isCompliant verdict\n"
        )
        return 1

    allow_ids = frozenset(entry.rule_id for entry in allow)
    offences = _collect_offences(
        validation_report, allow_ids, args.strict_warnings,
    )

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
