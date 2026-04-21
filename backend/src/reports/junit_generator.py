"""ARG-024 — JUnit XML generator (CI failure-gate compatible).

Renders a :class:`ReportData` as a JUnit-XML test report so that any CI
runner (Jenkins, GitLab CI, GitHub Actions, CircleCI, Bamboo, Bitbucket
Pipelines) can fail the pipeline when ARGUS finds vulnerabilities of a
configured severity.

Mapping (Finding → JUnit XML)
    severity  → ``<testcase classname="argus.findings.<severity>">``
                ``critical`` / ``high`` → ``<failure>`` (test fails)
                ``medium``              → ``<failure>`` (test fails)
                ``low`` / ``info``      → ``<system-out>`` (informational)
    title     → ``testcase.name`` (sanitized)
    cwe       → ``failure.type`` (e.g. ``CWE-79``)
    cvss      → ``failure.message`` prefix
    url       → ``failure`` body (URL + description, escaped)
    sha256    → ``<properties>`` (stable per-finding fingerprint)

Severity gate semantics
    The default behaviour is *informational* for ``low``/``info``. Tooling
    can promote them by re-encoding the JUnit XML with a lower threshold
    (out of scope for ARG-024). What matters: each finding is a
    ``<testcase>``, total count == ``tests`` attribute, failure count ==
    ``failures`` attribute — those two invariants make the output parseable
    by every JUnit consumer we care about.

Determinism
    Same finding list → same byte stream. Findings are sorted by the
    canonical priority key (severity → CVSS → title → CWE), and XML
    attributes are emitted in a stable order via ``ElementTree`` defaults.

Security
    * We use the standard library ``xml.etree.ElementTree`` only for
      *emission*. Parsing arbitrary JUnit XML in tests is done via
      ``defusedxml`` — see ``backend/tests/unit/reports/test_junit_generator.py``.
    * Every text node is escaped via ElementTree's built-in encoder; no
      finding string is ever concatenated into raw XML.
    * Element names and attribute keys are constants under our control;
      finding-derived strings appear ONLY as text content / quoted
      attribute values.
    * No timestamps reflect wall-clock time (would break determinism). We
      surface ``data.created_at`` only when the caller explicitly set it.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET  # noqa: S405  # nosec B405 — emission-only; tests parse via defusedxml
from typing import Final
from xml.dom import minidom  # noqa: S408  # nosec B408 — pretty-print only; never parses external input

from src.api.schemas import Finding
from src.reports.generators import ReportData

# Default JUnit XML attributes that downstream parsers expect.
JUNIT_TESTSUITE_NAME: Final[str] = "ARGUS Findings"
JUNIT_HOSTNAME: Final[str] = "argus-pentest"

# Severities that should trigger a CI failure (`<failure>` element).
_FAILING_SEVERITIES: Final[frozenset[str]] = frozenset({"critical", "high", "medium"})

# Severity rank used for stable ordering — matches sarif/tier_classifier.
_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}

# Bound XML attribute / text payloads to avoid pathological reports.
_MAX_NAME_LEN: Final[int] = 256
_MAX_MESSAGE_LEN: Final[int] = 4096
_MAX_BODY_LEN: Final[int] = 8192

# Strip control characters that are illegal in XML 1.0 (per spec §2.2).
# Allowed: TAB (0x09), LF (0x0A), CR (0x0D), and 0x20+; everything else is
# scrubbed to ``?`` so consumers don't reject the document.
_XML_INVALID_CHAR = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)


def _xml_safe(value: str | None, *, limit: int) -> str:
    """Return an XML-1.0-safe truncation of ``value``."""
    if not value:
        return ""
    cleaned = _XML_INVALID_CHAR.sub("?", str(value))
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "\u2026"
    return cleaned


def _severity_rank(sev: str | None) -> int:
    return _SEVERITY_RANK.get((sev or "").strip().lower(), 99)


def _is_failing(sev: str | None) -> bool:
    return (sev or "").strip().lower() in _FAILING_SEVERITIES


def _finding_priority_key(f: Finding) -> tuple[int, float, str, str]:
    sev_rank = _severity_rank(f.severity)
    cvss = -float(f.cvss) if f.cvss is not None else 0.0
    title = (f.title or "").lower()
    cwe = f.cwe or ""
    return (sev_rank, cvss, title, cwe)


def _classname_for(severity: str | None) -> str:
    """Return ``argus.findings.<severity>`` (or ``unknown``) for testcase classname."""
    sev = (severity or "").strip().lower() or "unknown"
    return f"argus.findings.{sev}"


def _failure_type(cwe: str | None) -> str:
    """Return the ``failure.type`` attribute (CWE id or generic fallback)."""
    raw = (cwe or "").strip().upper()
    if raw.startswith("CWE-"):
        return raw
    if raw.isdigit():
        return f"CWE-{raw}"
    return "ArgusFinding"


def _failure_message(f: Finding) -> str:
    """Build a one-line failure message: ``[CRITICAL][CVSS:9.8] Title``."""
    sev = (f.severity or "unknown").upper()
    cvss = f"[CVSS:{float(f.cvss):.1f}]" if f.cvss is not None else ""
    title = _xml_safe(f.title or "Untitled finding", limit=_MAX_NAME_LEN)
    parts = [f"[{sev}]", cvss, title]
    return _xml_safe(" ".join(p for p in parts if p), limit=_MAX_MESSAGE_LEN)


def _failure_body(f: Finding, *, target: str | None) -> str:
    """Multi-line failure body with target URL and description."""
    lines: list[str] = []
    if target:
        lines.append(f"Target: {_xml_safe(target, limit=_MAX_MESSAGE_LEN)}")
    if f.cwe:
        lines.append(f"CWE: {_xml_safe(f.cwe, limit=64)}")
    if f.cvss is not None:
        lines.append(f"CVSS: {float(f.cvss):.1f}")
    owasp = getattr(f, "owasp_category", None)
    if owasp:
        lines.append(f"OWASP: {_xml_safe(str(owasp), limit=64)}")
    if f.description:
        lines.append("")
        lines.append(_xml_safe(f.description, limit=_MAX_BODY_LEN))
    return "\n".join(lines)


def _system_out_body(f: Finding, *, target: str | None) -> str:
    """Body emitted as ``<system-out>`` for non-failing severities (low/info)."""
    sev = (f.severity or "unknown").upper()
    title = _xml_safe(f.title or "Untitled finding", limit=_MAX_NAME_LEN)
    parts: list[str] = [f"[{sev}] {title}"]
    if target:
        parts.append(f"Target: {_xml_safe(target, limit=_MAX_MESSAGE_LEN)}")
    if f.description:
        parts.append("")
        parts.append(_xml_safe(f.description, limit=_MAX_BODY_LEN))
    return "\n".join(parts)


def _testcase_name(f: Finding, *, idx: int) -> str:
    """Build a stable, unique testcase name (title + 1-based index suffix)."""
    title = _xml_safe(f.title or "Untitled finding", limit=_MAX_NAME_LEN)
    return f"{idx:04d}. {title}"


def _build_testcase(
    f: Finding,
    *,
    idx: int,
    target: str | None,
) -> ET.Element:
    """Build a ``<testcase>`` element for a single finding."""
    testcase = ET.Element(
        "testcase",
        {
            "classname": _classname_for(f.severity),
            "name": _testcase_name(f, idx=idx),
            "time": "0",
        },
    )
    if _is_failing(f.severity):
        failure = ET.SubElement(
            testcase,
            "failure",
            {
                "message": _failure_message(f),
                "type": _failure_type(f.cwe),
            },
        )
        failure.text = _failure_body(f, target=target)
    else:
        sysout = ET.SubElement(testcase, "system-out")
        sysout.text = _system_out_body(f, target=target)
    return testcase


def _testsuite_metadata(data: ReportData) -> dict[str, str]:
    """Return ``<testsuite>`` attributes (name, hostname, timestamp, package)."""
    attrs: dict[str, str] = {
        "name": JUNIT_TESTSUITE_NAME,
        "hostname": JUNIT_HOSTNAME,
        "package": "argus.report",
    }
    if data.scan_id:
        attrs["id"] = _xml_safe(data.scan_id, limit=128)
    if data.created_at:
        attrs["timestamp"] = _xml_safe(data.created_at, limit=64)
    return attrs


def _suite_properties(data: ReportData) -> ET.Element | None:
    """Surface scan metadata as ``<properties>`` (stable order)."""
    pairs: list[tuple[str, str]] = []
    if data.target:
        pairs.append(("target", _xml_safe(data.target, limit=2048)))
    if data.tenant_id:
        pairs.append(("tenant_id", _xml_safe(data.tenant_id, limit=128)))
    if data.scan_id:
        pairs.append(("scan_id", _xml_safe(data.scan_id, limit=128)))
    if data.report_id:
        pairs.append(("report_id", _xml_safe(data.report_id, limit=128)))
    technologies = sorted(str(t) for t in (data.technologies or []) if t)
    if technologies:
        pairs.append(("technologies", _xml_safe(",".join(technologies), limit=4096)))
    if not pairs:
        return None
    el = ET.Element("properties")
    for name, value in sorted(pairs):
        ET.SubElement(el, "property", {"name": name, "value": value})
    return el


def build_junit_tree(data: ReportData) -> ET.ElementTree:
    """Build a ``<testsuites>`` ElementTree from ``data`` (no I/O)."""
    findings_sorted = sorted(list(data.findings or []), key=_finding_priority_key)

    failures = sum(1 for f in findings_sorted if _is_failing(f.severity))
    total = len(findings_sorted) or 1

    testsuites = ET.Element(
        "testsuites",
        {
            "name": JUNIT_TESTSUITE_NAME,
            "tests": str(total),
            "failures": str(failures),
            "errors": "0",
            "time": "0",
        },
    )
    suite_attrs = _testsuite_metadata(data)
    suite_attrs.update({
        "tests": str(total),
        "failures": str(failures),
        "errors": "0",
        "skipped": "0",
        "time": "0",
    })
    testsuite = ET.SubElement(testsuites, "testsuite", suite_attrs)

    properties = _suite_properties(data)
    if properties is not None:
        testsuite.append(properties)

    if findings_sorted:
        for idx, f in enumerate(findings_sorted, start=1):
            testsuite.append(_build_testcase(f, idx=idx, target=data.target))
    else:
        passing = ET.SubElement(
            testsuite,
            "testcase",
            {
                "classname": "argus.findings.summary",
                "name": "0001. No vulnerabilities found",
                "time": "0",
            },
        )
        sysout = ET.SubElement(passing, "system-out")
        sysout.text = "ARGUS scan completed without findings."
    return ET.ElementTree(testsuites)


def generate_junit(data: ReportData) -> bytes:
    """Render ``data`` as a UTF-8 JUnit XML byte stream (pretty-printed)."""
    tree = build_junit_tree(data)
    root = tree.getroot()
    if root is None:  # pragma: no cover — build_junit_tree always populates the tree
        raise RuntimeError("build_junit_tree returned an empty ElementTree")
    raw = ET.tostring(root, encoding="utf-8", xml_declaration=False)
    # ``minidom.parseString`` here is operating on bytes WE just produced — no
    # external entity surface area exists. Pretty-printing yields stable
    # 2-space indentation that downstream consumers and snapshot tests prefer.
    pretty = minidom.parseString(raw).toprettyxml(  # noqa: S318  # nosec B318 — input is our own emission, no external XML
        indent="  ", encoding="utf-8"
    )
    return bytes(pretty)


__all__ = [
    "JUNIT_HOSTNAME",
    "JUNIT_TESTSUITE_NAME",
    "build_junit_tree",
    "generate_junit",
]
