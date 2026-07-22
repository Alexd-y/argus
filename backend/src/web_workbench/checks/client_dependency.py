"""Client-side dependency scanner — vulnerable JS libraries (WB-P7, pure).

A Retire.js-style *behavioral* analogue (not a copy of Retire.js code or its
database): given captured JavaScript content and/or a script URL, it identifies
the library + version via signatures and flags versions that fall inside a
known-vulnerable range. It is **pure** (no I/O/network/DB) and offline-testable.

This does not duplicate the server-side SCA / Stage-3 dependency gate
(``recon/vulnerability_analysis/dependency_check.py``) nor the JS endpoint
extractor (``recon/recon_js_analysis.py``) — it is client-dependency (frontend
library) vulnerability matching, a distinct concern.

PROVENANCE: the signature/advisory dataset below is an original, small curated
set compiled from **public NVD/CVE advisories** (each entry cites its CVE id).
It is intentionally conservative; extend it via the same structured entries.

Findings map to :class:`~src.pipeline.contracts.finding_dto.FindingDTO`
(category ``SUPPLY_CHAIN``) through :func:`dependency_findings_to_dtos`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID, uuid4

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceTier,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    RemediationDTO,
)

_MAX_EVIDENCE = 120


class DependencySeverity(StrEnum):
    """Advisory severity for a vulnerable dependency."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Representative CVSS v3.1 (vector, score) per advisory severity.
_SEVERITY_CVSS: dict[DependencySeverity, tuple[str, float]] = {
    DependencySeverity.LOW: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    DependencySeverity.MEDIUM: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),
    DependencySeverity.HIGH: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    DependencySeverity.CRITICAL: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
}


@dataclass(frozen=True)
class VulnRange:
    """A known-vulnerable version range for a library.

    A detected ``version`` is vulnerable when
    ``at_or_above <= version < below`` (either bound may be open).
    """

    below: str | None
    at_or_above: str | None
    identifiers: tuple[str, ...]
    severity: DependencySeverity
    cwe: int
    summary: str


@dataclass(frozen=True)
class LibrarySignature:
    """Detection signature + vulnerability ranges for one library."""

    name: str
    uri_regexes: tuple[re.Pattern[str], ...]
    content_regexes: tuple[re.Pattern[str], ...]
    vulns: tuple[VulnRange, ...]
    provenance: str


@dataclass(frozen=True)
class DetectedLibrary:
    """A library + version identified in captured JS/URL."""

    name: str
    version: str
    source: str  # "uri" | "content"
    evidence: str


@dataclass(frozen=True)
class DependencyFinding:
    """A vulnerable client dependency (secret-free evidence)."""

    library: str
    version: str
    identifiers: tuple[str, ...]
    severity: DependencySeverity
    cwe: int
    summary: str
    source: str
    evidence: str
    provenance: str


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# --- Curated signature/advisory dataset (public CVE advisories) -------------
_SIGNATURES: tuple[LibrarySignature, ...] = (
    LibrarySignature(
        name="jquery",
        uri_regexes=(_c(r"jquery[.\-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js"),),
        content_regexes=(
            _c(r"jQuery JavaScript Library v(\d+\.\d+\.\d+)"),
            _c(r"/\*!? jQuery v(\d+\.\d+\.\d+)"),
        ),
        vulns=(
            VulnRange(
                below="1.9.0",
                at_or_above=None,
                identifiers=("CVE-2012-6708",),
                severity=DependencySeverity.MEDIUM,
                cwe=79,
                summary="jQuery <1.9.0 selector interpreted as HTML (XSS).",
            ),
            VulnRange(
                below="3.0.0",
                at_or_above=None,
                identifiers=("CVE-2015-9251",),
                severity=DependencySeverity.MEDIUM,
                cwe=79,
                summary="jQuery <3.0.0 cross-domain ajax executes text/javascript (XSS).",
            ),
            VulnRange(
                below="3.5.0",
                at_or_above="1.2.0",
                identifiers=("CVE-2020-11022", "CVE-2020-11023"),
                severity=DependencySeverity.MEDIUM,
                cwe=79,
                summary="jQuery >=1.2 <3.5.0 htmlPrefilter regex XSS.",
            ),
        ),
        provenance="curated from public NVD advisories (CVE-2012-6708/2015-9251/2020-11022/11023)",
    ),
    LibrarySignature(
        name="bootstrap",
        uri_regexes=(_c(r"bootstrap[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"),),
        content_regexes=(_c(r"Bootstrap v(\d+\.\d+\.\d+)"),),
        vulns=(
            VulnRange(
                below="3.4.1",
                at_or_above=None,
                identifiers=("CVE-2019-8331",),
                severity=DependencySeverity.MEDIUM,
                cwe=79,
                summary="Bootstrap <3.4.1 XSS in tooltip/popover data-template.",
            ),
            VulnRange(
                below="4.3.1",
                at_or_above="4.0.0",
                identifiers=("CVE-2019-8331",),
                severity=DependencySeverity.MEDIUM,
                cwe=79,
                summary="Bootstrap >=4.0 <4.3.1 XSS in tooltip/popover data-template.",
            ),
        ),
        provenance="curated from public NVD advisory (CVE-2019-8331)",
    ),
    LibrarySignature(
        name="lodash",
        uri_regexes=(_c(r"lodash[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"),),
        content_regexes=(_c(r"lodash(?:\.js)? (\d+\.\d+\.\d+)"),),
        vulns=(
            VulnRange(
                below="4.17.12",
                at_or_above=None,
                identifiers=("CVE-2019-10744",),
                severity=DependencySeverity.HIGH,
                cwe=1321,
                summary="lodash <4.17.12 prototype pollution via defaultsDeep.",
            ),
            VulnRange(
                below="4.17.21",
                at_or_above=None,
                identifiers=("CVE-2020-8203",),
                severity=DependencySeverity.HIGH,
                cwe=1321,
                summary="lodash <4.17.21 prototype pollution via zipObjectDeep/set.",
            ),
        ),
        provenance="curated from public NVD advisories (CVE-2019-10744/2020-8203)",
    ),
    LibrarySignature(
        name="angularjs",
        uri_regexes=(_c(r"angular[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"),),
        content_regexes=(_c(r"AngularJS v(\d+\.\d+\.\d+)"),),
        vulns=(
            VulnRange(
                below="1.8.0",
                at_or_above=None,
                identifiers=("CVE-2020-7676",),
                severity=DependencySeverity.MEDIUM,
                cwe=79,
                summary="AngularJS <1.8.0 improper sanitization allows XSS.",
            ),
        ),
        provenance="curated from public NVD advisory (CVE-2020-7676)",
    ),
    LibrarySignature(
        name="moment",
        uri_regexes=(_c(r"moment[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"),),
        content_regexes=(_c(r"//!\s*moment\.js.*?(\d+\.\d+\.\d+)"),),
        vulns=(
            VulnRange(
                below="2.29.4",
                at_or_above=None,
                identifiers=("CVE-2022-31129",),
                severity=DependencySeverity.HIGH,
                cwe=1333,
                summary="moment <2.29.4 ReDoS in string-to-date parsing.",
            ),
        ),
        provenance="curated from public NVD advisory (CVE-2022-31129)",
    ),
    LibrarySignature(
        name="handlebars",
        uri_regexes=(_c(r"handlebars[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"),),
        content_regexes=(_c(r"Handlebars.*?v(\d+\.\d+\.\d+)"),),
        vulns=(
            VulnRange(
                below="4.7.7",
                at_or_above=None,
                identifiers=("CVE-2021-23369",),
                severity=DependencySeverity.HIGH,
                cwe=1321,
                summary="handlebars <4.7.7 prototype pollution / RCE via compile.",
            ),
        ),
        provenance="curated from public NVD advisory (CVE-2021-23369)",
    ),
)


def _parse_version(version: str) -> tuple[int, ...]:
    core = version.split("-", 1)[0].split("+", 1)[0]
    parts: list[int] = []
    for segment in core.split("."):
        if segment.isdigit():
            parts.append(int(segment))
        else:
            break
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    va, vb = _parse_version(a), _parse_version(b)
    width = max(len(va), len(vb))
    va += (0,) * (width - len(va))
    vb += (0,) * (width - len(vb))
    if va < vb:
        return -1
    return 1 if va > vb else 0


def _in_range(version: str, vr: VulnRange) -> bool:
    if vr.at_or_above is not None and _cmp(version, vr.at_or_above) < 0:
        return False
    if vr.below is not None and _cmp(version, vr.below) >= 0:
        return False
    return True


def detect_libraries(*, content: str = "", uri: str = "") -> list[DetectedLibrary]:
    """Identify libraries + versions from a script URL and/or its content."""
    detected: list[DetectedLibrary] = []
    seen: set[tuple[str, str, str]] = set()
    for sig in _SIGNATURES:
        if uri:
            for pattern in sig.uri_regexes:
                match = pattern.search(uri)
                if match:
                    key = (sig.name, match.group(1), "uri")
                    if key not in seen:
                        seen.add(key)
                        detected.append(
                            DetectedLibrary(sig.name, match.group(1), "uri", uri[:_MAX_EVIDENCE])
                        )
        if content:
            for pattern in sig.content_regexes:
                match = pattern.search(content)
                if match:
                    key = (sig.name, match.group(1), "content")
                    if key not in seen:
                        seen.add(key)
                        detected.append(
                            DetectedLibrary(
                                sig.name,
                                match.group(1),
                                "content",
                                match.group(0)[:_MAX_EVIDENCE],
                            )
                        )
    return detected


def _signature_for(name: str) -> LibrarySignature:
    for sig in _SIGNATURES:
        if sig.name == name:
            return sig
    raise KeyError(name)  # pragma: no cover - detections only use known names


def match_vulnerabilities(library: DetectedLibrary) -> list[DependencyFinding]:
    """Return every advisory range the detected version falls inside."""
    sig = _signature_for(library.name)
    findings: list[DependencyFinding] = []
    for vr in sig.vulns:
        if _in_range(library.version, vr):
            findings.append(
                DependencyFinding(
                    library=library.name,
                    version=library.version,
                    identifiers=vr.identifiers,
                    severity=vr.severity,
                    cwe=vr.cwe,
                    summary=vr.summary,
                    source=library.source,
                    evidence=library.evidence,
                    provenance=sig.provenance,
                )
            )
    return findings


def scan(*, content: str = "", uri: str = "") -> list[DependencyFinding]:
    """Detect libraries then match advisories, deduplicated by (lib, ver, CVEs)."""
    findings: list[DependencyFinding] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for library in detect_libraries(content=content, uri=uri):
        for finding in match_vulnerabilities(library):
            key = (finding.library, finding.version, finding.identifiers)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    return findings


def _cvss_for(severity: DependencySeverity) -> tuple[str, float]:
    return _SEVERITY_CVSS[severity]


def dependency_finding_to_dto(
    finding: DependencyFinding,
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
    finding_id: UUID | None = None,
) -> FindingDTO:
    """Project one :class:`DependencyFinding` onto a ``FindingDTO`` (SUPPLY_CHAIN)."""
    vector, score = _cvss_for(finding.severity)
    ids = ", ".join(finding.identifiers)
    summary = (
        f"{finding.library} {finding.version}: {finding.summary} "
        f"[{ids}] (source: {finding.source}; {finding.provenance})"
    )
    return FindingDTO(
        id=finding_id or uuid4(),
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        tool_run_id=tool_run_id,
        category=FindingCategory.SUPPLY_CHAIN,
        cwe=[finding.cwe],
        cvss_v3_vector=vector,
        cvss_v3_score=score,
        confidence=ConfidenceLevel.LIKELY,
        status=FindingStatus.NEW,
        evidence_tier=EvidenceTier.INFORMATIONAL,
        remediation=RemediationDTO(summary=summary[:2000]),
    )


def dependency_findings_to_dtos(
    findings: list[DependencyFinding],
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
) -> list[FindingDTO]:
    """Project a batch of dependency findings (fresh UUID per finding)."""
    return [
        dependency_finding_to_dto(
            finding,
            tenant_id=tenant_id,
            scan_id=scan_id,
            asset_id=asset_id,
            tool_run_id=tool_run_id,
        )
        for finding in findings
    ]


__all__ = [
    "DependencyFinding",
    "DependencySeverity",
    "DetectedLibrary",
    "LibrarySignature",
    "VulnRange",
    "dependency_finding_to_dto",
    "dependency_findings_to_dtos",
    "detect_libraries",
    "match_vulnerabilities",
    "scan",
]
