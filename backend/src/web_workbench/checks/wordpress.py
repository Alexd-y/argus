"""WordPress passive analyzer (WB-P7d, pure).

Reviews a captured request/response pair (proxy/repeater history) for WordPress
fingerprint, version disclosure, and common CMS misconfigurations — **without
sending anything**. It is a behavioural analogue of the well-known "wpscan"-style
passive checks (not a copy of their code or databases): every signal is derived
from markers already present in the captured exchange.

Signals (all secret-free — evidence is a marker/endpoint, never a leaked value):

* **Fingerprint** — ``/wp-content/`` / ``/wp-includes/`` references, the
  ``X-Pingback`` header, the ``api.w.org`` REST link, or a WordPress
  ``Set-Cookie`` name identify the platform.
* **Version disclosure** — the ``<meta name="generator">`` tag, the feed
  ``<generator>`` element, or ``readme.html`` leak the core version.
* **User enumeration** — the ``/wp-json/wp/v2/users`` REST route or an
  ``?author=<id>`` → ``/author/<slug>/`` redirect expose account slugs.
* **xmlrpc enabled** — ``xmlrpc.php`` answering (405 marker) is a brute-force /
  SSRF amplification surface.
* **Secret leak** — an accessible ``wp-content/debug.log`` (HTTP 200).
* **Directory listing** — an autoindex under ``wp-content``/``wp-includes``.

Pure (no I/O/network/DB), offline-testable. Findings map to
:class:`~src.pipeline.contracts.finding_dto.FindingDTO` through
:func:`wordpress_findings_to_dtos`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceTier,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    RemediationDTO,
)
from src.web_workbench.checks.severity import CheckSeverity, cvss_for
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse

#: Response body scanned is capped (noise / DoS guard).
_MAX_BODY_SCAN = 262_144

# CWE identifiers used by the WordPress checks.
_CWE_INFO_EXPOSURE = 200  # Exposure of Sensitive Information
_CWE_USER_ENUM = 204  # Observable Response Discrepancy (enumeration)
_CWE_MISCONFIG = 16  # Configuration
_CWE_LOG_LEAK = 532  # Insertion of Sensitive Information into Log File
_CWE_DIR_LISTING = 548  # Exposure of Information Through Directory Listing

_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([0-9][0-9.]*)?""",
    re.IGNORECASE,
)
_FEED_GENERATOR_RE = re.compile(
    r"<generator>https?://wordpress\.org/\?v=([0-9][0-9.]*)</generator>", re.IGNORECASE
)
_README_VERSION_RE = re.compile(r"\bVersion\s+([0-9][0-9.]*)", re.IGNORECASE)
_USERS_JSON_RE = re.compile(r'"slug"\s*:', re.IGNORECASE)


@dataclass(frozen=True)
class WordpressFinding:
    """A WordPress passive signal (secret-free evidence)."""

    code: str
    category: FindingCategory
    severity: CheckSeverity
    confidence: ConfidenceLevel
    cwe: int
    title: str
    detail: str
    evidence: str
    location: str


def _body_text(response_body: bytes) -> str:
    return response_body[:_MAX_BODY_SCAN].decode("latin-1", errors="replace")


def _path(request: NormalizedRequest) -> str:
    return urlsplit(request.target).path.lower()


def _query(request: NormalizedRequest) -> str:
    return urlsplit(request.target).query


def detect_fingerprint(
    request: NormalizedRequest, response: NormalizedResponse, body_text: str
) -> str | None:
    """Return a fingerprint marker if the exchange looks like WordPress, else ``None``."""
    if response.header("X-Pingback"):
        return "X-Pingback header"
    link = response.header("Link") or ""
    if "api.w.org" in link:
        return "Link: rel=api.w.org"
    set_cookie = response.header("Set-Cookie") or ""
    if re.search(r"\b(wordpress_|wp-settings)", set_cookie, re.IGNORECASE):
        # Only the cookie *name* is reported — never its value.
        return "wordpress_* cookie"
    if "/wp-content/" in body_text or "/wp-includes/" in body_text:
        return "/wp-content|/wp-includes reference"
    if _GENERATOR_RE.search(body_text):
        return "generator meta = WordPress"
    return None


def detect_version(request: NormalizedRequest, body_text: str) -> tuple[str, str] | None:
    """Return ``(version, source)`` if a core version is disclosed, else ``None``."""
    match = _GENERATOR_RE.search(body_text)
    if match and match.group(1):
        return match.group(1), "generator-meta"
    match = _FEED_GENERATOR_RE.search(body_text)
    if match:
        return match.group(1), "feed-generator"
    if _path(request).endswith("/readme.html"):
        readme = _README_VERSION_RE.search(body_text)
        if readme:
            return readme.group(1), "readme.html"
    return None


def _fingerprint_findings(
    request: NormalizedRequest, response: NormalizedResponse, body_text: str
) -> list[WordpressFinding]:
    location = f"{request.method} {request.target}"
    findings: list[WordpressFinding] = []

    marker = detect_fingerprint(request, response, body_text)
    if marker:
        findings.append(
            WordpressFinding(
                code="wordpress-detected",
                category=FindingCategory.INFO,
                severity=CheckSeverity.INFO,
                confidence=ConfidenceLevel.LIKELY,
                cwe=_CWE_INFO_EXPOSURE,
                title="WordPress platform identified",
                detail="Response markers identify the site as running WordPress.",
                evidence=marker,
                location=location,
            )
        )

    version = detect_version(request, body_text)
    if version:
        ver, source = version
        findings.append(
            WordpressFinding(
                code="wordpress-version-disclosed",
                category=FindingCategory.MISCONFIG,
                severity=CheckSeverity.LOW,
                confidence=ConfidenceLevel.CONFIRMED,
                cwe=_CWE_INFO_EXPOSURE,
                title="WordPress version disclosed",
                detail=(
                    "The exact WordPress core version is exposed, easing targeted "
                    "exploitation of version-specific vulnerabilities."
                ),
                evidence=f"{ver} (via {source})",
                location=location,
            )
        )
    return findings


def _misconfig_findings(
    request: NormalizedRequest, response: NormalizedResponse, body_text: str
) -> list[WordpressFinding]:
    location = f"{request.method} {request.target}"
    path = _path(request)
    status = response.status_code
    findings: list[WordpressFinding] = []

    # User enumeration via the REST route.
    if (
        path.startswith("/wp-json/wp/v2/users")
        and status == 200
        and _USERS_JSON_RE.search(body_text)
    ):
        findings.append(
            WordpressFinding(
                code="wordpress-user-enumeration",
                category=FindingCategory.MISCONFIG,
                severity=CheckSeverity.MEDIUM,
                confidence=ConfidenceLevel.CONFIRMED,
                cwe=_CWE_USER_ENUM,
                title="WordPress user enumeration (REST)",
                detail=(
                    "The wp/v2/users REST route returns account slugs to "
                    "unauthenticated clients, aiding credential attacks."
                ),
                evidence="/wp-json/wp/v2/users",
                location=location,
            )
        )

    # User enumeration via ?author=<id> redirect to /author/<slug>/.
    if "author=" in _query(request) and status in (301, 302):
        loc = response.header("Location") or ""
        if "/author/" in loc.lower():
            findings.append(
                WordpressFinding(
                    code="wordpress-author-enumeration",
                    category=FindingCategory.MISCONFIG,
                    severity=CheckSeverity.LOW,
                    confidence=ConfidenceLevel.LIKELY,
                    cwe=_CWE_USER_ENUM,
                    title="WordPress author enumeration",
                    detail=(
                        "An ?author=<id> request redirects to /author/<slug>/, "
                        "disclosing valid account slugs."
                    ),
                    evidence="?author= -> /author/ redirect",
                    location=location,
                )
            )

    # xmlrpc.php reachable.
    if path.endswith("/xmlrpc.php") and (
        status == 405 or "XML-RPC server accepts POST requests only" in body_text
    ):
        findings.append(
            WordpressFinding(
                code="wordpress-xmlrpc-enabled",
                category=FindingCategory.MISCONFIG,
                severity=CheckSeverity.MEDIUM,
                confidence=ConfidenceLevel.CONFIRMED,
                cwe=_CWE_MISCONFIG,
                title="WordPress XML-RPC enabled",
                detail=(
                    "xmlrpc.php is reachable; it enables credential brute-force "
                    "amplification (system.multicall) and pingback SSRF."
                ),
                evidence="xmlrpc.php reachable",
                location=location,
            )
        )

    # debug.log accessible.
    if path.endswith("/wp-content/debug.log") and status == 200:
        findings.append(
            WordpressFinding(
                code="wordpress-debug-log-exposed",
                category=FindingCategory.SECRET_LEAK,
                severity=CheckSeverity.HIGH,
                confidence=ConfidenceLevel.CONFIRMED,
                cwe=_CWE_LOG_LEAK,
                title="WordPress debug.log exposed",
                detail=(
                    "wp-content/debug.log is publicly readable and may leak paths, "
                    "SQL, tokens, or PII from WP_DEBUG output."
                ),
                evidence="wp-content/debug.log (HTTP 200)",
                location=location,
            )
        )

    # Directory listing under wp-content/wp-includes.
    if status == 200 and re.search(r"Index of /wp-(content|includes)", body_text, re.IGNORECASE):
        findings.append(
            WordpressFinding(
                code="wordpress-directory-listing",
                category=FindingCategory.MISCONFIG,
                severity=CheckSeverity.MEDIUM,
                confidence=ConfidenceLevel.CONFIRMED,
                cwe=_CWE_DIR_LISTING,
                title="WordPress directory listing enabled",
                detail=(
                    "Autoindex is enabled under wp-content/wp-includes, exposing "
                    "plugin/theme files and their versions."
                ),
                evidence="autoindex under wp-content|wp-includes",
                location=location,
            )
        )
    return findings


def analyze(
    request: NormalizedRequest,
    response: NormalizedResponse,
    response_body: bytes,
) -> list[WordpressFinding]:
    """Analyze one captured exchange for WordPress signals (deduplicated by code)."""
    body_text = _body_text(response_body)
    findings = _fingerprint_findings(request, response, body_text)
    findings.extend(_misconfig_findings(request, response, body_text))

    deduped: list[WordpressFinding] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.code in seen:
            continue
        seen.add(finding.code)
        deduped.append(finding)
    return deduped


def wordpress_finding_to_dto(
    finding: WordpressFinding,
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
    finding_id: UUID | None = None,
) -> FindingDTO:
    """Project one :class:`WordpressFinding` onto a ``FindingDTO``."""
    vector, score = cvss_for(finding.severity)
    # Only response-proven signals (CONFIRMED) reach the CONFIRMED tier; inferred
    # signals (fingerprint / redirect) stay SUSPECTED.
    tier = (
        EvidenceTier.CONFIRMED
        if finding.confidence is ConfidenceLevel.CONFIRMED
        else EvidenceTier.SUSPECTED
    )
    summary = (
        f"{finding.title}: {finding.detail} "
        f"(evidence: {finding.evidence}; at {finding.location})"
    )
    return FindingDTO(
        id=finding_id or uuid4(),
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        tool_run_id=tool_run_id,
        category=finding.category,
        cwe=[finding.cwe],
        cvss_v3_vector=vector,
        cvss_v3_score=score,
        confidence=finding.confidence,
        status=FindingStatus.NEW,
        evidence_tier=tier,
        remediation=RemediationDTO(summary=summary[:2000]),
    )


def wordpress_findings_to_dtos(
    findings: list[WordpressFinding],
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
) -> list[FindingDTO]:
    """Project a batch of WordPress findings (fresh UUID per finding)."""
    return [
        wordpress_finding_to_dto(
            finding,
            tenant_id=tenant_id,
            scan_id=scan_id,
            asset_id=asset_id,
            tool_run_id=tool_run_id,
        )
        for finding in findings
    ]


__all__ = [
    "WordpressFinding",
    "analyze",
    "detect_fingerprint",
    "detect_version",
    "wordpress_finding_to_dto",
    "wordpress_findings_to_dtos",
]
