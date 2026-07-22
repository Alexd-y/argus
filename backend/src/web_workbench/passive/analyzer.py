"""Passive HTTP audit over captured traffic (WB-P5a) — native, offline, no send.

This is the workbench's *passive* scanner: it reasons over already-captured
request/response pairs (proxy/repeater history) and never issues a request. It is
deliberately distinct from — and does not duplicate — the active Nuclei pipeline
(``nuclei_va_adapter``); active/template scanning stays there (SI: extend, not
duplicate).

Findings reuse the platform taxonomy (:class:`~src.pipeline.contracts.finding_dto.
FindingCategory` / ``ConfidenceLevel``) so the WB-P5b bridge can lift them into
``FindingDTO`` without a bespoke mapping. Passive findings are low-confidence by
nature (``SUSPECTED`` / ``LIKELY``) — they flag hygiene issues and candidates, not
proven exploits. Evidence snippets are short and never echo cookie values/secrets.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import parse_qsl, urlsplit

from src.pipeline.contracts.finding_dto import ConfidenceLevel, FindingCategory
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse

#: Minimum reflected value length to consider (avoids noise from tiny tokens).
_MIN_REFLECT_LEN = 4
#: Cap on reflected-input findings per response (noise guard).
_MAX_REFLECT_FINDINGS = 20


class PassiveSeverity(StrEnum):
    """Coarse severity for passive hygiene findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class PassiveFinding:
    """One passive audit result. ``evidence`` is a short, secret-free snippet."""

    code: str
    category: FindingCategory
    confidence: ConfidenceLevel
    severity: PassiveSeverity
    title: str
    detail: str
    evidence: str
    location: str

    def dedup_key(self) -> tuple[str, str, str]:
        return (self.code, self.location, self.evidence)


def _all_headers(response: NormalizedResponse, name: str) -> list[str]:
    lowered = name.lower()
    return [value for key, value in response.headers if key.lower() == lowered]


def _first_header(response: NormalizedResponse, name: str) -> str | None:
    values = _all_headers(response, name)
    return values[0] if values else None


def _location(request: NormalizedRequest) -> str:
    return f"{request.method} {request.target}"


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_security_headers(
    request: NormalizedRequest, response: NormalizedResponse, *, secure: bool
) -> list[PassiveFinding]:
    """Flag missing/weak response security headers (clickjacking, sniffing, TLS)."""
    findings: list[PassiveFinding] = []
    loc = _location(request)

    def _missing(header: str) -> bool:
        return _first_header(response, header) is None

    if secure and _missing("Strict-Transport-Security"):
        findings.append(
            PassiveFinding(
                code="missing-hsts",
                category=FindingCategory.MISCONFIG,
                confidence=ConfidenceLevel.LIKELY,
                severity=PassiveSeverity.LOW,
                title="Missing HSTS header",
                detail="HTTPS response has no Strict-Transport-Security header.",
                evidence="Strict-Transport-Security",
                location=loc,
            )
        )

    xcto = _first_header(response, "X-Content-Type-Options")
    if xcto is None or xcto.strip().lower() != "nosniff":
        findings.append(
            PassiveFinding(
                code="missing-nosniff",
                category=FindingCategory.MISCONFIG,
                confidence=ConfidenceLevel.LIKELY,
                severity=PassiveSeverity.INFO,
                title="Missing X-Content-Type-Options: nosniff",
                detail="Response allows MIME-type sniffing.",
                evidence="X-Content-Type-Options",
                location=loc,
            )
        )

    csp = _first_header(response, "Content-Security-Policy")
    if csp is None:
        findings.append(
            PassiveFinding(
                code="missing-csp",
                category=FindingCategory.MISCONFIG,
                confidence=ConfidenceLevel.SUSPECTED,
                severity=PassiveSeverity.LOW,
                title="Missing Content-Security-Policy",
                detail="Response has no Content-Security-Policy header.",
                evidence="Content-Security-Policy",
                location=loc,
            )
        )

    xfo_missing = _missing("X-Frame-Options")
    csp_has_frame_ancestors = csp is not None and "frame-ancestors" in csp.lower()
    if xfo_missing and not csp_has_frame_ancestors:
        findings.append(
            PassiveFinding(
                code="clickjacking",
                category=FindingCategory.MISCONFIG,
                confidence=ConfidenceLevel.SUSPECTED,
                severity=PassiveSeverity.LOW,
                title="No clickjacking protection",
                detail="No X-Frame-Options and no CSP frame-ancestors directive.",
                evidence="X-Frame-Options",
                location=loc,
            )
        )

    return findings


def check_cookies(
    request: NormalizedRequest, response: NormalizedResponse, *, secure: bool
) -> list[PassiveFinding]:
    """Flag Set-Cookie attributes that weaken session security."""
    findings: list[PassiveFinding] = []
    loc = _location(request)
    for raw_cookie in _all_headers(response, "Set-Cookie"):
        name = raw_cookie.split("=", 1)[0].strip()
        attrs = {seg.strip().lower() for seg in raw_cookie.split(";")[1:]}
        attr_text = raw_cookie.lower()

        if secure and "secure" not in attrs:
            findings.append(
                PassiveFinding(
                    code="cookie-missing-secure",
                    category=FindingCategory.MISCONFIG,
                    confidence=ConfidenceLevel.LIKELY,
                    severity=PassiveSeverity.MEDIUM,
                    title="Cookie without Secure flag",
                    detail="Cookie set over HTTPS without the Secure attribute.",
                    evidence=name,
                    location=loc,
                )
            )
        if "httponly" not in attrs:
            findings.append(
                PassiveFinding(
                    code="cookie-missing-httponly",
                    category=FindingCategory.MISCONFIG,
                    confidence=ConfidenceLevel.LIKELY,
                    severity=PassiveSeverity.LOW,
                    title="Cookie without HttpOnly flag",
                    detail="Cookie accessible to JavaScript (no HttpOnly).",
                    evidence=name,
                    location=loc,
                )
            )
        if "samesite" not in attr_text:
            findings.append(
                PassiveFinding(
                    code="cookie-missing-samesite",
                    category=FindingCategory.CSRF,
                    confidence=ConfidenceLevel.SUSPECTED,
                    severity=PassiveSeverity.LOW,
                    title="Cookie without SameSite attribute",
                    detail="Cookie has no SameSite attribute (CSRF exposure).",
                    evidence=name,
                    location=loc,
                )
            )
    return findings


def check_info_disclosure(
    request: NormalizedRequest, response: NormalizedResponse
) -> list[PassiveFinding]:
    """Flag version-banner headers that leak stack information."""
    findings: list[PassiveFinding] = []
    loc = _location(request)
    for header in ("Server", "X-Powered-By", "X-AspNet-Version"):
        value = _first_header(response, header)
        if value and any(ch.isdigit() for ch in value):
            findings.append(
                PassiveFinding(
                    code="version-disclosure",
                    category=FindingCategory.INFO,
                    confidence=ConfidenceLevel.LIKELY,
                    severity=PassiveSeverity.INFO,
                    title=f"Version disclosure in {header}",
                    detail=f"{header} header reveals a software version.",
                    evidence=f"{header}: {value[:80]}",
                    location=loc,
                )
            )
    return findings


def check_cors(request: NormalizedRequest, response: NormalizedResponse) -> list[PassiveFinding]:
    """Flag the classic wildcard-origin-with-credentials CORS misconfiguration."""
    acao = _first_header(response, "Access-Control-Allow-Origin")
    acac = _first_header(response, "Access-Control-Allow-Credentials")
    if acao == "*" and acac is not None and acac.strip().lower() == "true":
        return [
            PassiveFinding(
                code="cors-wildcard-credentials",
                category=FindingCategory.CORS,
                confidence=ConfidenceLevel.LIKELY,
                severity=PassiveSeverity.MEDIUM,
                title="CORS wildcard origin with credentials",
                detail="Access-Control-Allow-Origin: * with Allow-Credentials: true.",
                evidence="Access-Control-Allow-Origin: *",
                location=_location(request),
            )
        ]
    return []


def check_reflected_input(
    request: NormalizedRequest,
    response_body: bytes,
    *,
    request_body: bytes = b"",
) -> list[PassiveFinding]:
    """Flag request parameter values reflected verbatim in the response body.

    Passive XSS/injection *candidate* only (``SUSPECTED``) — reflection is not
    proof of exploitability; the active scanner/verifier confirms it downstream.
    """
    body_text = response_body.decode("latin-1")
    params: list[tuple[str, str]] = []
    query = urlsplit(request.target).query
    if query:
        params.extend(parse_qsl(query, keep_blank_values=True))
    content_type = request.header("Content-Type") or ""
    if "application/x-www-form-urlencoded" in content_type.lower() and request_body:
        params.extend(parse_qsl(request_body.decode("latin-1"), keep_blank_values=True))

    findings: list[PassiveFinding] = []
    seen_params: set[str] = set()
    loc = _location(request)
    for name, value in params:
        if len(value) < _MIN_REFLECT_LEN or name in seen_params:
            continue
        if value in body_text:
            seen_params.add(name)
            findings.append(
                PassiveFinding(
                    code="reflected-input",
                    category=FindingCategory.XSS,
                    confidence=ConfidenceLevel.SUSPECTED,
                    severity=PassiveSeverity.LOW,
                    title="Reflected parameter value",
                    detail="A request parameter value is reflected verbatim in the response body.",
                    evidence=name,
                    location=loc,
                )
            )
            if len(findings) >= _MAX_REFLECT_FINDINGS:
                break
    return findings


def analyze(
    request: NormalizedRequest,
    response: NormalizedResponse,
    response_body: bytes,
    *,
    secure: bool,
    request_body: bytes = b"",
) -> list[PassiveFinding]:
    """Run every passive check over one captured exchange, deduplicated."""
    raw_findings: list[PassiveFinding] = []
    raw_findings.extend(check_security_headers(request, response, secure=secure))
    raw_findings.extend(check_cookies(request, response, secure=secure))
    raw_findings.extend(check_info_disclosure(request, response))
    raw_findings.extend(check_cors(request, response))
    raw_findings.extend(check_reflected_input(request, response_body, request_body=request_body))

    seen: set[tuple[str, str, str]] = set()
    deduped: list[PassiveFinding] = []
    for finding in raw_findings:
        marker = finding.dedup_key()
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(finding)
    return deduped


__all__ = [
    "PassiveFinding",
    "PassiveSeverity",
    "analyze",
    "check_cookies",
    "check_cors",
    "check_info_disclosure",
    "check_reflected_input",
    "check_security_headers",
]
