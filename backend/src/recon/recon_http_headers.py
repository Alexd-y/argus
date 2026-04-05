"""HTTP security headers collector — runs during recon phase (ARGUS-002)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_USER_AGENT = "ARGUS-Scanner/1.0 (recon; +https://github.com/argus)"
_REQUEST_TIMEOUT = 15.0


class HeaderFinding(BaseModel):
    """Individual header analysis result."""

    header: str
    present: bool
    value: str | None = None
    compliant: bool = False
    recommendation: str = ""
    severity: str = "info"


class SecurityHeadersResult(BaseModel):
    """Complete security headers analysis."""

    target: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    status_code: int | None = None
    server: str | None = None
    x_powered_by: str | None = None
    headers_found: dict[str, str] = Field(default_factory=dict)
    headers_missing: list[HeaderFinding] = Field(default_factory=list)
    headers_present: list[HeaderFinding] = Field(default_factory=list)
    all_response_headers: dict[str, str] = Field(default_factory=dict)
    score: int = 0
    findings: list[HeaderFinding] = Field(default_factory=list)
    error: str | None = None


# ── header spec registry ──────────────────────────────────────────────────────

_CRITICAL_PENALTY = 15
_IMPORTANT_PENALTY = 8
_RECOMMENDED_PENALTY = 5
_INFO_PENALTY = 2
_DISCLOSURE_PENALTY = 5


class _HeaderSpec:
    __slots__ = ("name", "severity", "penalty", "recommended_value", "check")

    def __init__(
        self,
        name: str,
        *,
        severity: str,
        penalty: int,
        recommended_value: str,
        check: Any | None = None,
    ) -> None:
        self.name = name
        self.severity = severity
        self.penalty = penalty
        self.recommended_value = recommended_value
        self.check = check


def _check_hsts(value: str) -> bool:
    v = value.lower()
    return "max-age=" in v and int(_extract_max_age(v)) >= 31536000


def _extract_max_age(hsts_value: str) -> str:
    for part in hsts_value.split(";"):
        p = part.strip()
        if p.startswith("max-age="):
            digits = p[len("max-age=") :].strip()
            return digits if digits.isdigit() else "0"
    return "0"


def _check_csp(value: str) -> bool:
    return "default-src" in value.lower() or "script-src" in value.lower()


def _check_nosniff(value: str) -> bool:
    return value.strip().lower() == "nosniff"


def _check_xfo(value: str) -> bool:
    return value.strip().upper() in ("DENY", "SAMEORIGIN")


def _check_xxss(value: str) -> bool:
    return value.strip() == "0"


def _check_referrer(value: str) -> bool:
    safe = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    return value.strip().lower() in safe


def _check_non_empty(value: str) -> bool:
    return bool(value.strip())


def _check_cache_no_store(value: str) -> bool:
    return "no-store" in value.lower()


def _check_pragma(value: str) -> bool:
    return "no-cache" in value.lower()


def _check_xpcdp(value: str) -> bool:
    return value.strip().lower() == "none"


_HEADER_SPECS: list[_HeaderSpec] = [
    _HeaderSpec(
        "strict-transport-security",
        severity="medium",
        penalty=_CRITICAL_PENALTY,
        recommended_value="max-age=31536000; includeSubDomains",
        check=_check_hsts,
    ),
    _HeaderSpec(
        "content-security-policy",
        severity="medium",
        penalty=_CRITICAL_PENALTY,
        recommended_value="default-src 'self'",
        check=_check_csp,
    ),
    _HeaderSpec(
        "x-content-type-options",
        severity="low",
        penalty=_IMPORTANT_PENALTY,
        recommended_value="nosniff",
        check=_check_nosniff,
    ),
    _HeaderSpec(
        "x-frame-options",
        severity="low",
        penalty=_IMPORTANT_PENALTY,
        recommended_value="DENY or SAMEORIGIN",
        check=_check_xfo,
    ),
    _HeaderSpec(
        "x-xss-protection",
        severity="info",
        penalty=_INFO_PENALTY,
        recommended_value="0 (deprecated; rely on CSP)",
        check=_check_xxss,
    ),
    _HeaderSpec(
        "referrer-policy",
        severity="low",
        penalty=_IMPORTANT_PENALTY,
        recommended_value="strict-origin-when-cross-origin",
        check=_check_referrer,
    ),
    _HeaderSpec(
        "permissions-policy",
        severity="low",
        penalty=_IMPORTANT_PENALTY,
        recommended_value="Restrictive policy (e.g. camera=(), microphone=())",
        check=_check_non_empty,
    ),
    _HeaderSpec(
        "cross-origin-opener-policy",
        severity="low",
        penalty=_RECOMMENDED_PENALTY,
        recommended_value="same-origin",
        check=lambda v: v.strip().lower() == "same-origin",
    ),
    _HeaderSpec(
        "cross-origin-resource-policy",
        severity="low",
        penalty=_RECOMMENDED_PENALTY,
        recommended_value="same-origin",
        check=lambda v: v.strip().lower() == "same-origin",
    ),
    _HeaderSpec(
        "cross-origin-embedder-policy",
        severity="low",
        penalty=_RECOMMENDED_PENALTY,
        recommended_value="require-corp",
        check=lambda v: v.strip().lower() == "require-corp",
    ),
    _HeaderSpec(
        "cache-control",
        severity="info",
        penalty=_INFO_PENALTY,
        recommended_value="no-store for sensitive pages",
        check=_check_cache_no_store,
    ),
    _HeaderSpec(
        "pragma",
        severity="info",
        penalty=_INFO_PENALTY,
        recommended_value="no-cache",
        check=_check_pragma,
    ),
    _HeaderSpec(
        "x-permitted-cross-domain-policies",
        severity="info",
        penalty=_INFO_PENALTY,
        recommended_value="none",
        check=_check_xpcdp,
    ),
    _HeaderSpec(
        "feature-policy",
        severity="info",
        penalty=_INFO_PENALTY,
        recommended_value="Deprecated — use Permissions-Policy instead",
        check=_check_non_empty,
    ),
]

_DISCLOSURE_HEADERS: dict[str, str] = {
    "server": "Server header reveals software/version — consider removing or masking",
    "x-powered-by": "X-Powered-By reveals framework — remove in production",
    "x-aspnet-version": "X-AspNet-Version reveals .NET version — remove in production",
}

_VERSION_CHARS = set("0123456789./")


def _reveals_version(value: str) -> bool:
    """True when the header value appears to contain a version number."""
    return bool(value) and any(ch in _VERSION_CHARS for ch in value)


# ── analysis helpers ──────────────────────────────────────────────────────────


def _analyze_headers(response_headers: dict[str, str]) -> tuple[list[HeaderFinding], int]:
    """Analyze response headers against spec registry. Returns (findings, score)."""
    lower_map: dict[str, str] = {k.lower(): v for k, v in response_headers.items()}
    findings: list[HeaderFinding] = []
    score = 100

    for spec in _HEADER_SPECS:
        value = lower_map.get(spec.name)
        if value is None:
            findings.append(
                HeaderFinding(
                    header=spec.name,
                    present=False,
                    compliant=False,
                    recommendation=f"Add header: {spec.recommended_value}",
                    severity=spec.severity,
                )
            )
            score -= spec.penalty
        else:
            compliant = bool(spec.check(value)) if spec.check else True
            findings.append(
                HeaderFinding(
                    header=spec.name,
                    present=True,
                    value=value[:4096],
                    compliant=compliant,
                    recommendation="" if compliant else f"Recommended: {spec.recommended_value}",
                    severity="info" if compliant else spec.severity,
                )
            )

    for hdr_name, recommendation in _DISCLOSURE_HEADERS.items():
        value = lower_map.get(hdr_name)
        if value and _reveals_version(value):
            findings.append(
                HeaderFinding(
                    header=hdr_name,
                    present=True,
                    value=value[:512],
                    compliant=False,
                    recommendation=recommendation,
                    severity="low",
                )
            )
            score -= _DISCLOSURE_PENALTY

    return findings, max(0, score)


def _ensure_https_url(target: str) -> str:
    t = target.strip()
    if not t:
        return ""
    if t.startswith(("http://", "https://")):
        return t
    return f"https://{t}"


# ── public API ────────────────────────────────────────────────────────────────


async def collect_security_headers(target: str) -> SecurityHeadersResult:
    """Fetch target URL and analyze security-relevant headers."""
    base_result = SecurityHeadersResult(target=target)
    url = _ensure_https_url(target)
    if not url:
        base_result.error = "empty_target"
        return base_result

    urls_to_try = [url]
    if url.startswith("https://"):
        urls_to_try.append(url.replace("https://", "http://", 1))
    elif url.startswith("http://"):
        urls_to_try.insert(0, url.replace("http://", "https://", 1))

    last_error = ""
    for attempt_url in urls_to_try:
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(_REQUEST_TIMEOUT),
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": _USER_AGENT},
            ) as client:
                response = await client.get(attempt_url)

            raw_headers: dict[str, str] = dict(response.headers)
            lower_headers: dict[str, str] = {k.lower(): v for k, v in raw_headers.items()}

            findings, score = _analyze_headers(raw_headers)
            present = [f for f in findings if f.present]
            missing = [f for f in findings if not f.present]

            return SecurityHeadersResult(
                target=target,
                status_code=response.status_code,
                server=lower_headers.get("server"),
                x_powered_by=lower_headers.get("x-powered-by"),
                headers_found={f.header: (f.value or "") for f in present},
                headers_missing=missing,
                headers_present=present,
                all_response_headers=raw_headers,
                score=score,
                findings=findings,
            )

        except httpx.TimeoutException:
            last_error = f"timeout:{attempt_url}"
            logger.info(
                "security_headers_timeout",
                extra={"event": "security_headers_timeout", "url": attempt_url[:256]},
            )
        except httpx.ConnectError as exc:
            last_error = f"connect_error:{type(exc).__name__}"
            logger.info(
                "security_headers_connect_error",
                extra={"event": "security_headers_connect_error", "url": attempt_url[:256]},
            )
        except httpx.HTTPError as exc:
            last_error = f"http_error:{type(exc).__name__}"
            logger.warning(
                "security_headers_http_error",
                extra={
                    "event": "security_headers_http_error",
                    "url": attempt_url[:256],
                    "exc_type": type(exc).__name__,
                },
            )
        except Exception as exc:
            last_error = f"unexpected:{type(exc).__name__}"
            logger.warning(
                "security_headers_unexpected_error",
                extra={
                    "event": "security_headers_unexpected_error",
                    "url": attempt_url[:256],
                    "exc_type": type(exc).__name__,
                },
                exc_info=True,
            )

    base_result.error = last_error or "all_attempts_failed"
    return base_result


def security_headers_result_to_dict(result: SecurityHeadersResult) -> dict[str, Any]:
    """Serialize result to a JSON-compatible dict safe for MinIO / tool_results."""
    return result.model_dump(mode="json")
