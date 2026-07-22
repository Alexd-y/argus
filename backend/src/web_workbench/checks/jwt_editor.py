"""JWT inspector/analyzer — offline JWT security review (WB-P7b, pure).

Decodes a JWT (header + payload, **no signature verification** — analysis only)
captured from an ``Authorization: Bearer`` header or cookie and flags common JWT
weaknesses: ``alg=none`` / empty-signature acceptance, attacker-controlled key
headers (``jwk``/``jku``/``x5u``), ``kid`` injection, missing/excessive/expired
expiry, and sensitive data placed in the (merely base64) payload.

It is **pure** (no I/O/network/DB) and offline-testable. It complements the
workbench Decoder's ``jwt_decode`` transform (display) with structured security
analysis (extend, not duplicate).

SECURITY (SI-3): a :class:`JwtFinding` never echoes claim *values* — only claim
/ header *names* and coarse metadata. Findings map to a ``FindingDTO`` with
category ``JWT``.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass
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

#: Claim/header key substrings that must never travel inside a (base64) JWT.
_SENSITIVE_KEYS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "ssn",
    "credit_card",
    "card_number",
    "cardnumber",
    "cvv",
)
#: Characters in a ``kid`` that suggest path-traversal / SQLi / command injection.
_KID_INJECTION_CHARS = ("/", "\\", "..", "'", '"', ";", " ", "\n", "*", "$")
#: Expiry further than this many seconds ahead is an excessive lifetime.
_MAX_LIFETIME_SECONDS = 31_536_000  # 1 year


class JwtError(Exception):
    """Raised when the input is not a decodable JWT (fail-closed)."""


@dataclass(frozen=True)
class DecodedJwt:
    """A structurally decoded (unverified) JWT."""

    header: dict[str, object]
    payload: dict[str, object]
    signature: str
    parts: int


@dataclass(frozen=True)
class JwtFinding:
    """One JWT weakness (secret-free evidence)."""

    code: str
    severity: CheckSeverity
    confidence: ConfidenceLevel
    cwe: int
    title: str
    detail: str
    evidence: str


def _b64url_json(segment: str) -> dict[str, object]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise JwtError("JWT segment is not valid base64url") from exc
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JwtError("JWT segment is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise JwtError("JWT segment is not a JSON object")
    return decoded


def decode_jwt(token: str) -> DecodedJwt:
    """Decode a JWT's header + payload without verifying its signature."""
    parts = token.strip().split(".")
    if len(parts) not in (2, 3):
        raise JwtError("input is not a JWT (expected 2-3 dot-separated parts)")
    header = _b64url_json(parts[0])
    payload = _b64url_json(parts[1])
    signature = parts[2] if len(parts) == 3 else ""
    return DecodedJwt(header=header, payload=payload, signature=signature, parts=len(parts))


def is_jwt(token: str) -> bool:
    """Return ``True`` if ``token`` decodes as a JWT header+payload."""
    try:
        decode_jwt(token)
    except JwtError:
        return False
    return True


def _iter_keys(obj: object, prefix: str = "") -> list[str]:
    keys: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            keys.append(str(key))
            keys.extend(_iter_keys(value, path))
    elif isinstance(obj, list):
        for item in obj:
            keys.extend(_iter_keys(item, prefix))
    return keys


def _check_algorithm(decoded: DecodedJwt) -> list[JwtFinding]:
    findings: list[JwtFinding] = []
    alg = str(decoded.header.get("alg", "")).strip()
    alg_lower = alg.lower()
    if alg_lower == "none":
        findings.append(
            JwtFinding(
                code="jwt-alg-none",
                severity=CheckSeverity.CRITICAL,
                confidence=ConfidenceLevel.LIKELY,
                cwe=347,
                title="JWT alg=none",
                detail="Token declares alg=none — signature is not verified; forgeable.",
                evidence=f"alg={alg or 'none'}",
            )
        )
    elif not decoded.signature:
        findings.append(
            JwtFinding(
                code="jwt-empty-signature",
                severity=CheckSeverity.HIGH,
                confidence=ConfidenceLevel.SUSPECTED,
                cwe=347,
                title="JWT with empty signature",
                detail="Signing alg declared but signature segment is empty.",
                evidence=f"alg={alg}",
            )
        )
    return findings


def _check_key_headers(decoded: DecodedJwt) -> list[JwtFinding]:
    findings: list[JwtFinding] = []
    header = decoded.header
    if "jwk" in header:
        findings.append(
            JwtFinding(
                code="jwt-embedded-jwk",
                severity=CheckSeverity.HIGH,
                confidence=ConfidenceLevel.SUSPECTED,
                cwe=347,
                title="JWT embeds a JWK in its header",
                detail="An attacker-supplied embedded key ('jwk') may be trusted for verification.",
                evidence="header.jwk",
            )
        )
    for header_name in ("jku", "x5u"):
        if header_name in header:
            findings.append(
                JwtFinding(
                    code=f"jwt-{header_name}-header",
                    severity=CheckSeverity.MEDIUM,
                    confidence=ConfidenceLevel.SUSPECTED,
                    cwe=347,
                    title=f"JWT references an external key URL ('{header_name}')",
                    detail=f"'{header_name}' points the verifier at a remote key; SSRF/key-injection risk.",
                    evidence=f"header.{header_name}",
                )
            )
    kid = header.get("kid")
    if isinstance(kid, str) and any(marker in kid for marker in _KID_INJECTION_CHARS):
        findings.append(
            JwtFinding(
                code="jwt-kid-injection",
                severity=CheckSeverity.MEDIUM,
                confidence=ConfidenceLevel.SUSPECTED,
                cwe=91,
                title="JWT 'kid' contains injection metacharacters",
                detail="The 'kid' header carries path/SQL/command metacharacters (injection candidate).",
                evidence="header.kid",
            )
        )
    return findings


def _check_expiry(decoded: DecodedJwt, now: float) -> list[JwtFinding]:
    findings: list[JwtFinding] = []
    exp = decoded.payload.get("exp")
    if exp is None:
        findings.append(
            JwtFinding(
                code="jwt-no-expiry",
                severity=CheckSeverity.MEDIUM,
                confidence=ConfidenceLevel.LIKELY,
                cwe=613,
                title="JWT has no expiry ('exp')",
                detail="Token never expires; a leaked token is valid indefinitely.",
                evidence="payload.exp(absent)",
            )
        )
        return findings
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return findings
    if exp < now:
        findings.append(
            JwtFinding(
                code="jwt-expired",
                severity=CheckSeverity.INFO,
                confidence=ConfidenceLevel.LIKELY,
                cwe=613,
                title="JWT is expired",
                detail="Token 'exp' is in the past; if still accepted, expiry is not enforced.",
                evidence="payload.exp",
            )
        )
    elif exp - now > _MAX_LIFETIME_SECONDS:
        findings.append(
            JwtFinding(
                code="jwt-long-expiry",
                severity=CheckSeverity.LOW,
                confidence=ConfidenceLevel.LIKELY,
                cwe=613,
                title="JWT has an excessive lifetime",
                detail="Token 'exp' is more than a year ahead; oversized session window.",
                evidence="payload.exp",
            )
        )
    return findings


def _check_sensitive_claims(decoded: DecodedJwt) -> list[JwtFinding]:
    findings: list[JwtFinding] = []
    seen: set[str] = set()
    for key in _iter_keys(decoded.payload):
        lowered = key.lower()
        for marker in _SENSITIVE_KEYS:
            if marker in lowered and key not in seen:
                seen.add(key)
                findings.append(
                    JwtFinding(
                        code="jwt-sensitive-claim",
                        severity=CheckSeverity.MEDIUM,
                        confidence=ConfidenceLevel.LIKELY,
                        cwe=522,
                        title="Sensitive data in JWT payload",
                        detail=(
                            "JWT payload is base64 (not encrypted); a sensitive-looking "
                            "claim is exposed to anyone holding the token."
                        ),
                        evidence=f"payload.{key}",
                    )
                )
                break
    return findings


def analyze_jwt(token: str, *, now: float | None = None) -> list[JwtFinding]:
    """Decode and analyze a JWT, returning every weakness found (deduplicated)."""
    decoded = decode_jwt(token)
    current = time.time() if now is None else now
    findings: list[JwtFinding] = []
    findings.extend(_check_algorithm(decoded))
    findings.extend(_check_key_headers(decoded))
    findings.extend(_check_expiry(decoded, current))
    findings.extend(_check_sensitive_claims(decoded))

    seen: set[tuple[str, str]] = set()
    deduped: list[JwtFinding] = []
    for finding in findings:
        marker = (finding.code, finding.evidence)
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(finding)
    return deduped


def jwt_finding_to_dto(
    finding: JwtFinding,
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
    finding_id: UUID | None = None,
) -> FindingDTO:
    """Project one :class:`JwtFinding` onto a ``FindingDTO`` (category JWT)."""
    vector, score = cvss_for(finding.severity)
    tier = (
        EvidenceTier.SUSPECTED
        if finding.confidence is ConfidenceLevel.SUSPECTED
        else EvidenceTier.INFORMATIONAL
    )
    summary = f"{finding.title}: {finding.detail} (evidence: {finding.evidence})"
    return FindingDTO(
        id=finding_id or uuid4(),
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        tool_run_id=tool_run_id,
        category=FindingCategory.JWT,
        cwe=[finding.cwe],
        cvss_v3_vector=vector,
        cvss_v3_score=score,
        confidence=finding.confidence,
        status=FindingStatus.NEW,
        evidence_tier=tier,
        remediation=RemediationDTO(summary=summary[:2000]),
    )


def jwt_findings_to_dtos(
    findings: list[JwtFinding],
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
) -> list[FindingDTO]:
    """Project a batch of JWT findings (fresh UUID per finding)."""
    return [
        jwt_finding_to_dto(
            finding,
            tenant_id=tenant_id,
            scan_id=scan_id,
            asset_id=asset_id,
            tool_run_id=tool_run_id,
        )
        for finding in findings
    ]


__all__ = [
    "DecodedJwt",
    "JwtError",
    "JwtFinding",
    "analyze_jwt",
    "decode_jwt",
    "is_jwt",
    "jwt_finding_to_dto",
    "jwt_findings_to_dtos",
]
