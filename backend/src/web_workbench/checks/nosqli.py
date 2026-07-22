"""NoSQL-injection passive analyzer (WB-P7c, pure).

Reviews a captured request/response pair (proxy/repeater history) for NoSQL
(MongoDB-style) injection signals — **without sending anything**:

* **Operator injection** — client-controlled input carries MongoDB query
  operators (``$ne``/``$gt``/``$regex``/``$where``…), either as bracketed
  parameter names (``user[$ne]=`` — the Express/PHP array-injection form) or as
  ``$``-prefixed keys inside a JSON body. Presence alone is a *candidate*.
* **Error signature** — the response body leaks a NoSQL engine error
  (Mongo/BSON/cast errors). Reuses the shared, curated error-signature set from
  :data:`src.recon.quick_fuzz.detection_sigs.DETECTION_SIGNATURES` (extend, not
  duplicate) with a few extra Mongo/Couch markers.

When operator injection **and** an error signature co-occur the analyzer raises
a single, higher-confidence error-based finding. It is **pure** (no I/O) and
offline-testable.

SECURITY (SI-3): findings carry only operator / parameter *names* and the matched
error marker — never request/response values.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID, uuid4

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceTier,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    RemediationDTO,
)
from src.recon.quick_fuzz.detection_sigs import DETECTION_SIGNATURES
from src.web_workbench.checks.severity import CheckSeverity, cvss_for
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse

#: CWE-943: Improper Neutralization of Special Elements in a Data Query.
_CWE_NOSQLI = 943

_OPERATORS = frozenset(
    {
        "ne",
        "gt",
        "gte",
        "lt",
        "lte",
        "in",
        "nin",
        "regex",
        "where",
        "exists",
        "or",
        "and",
        "not",
        "nor",
        "elemMatch",
    }
)
_ALT = "|".join(sorted(_OPERATORS))
#: ``param[$ne]`` bracket-injection form in a parameter name.
_BRACKET_RE = re.compile(rf"\[\s*\$({_ALT})\s*\]", re.IGNORECASE)
#: A bare ``$op`` operator token inside a value or JSON key.
_TOKEN_RE = re.compile(rf"\$({_ALT})\b", re.IGNORECASE)

#: Reused curated NoSQL error signatures + a few extra engine markers.
_ERROR_SIGNATURES: tuple[str, ...] = tuple(
    dict.fromkeys(
        [sig.lower() for sig in DETECTION_SIGNATURES.get("nosql", [])]
        + [
            "mongoerror",
            "mongoservererror",
            "bsonerror",
            "e11000 duplicate key",
            "unexpected token",
            "couchdb",
            "unknown operator",
        ]
    )
)
#: Response body scanned for error markers is capped (noise / DoS guard).
_MAX_BODY_SCAN = 262_144


@dataclass(frozen=True)
class NosqlFinding:
    """A NoSQL-injection signal (secret-free evidence)."""

    code: str
    severity: CheckSeverity
    confidence: ConfidenceLevel
    cwe: int
    title: str
    detail: str
    evidence: str
    location: str


def _walk_json_keys(obj: object) -> list[str]:
    keys: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            keys.append(str(key))
            keys.extend(_walk_json_keys(value))
    elif isinstance(obj, list):
        for item in obj:
            keys.extend(_walk_json_keys(item))
    return keys


def _operator_params(request: NormalizedRequest, request_body: bytes) -> list[str]:
    """Return distinct ``param$op`` evidence tokens found in request input."""
    found: list[str] = []
    seen: set[str] = set()

    def _record(token: str) -> None:
        if token not in seen:
            seen.add(token)
            found.append(token)

    query = urlsplit(request.target).query
    pairs = list(parse_qsl(query, keep_blank_values=True)) if query else []

    body_text = request_body.decode("latin-1") if request_body else ""
    content_type = (request.header("Content-Type") or "").lower()

    if "application/x-www-form-urlencoded" in content_type and body_text:
        pairs.extend(parse_qsl(body_text, keep_blank_values=True))

    for name, value in pairs:
        bracket = _BRACKET_RE.search(name)
        if bracket:
            _record(f"{name.split('[')[0]}[${bracket.group(1).lower()}]")
        token = _TOKEN_RE.search(value)
        if token:
            _record(f"{name}=${token.group(1).lower()}")

    if body_text and ("application/json" in content_type or body_text.lstrip()[:1] in "{["):
        try:
            parsed = json.loads(body_text)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            parsed = None
        if parsed is not None:
            for key in _walk_json_keys(parsed):
                if key.startswith("$") and key[1:].lower() in _OPERATORS:
                    _record(f"body.{key.lower()}")

    return found


def _error_markers(response_body: bytes) -> list[str]:
    body = response_body[:_MAX_BODY_SCAN].decode("latin-1").lower()
    return [sig for sig in _ERROR_SIGNATURES if sig in body]


def detect_operator_injection(
    request: NormalizedRequest, request_body: bytes = b""
) -> list[NosqlFinding]:
    """Flag MongoDB operators present in client-controlled request input."""
    location = f"{request.method} {request.target}"
    findings: list[NosqlFinding] = []
    for token in _operator_params(request, request_body):
        findings.append(
            NosqlFinding(
                code="nosqli-operator-injection",
                severity=CheckSeverity.MEDIUM,
                confidence=ConfidenceLevel.SUSPECTED,
                cwe=_CWE_NOSQLI,
                title="NoSQL operator in request input",
                detail=(
                    "Client-controlled input carries a MongoDB query operator; "
                    "if passed unsanitised to a query it enables NoSQL injection."
                ),
                evidence=token,
                location=location,
            )
        )
    return findings


def detect_error_signature(request: NormalizedRequest, response_body: bytes) -> list[NosqlFinding]:
    """Flag NoSQL engine error markers leaked in the response body."""
    location = f"{request.method} {request.target}"
    findings: list[NosqlFinding] = []
    for marker in _error_markers(response_body):
        findings.append(
            NosqlFinding(
                code="nosqli-error-signature",
                severity=CheckSeverity.MEDIUM,
                confidence=ConfidenceLevel.SUSPECTED,
                cwe=_CWE_NOSQLI,
                title="NoSQL engine error disclosed",
                detail="Response leaks a NoSQL engine error, indicating unsanitised query input.",
                evidence=marker,
                location=location,
            )
        )
    return findings


def analyze(
    request: NormalizedRequest,
    response: NormalizedResponse,
    response_body: bytes,
    *,
    request_body: bytes = b"",
) -> list[NosqlFinding]:
    """Analyze one captured exchange for NoSQL-injection signals.

    ``response`` participates only via its body here; the parameter is kept for
    signature symmetry with the other passive analyzers and future status-aware
    heuristics. When operator injection and an error signature co-occur, a single
    elevated (HIGH/LIKELY) error-based finding is returned instead of the weaker
    individual signals.
    """
    _ = response  # body carries the signal; status-aware logic is future work.
    operators = detect_operator_injection(request, request_body)
    errors = detect_error_signature(request, response_body)
    location = f"{request.method} {request.target}"

    if operators and errors:
        return [
            NosqlFinding(
                code="nosqli-error-based",
                severity=CheckSeverity.HIGH,
                confidence=ConfidenceLevel.LIKELY,
                cwe=_CWE_NOSQLI,
                title="Error-based NoSQL injection",
                detail=(
                    "A NoSQL operator was injected and the response leaked an engine "
                    f"error ({len(operators)} operator token(s) seen) — likely NoSQLi."
                ),
                evidence=f"{operators[0].evidence} -> {errors[0].evidence}",
                location=location,
            )
        ]
    return operators + errors


def nosql_finding_to_dto(
    finding: NosqlFinding,
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
    finding_id: UUID | None = None,
) -> FindingDTO:
    """Project one :class:`NosqlFinding` onto a ``FindingDTO`` (NOSQLI)."""
    vector, score = cvss_for(finding.severity)
    # Passive heuristics never reproduce an exploit, so CONFIRMED confidence is
    # the only path to the CONFIRMED tier; SUSPECTED/LIKELY stay at SUSPECTED.
    tier = (
        EvidenceTier.CONFIRMED
        if finding.confidence is ConfidenceLevel.CONFIRMED
        else EvidenceTier.SUSPECTED
    )
    summary = (
        f"{finding.title}: {finding.detail} (evidence: {finding.evidence}; at {finding.location})"
    )
    return FindingDTO(
        id=finding_id or uuid4(),
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        tool_run_id=tool_run_id,
        category=FindingCategory.NOSQLI,
        cwe=[finding.cwe],
        cvss_v3_vector=vector,
        cvss_v3_score=score,
        confidence=finding.confidence,
        status=FindingStatus.NEW,
        evidence_tier=tier,
        remediation=RemediationDTO(summary=summary[:2000]),
    )


def nosql_findings_to_dtos(
    findings: list[NosqlFinding],
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
) -> list[FindingDTO]:
    """Project a batch of NoSQLi findings (fresh UUID per finding)."""
    return [
        nosql_finding_to_dto(
            finding,
            tenant_id=tenant_id,
            scan_id=scan_id,
            asset_id=asset_id,
            tool_run_id=tool_run_id,
        )
        for finding in findings
    ]


__all__ = [
    "NosqlFinding",
    "analyze",
    "detect_error_signature",
    "detect_operator_injection",
    "nosql_finding_to_dto",
    "nosql_findings_to_dtos",
]
