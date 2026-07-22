"""Authorization analyzer — owner/attacker/anon diff → BAC/IDOR (WB-P6a, pure).

Compares an authorized *owner* exchange against one or more *attacker* exchanges
(a different authenticated principal, or the anonymous principal) that requested
the **same** owner-owned resource, and classifies proven cross-user reads as
Broken Access Control findings.

This is a thin, offline adapter over the existing, battle-tested
:class:`~src.playbooks.oracles.AuthzOracle` (IDOR / BOLA) — the verdict logic
(denied-status handling, JSON field diffing, volatile-field suppression,
byte-identical raw compare, "no bare 2xx") is **reused, not duplicated**
(invariant: extend). This module only adapts captured workbench traffic
(:class:`NormalizedRequest`/``NormalizedResponse`` + bodies) into the oracle's
:class:`~src.playbooks.actions.HttpExchange` shape and adds the workbench-level
IDOR-vs-BFLA-vs-unauth classification.

SECURITY (SI-3): the analyzer never emits raw response bodies. An
:class:`AuthorizationFinding` carries only the oracle reason, differing **field
paths** (not values), the detected object-id token (a URL identifier, not a
secret) and coarse metadata. It performs no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from src.pipeline.contracts.finding_dto import ConfidenceLevel
from src.playbooks.actions import HttpExchange, HttpRequestSpec, HttpResponse
from src.playbooks.oracles import AuthzOracle, OracleResult, OracleVerdict
from src.playbooks.schema import HttpMethod
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse

#: Request body cap accepted by ``HttpRequestSpec`` (structural model bound).
_MAX_REQUEST_BODY = 65_536
#: Response body cap accepted by ``HttpResponse`` (structural model bound).
_MAX_RESPONSE_BODY = 1_048_576

#: Object-identifier tokens in a URL that make a cross-user read an IDOR (direct
#: object reference) rather than a generic function-level bypass (BFLA).
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_NUMERIC_ID_RE = re.compile(r"(?<![A-Za-z0-9])\d{1,}(?![A-Za-z0-9])")
_LONG_HEX_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{12,}(?![0-9a-fA-F])")


class AuthorizationError(Exception):
    """Raised on malformed analyzer input (fail-closed)."""


class AuthzClass(StrEnum):
    """Workbench classification of a proven access-control failure."""

    #: Direct object reference manipulated to read another user's object.
    IDOR = "idor"
    #: Function/endpoint reachable by a user who should not reach it.
    BFLA = "bfla"
    #: Owner-scoped resource reachable with no authentication at all.
    UNAUTH_ACCESS = "unauth_access"


@dataclass(frozen=True)
class CapturedExchange:
    """One captured request/response pair for a labelled principal.

    ``is_anonymous`` marks the unauthenticated principal (drives the
    ``UNAUTH_ACCESS`` classification). Bodies are raw captured bytes.
    """

    principal: str
    request: NormalizedRequest
    response: NormalizedResponse
    request_body: bytes = b""
    response_body: bytes = b""
    is_anonymous: bool = False


@dataclass(frozen=True)
class AuthorizationFinding:
    """A classified access-control finding (secret-free evidence)."""

    classification: AuthzClass
    verdict: OracleVerdict
    confidence: ConfidenceLevel
    reason: str
    principal: str
    location: str
    object_id: str | None
    differing_fields: tuple[str, ...]


def _headers_to_map(headers: tuple[tuple[str, str], ...]) -> dict[str, str]:
    # Structural models want a mapping; duplicate names collapse (last wins).
    # The AuthzOracle never inspects headers, so this is display-only.
    return {name: value for name, value in headers}


def _method_of(request: NormalizedRequest) -> HttpMethod:
    try:
        return HttpMethod(request.method.upper())
    except ValueError:
        # CONNECT/TRACE or non-standard verbs: the oracle ignores the request,
        # so a safe default keeps the structural model valid.
        return HttpMethod.GET


def _to_exchange(captured: CapturedExchange) -> HttpExchange:
    request = HttpRequestSpec(
        method=_method_of(captured.request),
        url=captured.request.target[:2048],
        headers=_headers_to_map(captured.request.headers),
        body=(captured.request_body[:_MAX_REQUEST_BODY].decode("latin-1") or None),
    )
    response = HttpResponse(
        status=captured.response.status_code,
        headers=_headers_to_map(captured.response.headers),
        body=captured.response_body[:_MAX_RESPONSE_BODY].decode("latin-1"),
    )
    return HttpExchange(request=request, response=response)


def detect_object_id(target: str) -> str | None:
    """Return the first object-identifier token in ``target`` (path or query).

    Used only to distinguish IDOR (a manipulable direct reference is present)
    from a generic function-level bypass. Returns a URL token — never a secret.
    """
    split = urlsplit(target)
    for segment in (split.path, split.query):
        if not segment:
            continue
        for pattern in (_UUID_RE, _LONG_HEX_RE, _NUMERIC_ID_RE):
            match = pattern.search(segment)
            if match:
                return match.group(0)
    return None


def _classify(attacker: CapturedExchange, object_id: str | None) -> AuthzClass:
    if attacker.is_anonymous:
        return AuthzClass.UNAUTH_ACCESS
    if object_id is not None:
        return AuthzClass.IDOR
    return AuthzClass.BFLA


def evaluate_pair(
    owner: CapturedExchange,
    attacker: CapturedExchange,
    *,
    sensitive_fields: Sequence[str] = (),
    volatile_fields: Sequence[str] = (),
    denied_statuses: Sequence[int] = (),
) -> OracleResult:
    """Run the shared :class:`AuthzOracle` over an owner/attacker capture pair.

    ``owner`` must be the victim's *successful* (2xx) response; otherwise a
    match is meaningless and the result is ``INCONCLUSIVE``.
    """
    if not 200 <= owner.response.status_code <= 299:
        return OracleResult(
            oracle_type=AuthzOracle.oracle_type,
            verdict=OracleVerdict.INCONCLUSIVE,
            confidence=ConfidenceLevel.SUSPECTED,
            reason=(
                "owner baseline is not a 2xx success "
                f"(HTTP {owner.response.status_code}); cross-user read cannot be judged"
            ),
        )
    params: dict[str, object] = {
        "sensitive_fields": list(sensitive_fields),
        "volatile_fields": list(volatile_fields),
    }
    if denied_statuses:
        params["denied_statuses"] = list(denied_statuses)
    return AuthzOracle().evaluate(_to_exchange(owner), _to_exchange(attacker), params)


def analyze_authorization(
    *,
    owner: CapturedExchange,
    attackers: Sequence[CapturedExchange],
    sensitive_fields: Sequence[str] = (),
    volatile_fields: Sequence[str] = (),
    denied_statuses: Sequence[int] = (),
) -> list[AuthorizationFinding]:
    """Classify proven cross-user reads across every attacker principal.

    Only ``FINDING`` verdicts surface as :class:`AuthorizationFinding`; each is
    classified IDOR / BFLA / UNAUTH_ACCESS. ``NO_FINDING`` / ``INCONCLUSIVE``
    verdicts are intentionally dropped (use :func:`evaluate_pair` for the raw
    verdict).
    """
    if not attackers:
        raise AuthorizationError("at least one attacker exchange is required")

    object_id = detect_object_id(owner.request.target)
    findings: list[AuthorizationFinding] = []
    for attacker in attackers:
        result = evaluate_pair(
            owner,
            attacker,
            sensitive_fields=sensitive_fields,
            volatile_fields=volatile_fields,
            denied_statuses=denied_statuses,
        )
        if result.verdict is not OracleVerdict.FINDING:
            continue
        findings.append(
            AuthorizationFinding(
                classification=_classify(attacker, object_id),
                verdict=result.verdict,
                confidence=result.confidence,
                reason=result.reason,
                principal=attacker.principal,
                location=f"{owner.request.method} {owner.request.target}",
                object_id=object_id,
                differing_fields=tuple(result.differing_fields),
            )
        )
    return findings


__all__ = [
    "AuthorizationError",
    "AuthorizationFinding",
    "AuthzClass",
    "CapturedExchange",
    "analyze_authorization",
    "detect_object_id",
    "evaluate_pair",
]
