"""Declarative check DSL — BCheck-like data-only security checks (WB-P8a, pure).

A :class:`DeclarativeCheck` is a signed, **data-only** description of a passive
or active security check: metadata + a boolean group of matchers over the parts
of an HTTP exchange, optional evidence extractors, an optional OAST requirement,
and a ``FindingDTO`` mapping. Like :mod:`src.playbooks.schema` it is *data, not
code* — it can never carry Python, shell strings, ``eval``/``exec``, or import
paths. All models are ``extra="forbid"`` + ``frozen`` (fail-closed).

The evaluator is **pure** (no I/O/network/DB) and offline-testable. It runs the
matcher group against a captured request/response and yields a
:class:`CheckFinding`. OAST-dependent checks fail closed unless the caller
supplies confirmed out-of-band interactions (the live correlator lives
elsewhere; this module never performs network I/O).

SECURITY: the DSL cannot execute anything; regexes are size-bounded and
compiled at validation time; scanned message parts are length-capped (DoS
guard); extractor captures are truncated. Findings map to a ``FindingDTO``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Self
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

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

#: ``author.jquery-version-leak`` style dotted slug.
_CHECK_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$")
#: Regex source length is bounded to keep validation/eval cheap (ReDoS guard).
_MAX_REGEX_LEN: Final[int] = 512
#: Each scanned message part is capped before matching (DoS guard).
_MAX_SCAN_BYTES: Final[int] = 524_288
#: Extractor captures are truncated to keep findings compact.
_MAX_CAPTURE_LEN: Final[int] = 200
#: ``Nxx`` status-class wildcard, e.g. ``5xx``.
_STATUS_CLASS_RE: Final[re.Pattern[str]] = re.compile(r"^[1-5]xx$")


class DslError(ValueError):
    """Raised when a declarative check cannot be loaded (fail-closed)."""


class MessagePart(StrEnum):
    """Which part of the HTTP exchange a matcher/extractor reads."""

    REQUEST_LINE = "request_line"
    REQUEST_HEADER = "request_header"
    REQUEST_BODY = "request_body"
    URL = "url"
    RESPONSE_LINE = "response_line"
    RESPONSE_HEADER = "response_header"
    RESPONSE_BODY = "response_body"
    STATUS_CODE = "status_code"


_REQUEST_PARTS: Final[frozenset[MessagePart]] = frozenset(
    {
        MessagePart.REQUEST_LINE,
        MessagePart.REQUEST_HEADER,
        MessagePart.REQUEST_BODY,
        MessagePart.URL,
    }
)


class MatcherKind(StrEnum):
    """Closed set of matcher operators (no code, no eval)."""

    CONTAINS = "contains"
    REGEX = "regex"
    EQUALS = "equals"
    STATUS = "status"


class BooleanOp(StrEnum):
    """How the matchers in a group combine."""

    AND = "and"
    OR = "or"


class CheckScope(StrEnum):
    """Whether a check inspects request-side or response-side signals."""

    PASSIVE = "passive"
    ACTIVE = "active"


class Matcher(BaseModel):
    """A single condition over one message part (data-only)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    part: MessagePart
    kind: MatcherKind
    value: StrictStr = Field(min_length=1, max_length=_MAX_REGEX_LEN)
    negate: StrictBool = False
    case_sensitive: StrictBool = False

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.kind is MatcherKind.REGEX:
            try:
                re.compile(self.value)
            except re.error as exc:
                raise ValueError(f"invalid matcher regex: {exc}") from exc
        if self.kind is MatcherKind.STATUS:
            if self.part is not MessagePart.STATUS_CODE:
                raise ValueError("status matcher requires part=status_code")
            if not (self.value.isdigit() or _STATUS_CLASS_RE.fullmatch(self.value)):
                raise ValueError("status matcher value must be a code or Nxx class")
        if "\n" in self.value or "\r" in self.value:
            raise ValueError("matcher value must be single-line")
        return self


class MatcherGroup(BaseModel):
    """A boolean group of matchers (AND/OR)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    op: BooleanOp = BooleanOp.AND
    matchers: list[Matcher] = Field(min_length=1, max_length=32)


class Extractor(BaseModel):
    """Capture a (length-capped) substring for evidence labelling."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=64)
    part: MessagePart
    regex: StrictStr = Field(min_length=1, max_length=_MAX_REGEX_LEN)
    group: StrictInt = Field(default=0, ge=0, le=32)

    @field_validator("regex")
    @classmethod
    def _check_regex(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid extractor regex: {exc}") from exc
        return value


class DeclarativeCheck(BaseModel):
    """Top-level signed, declarative check descriptor (data, not code)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: StrictInt = Field(ge=1, le=1_000)
    check_id: StrictStr = Field(min_length=3, max_length=128, pattern=_CHECK_ID_RE.pattern)
    name: StrictStr = Field(min_length=1, max_length=200)
    author: StrictStr = Field(default="", max_length=200)
    version: StrictInt = Field(default=1, ge=1, le=1_000_000)
    description: StrictStr = Field(default="", max_length=4000)
    category: FindingCategory
    severity: CheckSeverity
    confidence: ConfidenceLevel = ConfidenceLevel.SUSPECTED
    cwe: list[StrictInt] = Field(default_factory=list, max_length=16)
    scope: CheckScope = CheckScope.PASSIVE
    requires_oast: StrictBool = False
    match: MatcherGroup
    extractors: list[Extractor] = Field(default_factory=list, max_length=16)
    remediation: StrictStr = Field(default="", max_length=2000)

    @field_validator("cwe")
    @classmethod
    def _check_cwe(cls, value: list[int]) -> list[int]:
        for cwe in value:
            if cwe <= 0:
                raise ValueError(f"CWE id must be positive, got {cwe}")
        if len(set(value)) != len(value):
            raise ValueError("cwe entries must be unique")
        return value

    @model_validator(mode="after")
    def _validate(self) -> Self:
        # A passive check may only read request-side signals it already has; a
        # response-part matcher is fine (it is captured). OAST needs live
        # correlation, which only an ACTIVE check can obtain.
        if self.requires_oast and self.scope is not CheckScope.ACTIVE:
            raise ValueError("requires_oast checks must have scope=active")
        return self


@dataclass(frozen=True)
class CheckFinding:
    """A finding produced by a declarative check (evidence is capped)."""

    check_id: str
    category: FindingCategory
    severity: CheckSeverity
    confidence: ConfidenceLevel
    cwe: tuple[int, ...]
    title: str
    detail: str
    evidence: str
    location: str


def load_check(data: object) -> DeclarativeCheck:
    """Validate an untrusted mapping into a :class:`DeclarativeCheck`.

    Fail-closed: any unexpected key, wrong type, bad regex, or invalid combo
    raises :class:`DslError` (never a raw pydantic/stack trace to callers).
    """
    if not isinstance(data, dict):
        raise DslError("check descriptor must be a mapping")
    try:
        return DeclarativeCheck.model_validate(data)
    except ValueError as exc:
        raise DslError(f"invalid declarative check: {exc.__class__.__name__}") from exc


def _headers_text(headers: tuple[tuple[str, str], ...]) -> str:
    return "\n".join(f"{name}: {value}" for name, value in headers)


def _part_text(
    part: MessagePart,
    request: NormalizedRequest,
    response: NormalizedResponse,
    request_body: bytes,
    response_body: bytes,
) -> str:
    if part is MessagePart.REQUEST_LINE:
        return f"{request.method} {request.target} {request.http_version}"
    if part is MessagePart.URL:
        return request.target
    if part is MessagePart.REQUEST_HEADER:
        return _headers_text(request.headers)
    if part is MessagePart.REQUEST_BODY:
        return request_body[:_MAX_SCAN_BYTES].decode("latin-1")
    if part is MessagePart.RESPONSE_LINE:
        return f"{response.http_version} {response.status_code} {response.reason}"
    if part is MessagePart.RESPONSE_HEADER:
        return _headers_text(response.headers)
    if part is MessagePart.RESPONSE_BODY:
        return response_body[:_MAX_SCAN_BYTES].decode("latin-1")
    if part is MessagePart.STATUS_CODE:
        return str(response.status_code)
    raise DslError(f"unhandled message part: {part}")  # pragma: no cover - exhaustive


def _match_status(value: str, status_code: int) -> bool:
    if value.isdigit():
        return int(value) == status_code
    return int(value[0]) == status_code // 100


def _match_one(matcher: Matcher, text: str, status_code: int) -> bool:
    if matcher.kind is MatcherKind.STATUS:
        result = _match_status(matcher.value, status_code)
    else:
        haystack = text if matcher.case_sensitive else text.lower()
        needle = matcher.value if matcher.case_sensitive else matcher.value.lower()
        if matcher.kind is MatcherKind.CONTAINS:
            result = needle in haystack
        elif matcher.kind is MatcherKind.EQUALS:
            result = haystack.strip() == needle.strip()
        elif matcher.kind is MatcherKind.REGEX:
            flags = 0 if matcher.case_sensitive else re.IGNORECASE
            result = re.search(matcher.value, text, flags) is not None
        else:  # pragma: no cover - exhaustive over MatcherKind
            raise DslError(f"unhandled matcher kind: {matcher.kind}")
    return not result if matcher.negate else result


def _extract_evidence(
    check: DeclarativeCheck,
    request: NormalizedRequest,
    response: NormalizedResponse,
    request_body: bytes,
    response_body: bytes,
) -> str:
    parts: list[str] = []
    for extractor in check.extractors:
        text = _part_text(extractor.part, request, response, request_body, response_body)
        found = re.search(extractor.regex, text)
        if not found:
            continue
        try:
            captured = found.group(extractor.group)
        except IndexError:
            captured = found.group(0)
        if captured is None:
            captured = found.group(0)
        parts.append(f"{extractor.name}={captured[:_MAX_CAPTURE_LEN]}")
    return "; ".join(parts)


def evaluate_check(
    check: DeclarativeCheck,
    request: NormalizedRequest,
    response: NormalizedResponse,
    response_body: bytes,
    *,
    request_body: bytes = b"",
    oast_confirmed: bool = False,
) -> CheckFinding | None:
    """Run one declarative check against a captured exchange (pure).

    Returns a :class:`CheckFinding` when the matcher group is satisfied,
    otherwise ``None``. OAST-dependent checks fail closed unless
    ``oast_confirmed`` is supplied by the caller (from the live correlator).
    """
    if check.requires_oast and not oast_confirmed:
        return None

    results = [
        _match_one(
            matcher,
            _part_text(matcher.part, request, response, request_body, response_body),
            response.status_code,
        )
        for matcher in check.match.matchers
    ]
    satisfied = all(results) if check.match.op is BooleanOp.AND else any(results)
    if not satisfied:
        return None

    location = f"{request.method} {request.target}"
    evidence = _extract_evidence(check, request, response, request_body, response_body)
    return CheckFinding(
        check_id=check.check_id,
        category=check.category,
        severity=check.severity,
        confidence=check.confidence,
        cwe=tuple(check.cwe),
        title=check.name,
        detail=check.description or check.name,
        evidence=evidence or f"matched {len(results)} condition(s)",
        location=location,
    )


def evaluate_checks(
    checks: list[DeclarativeCheck],
    request: NormalizedRequest,
    response: NormalizedResponse,
    response_body: bytes,
    *,
    request_body: bytes = b"",
    oast_confirmed: bool = False,
) -> list[CheckFinding]:
    """Evaluate a batch of checks, returning every satisfied finding."""
    findings: list[CheckFinding] = []
    for check in checks:
        finding = evaluate_check(
            check,
            request,
            response,
            response_body,
            request_body=request_body,
            oast_confirmed=oast_confirmed,
        )
        if finding is not None:
            findings.append(finding)
    return findings


def check_finding_to_dto(
    finding: CheckFinding,
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
    finding_id: UUID | None = None,
) -> FindingDTO:
    """Project one :class:`CheckFinding` onto a ``FindingDTO``."""
    vector, score = cvss_for(finding.severity)
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
        category=finding.category,
        cwe=list(finding.cwe),
        cvss_v3_vector=vector,
        cvss_v3_score=score,
        confidence=finding.confidence,
        status=FindingStatus.NEW,
        evidence_tier=tier,
        remediation=RemediationDTO(summary=summary[:2000]),
    )


__all__ = [
    "BooleanOp",
    "CheckFinding",
    "CheckScope",
    "DeclarativeCheck",
    "DslError",
    "Extractor",
    "Matcher",
    "MatcherGroup",
    "MatcherKind",
    "MessagePart",
    "check_finding_to_dto",
    "evaluate_check",
    "evaluate_checks",
    "load_check",
]
