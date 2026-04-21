"""Canary fallback for blind validators when OAST is unavailable (Backlog/dev1_md §12).

Out-of-band callbacks (DNS / HTTP / SMTP) are the strongest evidence for
blind vulnerabilities — but a tenant may have OAST disabled by policy or
the listener may be temporarily unreachable. In those cases the validator
falls back to a *canary*: a unique, hard-to-collide marker the validator
embeds into the payload and then looks for in the response.

Four canary kinds are supported:

* :attr:`CanaryKind.TIME_DELAY` — the marker is an integer millisecond
  delay derived from a random nonce. The verifier compares the response
  time against the expected delay (with a tolerance window) to flag
  blind time-based SQL injection / SSRF.

* :attr:`CanaryKind.DOM_MARKER` — the marker is a random hex nonce that
  the validator expects to surface inside the HTML response body. Used
  for stored / reflected XSS where OAST cannot be used.

* :attr:`CanaryKind.HEADER_MARKER` — the marker is expected to land in
  a specific response header (e.g. injected CRLF that lifts a marker
  into ``Set-Cookie``). The verifier matches the value exactly.

* :attr:`CanaryKind.COOKIE_MARKER` — same as header marker but the
  verifier looks at the parsed cookie jar (case-insensitive name match).

Canary evidence is **always** weaker than OAST evidence: the verifier
returns a :class:`ConfidenceLevel` of at most ``MEDIUM`` regardless of
how strong the local match looks. Callers must surface that limitation
to the operator (the orchestrator does this automatically when it
records the canary's ``evidence_strategy`` on the finding).
"""

from __future__ import annotations

import logging
import re
import secrets
from datetime import datetime, timezone
from enum import StrEnum
from typing import Final, Protocol
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
from typing_extensions import Self

from src.pipeline.contracts.finding_dto import ConfidenceLevel


_logger = logging.getLogger(__name__)


_MARKER_BYTES: Final[int] = 16
_MIN_TIME_DELAY_MS: Final[int] = 250
_MAX_TIME_DELAY_MS: Final[int] = 30_000
_MAX_TARGET_HINT_LEN: Final[int] = 256
_MAX_HEADER_NAME_LEN: Final[int] = 64
_MAX_RESPONSE_TEXT_BYTES: Final[int] = 8 * 1024 * 1024  # 8 MiB scan cap

_MARKER_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_\-]{8,128}$")
_HEADER_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,64}$"
)
_TIME_DELAY_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]{3,5}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CanaryError(Exception):
    """Base for every canary-fallback error."""


class CanaryGenerationError(CanaryError):
    """Raised when the requested canary cannot be safely generated."""


class CanaryVerificationInputError(CanaryError):
    """Raised when verifier inputs are inconsistent with the canary kind."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class CanaryKind(StrEnum):
    """Closed taxonomy of canary marker kinds."""

    TIME_DELAY = "time_delay"
    DOM_MARKER = "dom_marker"
    HEADER_MARKER = "header_marker"
    COOKIE_MARKER = "cookie_marker"


class CanaryFailureReason(StrEnum):
    """Closed taxonomy of failed canary verifications.

    Surfacing structured reasons (rather than free-form strings) is a hard
    requirement of the verifier orchestrator: the failure list ends up in
    audit logs and customer-visible reports, so we need a finite set of
    documented codes to prevent log injection.
    """

    NO_RESPONSE = "canary_no_response"
    NO_MATCH = "canary_no_match"
    UNDER_TOLERANCE = "canary_under_tolerance"
    MISSING_HEADER = "canary_missing_header"
    MISSING_COOKIE = "canary_missing_cookie"
    KIND_MISMATCH = "canary_kind_mismatch"


class Canary(BaseModel):
    """A single canary marker emitted by :class:`CanaryGenerator`.

    The Pydantic model is deliberately small and frozen — the verifier
    reads it as opaque immutable data, never mutates it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    kind: CanaryKind
    secret_value: StrictStr = Field(min_length=3, max_length=128)
    created_at: datetime = Field(default_factory=_utcnow)
    target_hint: StrictStr | None = Field(default=None, max_length=_MAX_TARGET_HINT_LEN)
    header_name: StrictStr | None = Field(
        default=None, min_length=1, max_length=_MAX_HEADER_NAME_LEN
    )
    cookie_name: StrictStr | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("header_name")
    @classmethod
    def _validate_header_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _HEADER_NAME_RE.fullmatch(value):
            raise ValueError("header_name contains characters disallowed by RFC 7230")
        return value

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.kind is CanaryKind.TIME_DELAY:
            if not _TIME_DELAY_RE.fullmatch(self.secret_value):
                raise ValueError(
                    "time_delay canary secret_value must be a 3-5 digit ms value"
                )
            ms = int(self.secret_value)
            if ms < _MIN_TIME_DELAY_MS or ms > _MAX_TIME_DELAY_MS:
                raise ValueError(
                    f"time_delay canary out of bounds: {ms}ms not in "
                    f"[{_MIN_TIME_DELAY_MS}, {_MAX_TIME_DELAY_MS}]"
                )
            if self.header_name is not None or self.cookie_name is not None:
                raise ValueError(
                    "time_delay canary must not carry header_name or cookie_name"
                )
        else:
            if not _MARKER_VALUE_RE.fullmatch(self.secret_value):
                raise ValueError(
                    "marker canary secret_value must be 8-128 URL-safe characters"
                )
            if self.kind is CanaryKind.HEADER_MARKER and self.header_name is None:
                raise ValueError("header_marker canary requires header_name")
            if self.kind is CanaryKind.COOKIE_MARKER and self.cookie_name is None:
                raise ValueError("cookie_marker canary requires cookie_name")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return self

    @property
    def expected_delay_ms(self) -> int | None:
        """Return the expected delay for ``time_delay`` canaries."""
        if self.kind is not CanaryKind.TIME_DELAY:
            return None
        return int(self.secret_value)


class CanaryVerificationResult(BaseModel):
    """Outcome of :meth:`CanaryVerifier.verify`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verified: StrictBool
    canary_id: UUID
    canary_kind: CanaryKind
    confidence: ConfidenceLevel
    failure_reason: CanaryFailureReason | None = None
    evidence: dict[StrictStr, StrictStr] = Field(default_factory=dict)
    observed_response_time_ms: StrictInt | None = Field(default=None, ge=0, le=600_000)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.verified and self.failure_reason is not None:
            raise ValueError("verified=True is incompatible with a failure_reason")
        if not self.verified and self.failure_reason is None:
            raise ValueError("verified=False requires a structured failure_reason")
        if self.confidence not in {
            ConfidenceLevel.SUSPECTED,
            ConfidenceLevel.LIKELY,
            # Backlog §12: canary evidence is always at most MEDIUM strength.
            # We map "medium" to ``LIKELY`` (the closest finding-DTO level)
            # and reject CONFIRMED / EXPLOITABLE outright.
        }:
            raise ValueError(
                "canary confidence must be SUSPECTED or LIKELY (canary <= medium)"
            )
        return self


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class CanaryGenerator:
    """Mint :class:`Canary` instances backed by a CSPRNG.

    The generator is stateless, thread-safe, and side-effect free. The
    optional ``id_factory`` and ``token_factory`` arguments let tests
    inject deterministic values when needed; production code uses the
    defaults (UUID4 + :mod:`secrets`).
    """

    def __init__(
        self,
        *,
        id_factory: "_IdFn | None" = None,
        token_factory: "_TokenFn | None" = None,
        delay_ms_factory: "_DelayFn | None" = None,
        clock: "_ClockFn | None" = None,
    ) -> None:
        self._id_factory: _IdFn = id_factory or uuid4
        self._token_factory: _TokenFn = token_factory or _default_token_hex
        self._delay_ms_factory: _DelayFn = delay_ms_factory or _default_delay_ms
        self._clock: _ClockFn = clock or _utcnow

    def generate(
        self,
        kind: CanaryKind,
        *,
        target_hint: str | None = None,
        header_name: str | None = None,
        cookie_name: str | None = None,
    ) -> Canary:
        """Mint a new :class:`Canary` of the requested ``kind``."""
        if kind is CanaryKind.TIME_DELAY:
            if header_name is not None or cookie_name is not None:
                raise CanaryGenerationError(
                    "time_delay canary does not accept header_name or cookie_name"
                )
            secret = str(self._delay_ms_factory())
        elif kind is CanaryKind.DOM_MARKER:
            secret = self._token_factory(_MARKER_BYTES)
        elif kind is CanaryKind.HEADER_MARKER:
            if not header_name:
                raise CanaryGenerationError("header_marker canary requires header_name")
            secret = self._token_factory(_MARKER_BYTES)
        elif kind is CanaryKind.COOKIE_MARKER:
            if not cookie_name:
                raise CanaryGenerationError("cookie_marker canary requires cookie_name")
            secret = self._token_factory(_MARKER_BYTES)
        else:
            # Defensive: ``kind`` is a closed StrEnum so this branch is
            # unreachable, but mypy --strict insists on exhaustive
            # handling of the enum members.
            raise CanaryGenerationError(f"unknown canary kind {kind!r}")

        canary = Canary(
            id=self._id_factory(),
            kind=kind,
            secret_value=secret,
            created_at=self._clock(),
            target_hint=target_hint,
            header_name=header_name,
            cookie_name=cookie_name,
        )
        _logger.debug(
            "oast.canary.generated",
            extra={
                "canary_id": str(canary.id),
                "kind": kind.value,
                "target_hint": target_hint,
            },
        )
        return canary


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class CanaryVerifier:
    """Match a :class:`Canary` against a recorded HTTP-like response.

    The verifier is pure: given a canary and the observed response data,
    it returns a :class:`CanaryVerificationResult`. It does not perform
    HTTP requests itself — the validator (or tests) feeds it the
    response payload it already collected.

    Parameters
    ----------
    time_delay_tolerance_ratio
        Acceptable downwards deviation from the canary's expected delay.
        Defaults to ``0.10`` (10 %); the verifier rejects matches where
        ``observed < expected * (1 - tolerance)``. Upwards deviations
        always pass — slow responses still prove the delay was injected.
    time_delay_tolerance_absolute_ms
        Minimum tolerance in milliseconds, applied alongside the ratio
        to keep tiny expected delays robust against jitter.
    """

    def __init__(
        self,
        *,
        time_delay_tolerance_ratio: float = 0.10,
        time_delay_tolerance_absolute_ms: int = 100,
    ) -> None:
        if not 0 < time_delay_tolerance_ratio < 1:
            raise ValueError("time_delay_tolerance_ratio must be in (0, 1)")
        if time_delay_tolerance_absolute_ms < 0:
            raise ValueError("time_delay_tolerance_absolute_ms must be >= 0")
        self._tolerance_ratio = time_delay_tolerance_ratio
        self._tolerance_abs_ms = time_delay_tolerance_absolute_ms

    def verify(
        self,
        canary: Canary,
        *,
        response_text: str | None = None,
        response_headers: dict[str, str] | None = None,
        response_cookies: dict[str, str] | None = None,
        response_time_ms: int | None = None,
    ) -> CanaryVerificationResult:
        """Verify ``canary`` against the supplied response artefacts."""
        if canary.kind is CanaryKind.TIME_DELAY:
            return self._verify_time_delay(canary, response_time_ms)
        if canary.kind is CanaryKind.DOM_MARKER:
            return self._verify_dom_marker(canary, response_text)
        if canary.kind is CanaryKind.HEADER_MARKER:
            return self._verify_header_marker(canary, response_headers)
        if canary.kind is CanaryKind.COOKIE_MARKER:
            return self._verify_cookie_marker(canary, response_cookies)
        raise CanaryVerificationInputError(f"unknown canary kind {canary.kind!r}")

    # -- per-kind handlers ---------------------------------------------------

    def _verify_time_delay(
        self, canary: Canary, response_time_ms: int | None
    ) -> CanaryVerificationResult:
        expected = canary.expected_delay_ms
        if expected is None:
            raise CanaryVerificationInputError(
                "time_delay canary missing expected delay (corrupted model)"
            )
        if response_time_ms is None:
            return self._fail(
                canary,
                CanaryFailureReason.NO_RESPONSE,
                evidence={"expected_ms": str(expected)},
            )
        if response_time_ms < 0:
            raise CanaryVerificationInputError(
                "response_time_ms must be >= 0 (got negative)"
            )

        tolerance = max(
            int(expected * self._tolerance_ratio),
            self._tolerance_abs_ms,
        )
        threshold = max(0, expected - tolerance)
        if response_time_ms < threshold:
            return self._fail(
                canary,
                CanaryFailureReason.UNDER_TOLERANCE,
                evidence={
                    "expected_ms": str(expected),
                    "observed_ms": str(response_time_ms),
                    "threshold_ms": str(threshold),
                },
                observed_response_time_ms=response_time_ms,
            )
        return self._ok(
            canary,
            evidence={
                "expected_ms": str(expected),
                "observed_ms": str(response_time_ms),
                "threshold_ms": str(threshold),
            },
            observed_response_time_ms=response_time_ms,
        )

    def _verify_dom_marker(
        self, canary: Canary, response_text: str | None
    ) -> CanaryVerificationResult:
        if response_text is None:
            return self._fail(canary, CanaryFailureReason.NO_RESPONSE)
        if len(response_text) > _MAX_RESPONSE_TEXT_BYTES:
            # Defensive bound — refuse to scan multi-megabyte blobs since
            # they are almost certainly attacker-controlled noise.
            return self._fail(
                canary,
                CanaryFailureReason.NO_MATCH,
                evidence={"reason": "response_too_large"},
            )
        if canary.secret_value not in response_text:
            return self._fail(canary, CanaryFailureReason.NO_MATCH)
        return self._ok(
            canary,
            evidence={"matched_marker": canary.secret_value},
        )

    def _verify_header_marker(
        self, canary: Canary, response_headers: dict[str, str] | None
    ) -> CanaryVerificationResult:
        if response_headers is None:
            return self._fail(canary, CanaryFailureReason.NO_RESPONSE)
        assert canary.header_name is not None  # validated by the model
        target_name = canary.header_name.lower()
        # Headers are case-insensitive (RFC 7230 §3.2). Look up by lowered
        # name so callers can pass their natural-case dict.
        for name, value in response_headers.items():
            if name.lower() == target_name and canary.secret_value in value:
                return self._ok(
                    canary,
                    evidence={
                        "matched_marker": canary.secret_value,
                        "header": canary.header_name,
                    },
                )
        return self._fail(
            canary,
            CanaryFailureReason.MISSING_HEADER,
            evidence={"header": canary.header_name},
        )

    def _verify_cookie_marker(
        self, canary: Canary, response_cookies: dict[str, str] | None
    ) -> CanaryVerificationResult:
        if response_cookies is None:
            return self._fail(canary, CanaryFailureReason.NO_RESPONSE)
        assert canary.cookie_name is not None
        target = canary.cookie_name.lower()
        for name, value in response_cookies.items():
            if name.lower() == target and canary.secret_value in value:
                return self._ok(
                    canary,
                    evidence={
                        "matched_marker": canary.secret_value,
                        "cookie": canary.cookie_name,
                    },
                )
        return self._fail(
            canary,
            CanaryFailureReason.MISSING_COOKIE,
            evidence={"cookie": canary.cookie_name},
        )

    # -- result helpers ------------------------------------------------------

    @staticmethod
    def _ok(
        canary: Canary,
        *,
        evidence: dict[str, str],
        observed_response_time_ms: int | None = None,
    ) -> CanaryVerificationResult:
        return CanaryVerificationResult(
            verified=True,
            canary_id=canary.id,
            canary_kind=canary.kind,
            confidence=ConfidenceLevel.LIKELY,
            failure_reason=None,
            evidence=evidence,
            observed_response_time_ms=observed_response_time_ms,
        )

    @staticmethod
    def _fail(
        canary: Canary,
        reason: CanaryFailureReason,
        *,
        evidence: dict[str, str] | None = None,
        observed_response_time_ms: int | None = None,
    ) -> CanaryVerificationResult:
        return CanaryVerificationResult(
            verified=False,
            canary_id=canary.id,
            canary_kind=canary.kind,
            confidence=ConfidenceLevel.SUSPECTED,
            failure_reason=reason,
            evidence=dict(evidence or {}),
            observed_response_time_ms=observed_response_time_ms,
        )


# ---------------------------------------------------------------------------
# Helpers / type aliases
# ---------------------------------------------------------------------------


class _IdFn(Protocol):
    def __call__(self) -> UUID: ...


class _TokenFn(Protocol):
    def __call__(self, nbytes: int, /) -> str: ...


class _DelayFn(Protocol):
    def __call__(self) -> int: ...


class _ClockFn(Protocol):
    def __call__(self) -> datetime: ...


def _default_token_hex(nbytes: int) -> str:
    if nbytes <= 0 or nbytes > 32:
        raise CanaryGenerationError(
            "marker byte size must be in (0, 32] for safe encoding"
        )
    return secrets.token_hex(nbytes)


def _default_delay_ms() -> int:
    """Pick a random delay in the safe range, biased away from boundaries."""
    span = _MAX_TIME_DELAY_MS - _MIN_TIME_DELAY_MS
    # ``secrets.randbelow`` is uniform; we add the lower bound to keep
    # the result inside [_MIN_TIME_DELAY_MS, _MAX_TIME_DELAY_MS].
    return _MIN_TIME_DELAY_MS + secrets.randbelow(span + 1)


__all__ = [
    "Canary",
    "CanaryError",
    "CanaryFailureReason",
    "CanaryGenerationError",
    "CanaryGenerator",
    "CanaryKind",
    "CanaryVerificationInputError",
    "CanaryVerificationResult",
    "CanaryVerifier",
]
