"""Shared primitives for cloud-IAM ownership verifiers (ARG-043).

Every public symbol below MUST stay importable without dragging in any
cloud SDK — the SDKs themselves are imported lazily inside the
provider-specific modules so a deployment without ``boto3`` /
``google-auth`` / ``azure-identity`` can still load
:mod:`src.policy.ownership` for unit tests.

Design tenets (mirror the ARG-043 spec):

* **No raw secrets, ever.** Tokens, role ARNs, JWT bodies, OAuth
  bearer tokens, service-account emails and Azure object IDs are all
  reduced to SHA-256 / 16-hex-char digests via :func:`hash_identifier`
  before reaching audit-log payloads or log lines.
* **Closed taxonomy.** Failure summaries are drawn from
  :data:`src.policy.ownership.CLOUD_IAM_FAILURE_REASONS`. Verifier
  modules ALWAYS map cloud SDK error classes to a known reason via the
  helpers below — never emit raw exception strings.
* **Bounded latency.** Cloud SDK calls are wrapped in
  :func:`run_with_timeout` so a hostile cloud-side stall cannot tie up
  the verification path beyond
  :data:`src.policy.ownership.CLOUD_SDK_TIMEOUT_S` seconds.
* **Constant-time secret compares.** Token / external-id comparisons
  use :func:`constant_time_str_equal` which delegates to
  :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Final, TypeVar
from uuid import UUID

from src.policy.audit import AuditEventType, AuditLogger
from src.policy.ownership import (
    CLOUD_SDK_TIMEOUT_S,
    OwnershipChallenge,
    OwnershipMethod,
    OwnershipProof,
    OwnershipTimeoutError,
    OwnershipVerificationError,
    hash_identifier,
)

_logger = logging.getLogger(__name__)

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


CLOUD_PROOF_DEFAULT_TTL: Final[timedelta] = timedelta(hours=1)
"""Default ``valid_until - verified_at`` for cloud-IAM proofs (1h).

The dispatch-layer cache TTL is shorter (10 min) so tenants that re-key
or revoke a cloud principal see ARGUS forget the proof inside a minute.
This 1h value is the durable proof TTL persisted in
:class:`OwnershipProofStore`.
"""


@dataclass(frozen=True, slots=True)
class CloudPrincipalDescriptor:
    """Hashed, audit-safe summary of the principal being verified.

    Constructed by each verifier module from the challenge/target so the
    dispatch layer + audit log always emit identical hashed keys.
    """

    cloud_provider: str
    """``"aws"`` / ``"gcp"`` / ``"azure"``."""

    principal_kind: str
    """Cloud-side primitive — e.g. ``"role_arn"`` / ``"service_account"``
    / ``"managed_identity_object_id"``. Stable token, not free-form."""

    principal_hash: str
    """16-hex SHA-256 truncation of the raw principal identifier."""

    target_hash: str
    """16-hex SHA-256 truncation of ``OwnershipChallenge.target``."""

    def to_audit_payload(self) -> dict[str, str]:
        """Render the descriptor as a JSON-safe ``dict[str, str]``."""
        return {
            "cloud_provider": self.cloud_provider,
            "principal_kind": self.principal_kind,
            "principal_hash": self.principal_hash,
            "target_hash": self.target_hash,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    """Return ``datetime.now(tz=UTC)`` — single source of truth."""
    return datetime.now(tz=timezone.utc)


def constant_time_str_equal(left: str, right: str) -> bool:
    """Constant-time UTF-8 string equality."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def descriptor_from_challenge(
    *,
    cloud_provider: str,
    principal_kind: str,
    principal_identifier: str,
    challenge: OwnershipChallenge,
) -> CloudPrincipalDescriptor:
    """Build a :class:`CloudPrincipalDescriptor` from raw inputs.

    ``principal_identifier`` and ``challenge.target`` are hashed via
    :func:`hash_identifier` so callers can hand the descriptor to the
    audit logger without leaking the original strings.
    """
    return CloudPrincipalDescriptor(
        cloud_provider=cloud_provider,
        principal_kind=principal_kind,
        principal_hash=hash_identifier(principal_identifier),
        target_hash=hash_identifier(challenge.target),
    )


def make_proof(
    *,
    challenge: OwnershipChallenge,
    notes: str = "",
    ttl: timedelta = CLOUD_PROOF_DEFAULT_TTL,
) -> OwnershipProof:
    """Build a fresh :class:`OwnershipProof` for a cloud verification.

    ``valid_until = verified_at + ttl``, capped against
    ``challenge.expires_at`` so a successful verify never outlives the
    challenge itself.
    """
    if ttl.total_seconds() <= 0:
        raise ValueError("ttl must be positive")
    verified_at = utcnow()
    valid_until = min(verified_at + ttl, challenge.expires_at)
    if valid_until <= verified_at:
        valid_until = verified_at + timedelta(seconds=1)
    if valid_until > challenge.expires_at:
        valid_until = challenge.expires_at
    if len(notes) > 256:
        notes = notes[:256]
    return OwnershipProof(
        challenge_id=challenge.challenge_id,
        tenant_id=challenge.tenant_id,
        target=challenge.target,
        method=challenge.method,
        verified_at=verified_at,
        valid_until=valid_until,
        notes=notes,
    )


async def run_with_timeout(
    coro_factory: Callable[[], Awaitable[T]],
    *,
    timeout_s: float | None = None,
    timeout_reason: str,
) -> T:
    """Run a coroutine factory under a strict timeout.

    On timeout, raises :class:`OwnershipTimeoutError(timeout_reason)`
    — caller MUST pass a closed-taxonomy reason. ``coro_factory``
    rather than a coroutine is required so retries / repeated calls do
    not need to re-create the awaitable in the call site.

    ``timeout_s`` defaults to the *current* value of
    :data:`src.policy.ownership.CLOUD_SDK_TIMEOUT_S`. Reading it at
    call time keeps unit tests and operators able to monkeypatch the
    constant without rebinding closures.
    """
    if timeout_reason not in _ALLOWED_TIMEOUT_REASONS:
        raise ValueError(
            f"timeout_reason {timeout_reason!r} is not a closed-taxonomy timeout reason"
        )
    effective = timeout_s if timeout_s is not None else CLOUD_SDK_TIMEOUT_S
    if effective <= 0:
        raise ValueError("timeout_s must be positive")
    try:
        return await asyncio.wait_for(coro_factory(), timeout=effective)
    except asyncio.TimeoutError as exc:
        raise OwnershipTimeoutError(timeout_reason) from exc


_ALLOWED_TIMEOUT_REASONS: Final[frozenset[str]] = frozenset(
    {
        "ownership_aws_sts_timeout",
        "ownership_gcp_sa_jwt_timeout",
        "ownership_azure_mi_timeout",
    }
)


def emit_cloud_attempt(
    *,
    audit_logger: AuditLogger,
    challenge: OwnershipChallenge,
    actor_id: UUID | None,
    descriptor: CloudPrincipalDescriptor,
    allowed: bool,
    summary: str | None,
    extra: dict[str, object] | None = None,
) -> None:
    """Emit an audit log entry for a single cloud verification attempt.

    The payload is composed exclusively from hashed identifiers + the
    closed-taxonomy summary; raw cloud SDK responses must NOT be passed
    in via ``extra``. Callers can include scalar diagnostic fields
    (e.g. ``{"sdk_attempt": 1}``) but never tokens / ARNs / emails.
    """
    payload: dict[str, object] = {
        "cloud_attempt": True,
        "method": challenge.method,
        "challenge_id": challenge.challenge_id,
        **descriptor.to_audit_payload(),
    }
    if extra:
        for key, value in extra.items():
            if key in {
                "principal_arn",
                "principal_email",
                "token",
                "jwt",
                "external_id",
                "client_secret",
                "access_token",
                "id_token",
                "raw_response",
            }:
                raise ValueError(
                    "extra cloud audit field would leak a raw secret"
                )
            payload[key] = value
    audit_logger.emit(
        event_type=AuditEventType.OWNERSHIP_VERIFY,
        tenant_id=challenge.tenant_id,
        actor_id=actor_id,
        decision_allowed=allowed,
        failure_summary=summary,
        payload=payload,
    )


def redact_token(value: str | None, *, keep: int = 4) -> str:
    """Return a printable-but-redacted form of ``value`` for diagnostics.

    Used ONLY when a structural log line absolutely needs to mention
    that a token existed (e.g. ``"sts assumed: %s"``). The caller
    should still prefer :func:`hash_identifier` for any persisted
    payload. ``keep`` defaults to 4 chars at most so the returned
    string never reveals enough entropy to be replayed.
    """
    if value is None:
        return "<none>"
    keep = max(0, min(keep, 4))
    if len(value) <= keep:
        return "<redacted>"
    return f"{value[:keep]}***[redacted, len={len(value)}]"


# ---------------------------------------------------------------------------
# Cloud-method ↔ timeout-reason ↔ provider tag table
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CloudMethodMetadata:
    """Per-method static metadata used by :class:`OwnershipVerifier`."""

    cloud_provider: str
    timeout_reason: str
    invalid_method_reason: str


CLOUD_METHOD_METADATA: Final[dict[OwnershipMethod, CloudMethodMetadata]] = {
    OwnershipMethod.AWS_STS_ASSUME_ROLE: CloudMethodMetadata(
        cloud_provider="aws",
        timeout_reason="ownership_aws_sts_timeout",
        invalid_method_reason="ownership_aws_sts_invalid_arn",
    ),
    OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT: CloudMethodMetadata(
        cloud_provider="gcp",
        timeout_reason="ownership_gcp_sa_jwt_timeout",
        invalid_method_reason="ownership_gcp_sa_jwt_invalid_audience",
    ),
    OwnershipMethod.AZURE_MANAGED_IDENTITY: CloudMethodMetadata(
        cloud_provider="azure",
        timeout_reason="ownership_azure_mi_timeout",
        invalid_method_reason="ownership_azure_mi_token_refresh_failed",
    ),
}


def metadata_for(method: OwnershipMethod) -> CloudMethodMetadata:
    """Look up :class:`CloudMethodMetadata` for ``method``.

    Raises :class:`OwnershipVerificationError` if ``method`` is not a
    cloud-IAM method — guards against accidental dispatch from the
    DNS / HTTP code path.
    """
    meta = CLOUD_METHOD_METADATA.get(method)
    if meta is None:
        raise OwnershipVerificationError("ownership_method_invalid")
    return meta


__all__ = [
    "CLOUD_METHOD_METADATA",
    "CLOUD_PROOF_DEFAULT_TTL",
    "CloudMethodMetadata",
    "CloudPrincipalDescriptor",
    "constant_time_str_equal",
    "descriptor_from_challenge",
    "emit_cloud_attempt",
    "hash_identifier",
    "make_proof",
    "metadata_for",
    "redact_token",
    "run_with_timeout",
    "utcnow",
]
