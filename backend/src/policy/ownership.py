"""Customer ownership proof for ARGUS pre-flight (Backlog/dev1_md §8, §10).

Before ARGUS touches a target, the customer must prove they actually
control it. Six orthogonal challenge methods are supported across two
families:

DNS / HTTP family (Cycle 1)
    * **DNS_TXT** — the customer publishes a TXT record at
      ``_argus-ownership.<domain>`` whose value matches a 256-bit token
      issued by ARGUS.
    * **HTTP_HEADER** — the customer responds to a request with an
      ``X-Argus-Ownership`` header carrying the token.
    * **WEBROOT** — the customer serves the token bytes at
      ``https://<host>/.well-known/argus-ownership.txt``.

Cloud IAM family (Cycle 5 — ARG-043)
    * **AWS_STS_ASSUME_ROLE** — ARGUS calls
      ``sts:AssumeRole`` with an external_id; the customer's role trust
      policy pins ``sts:ExternalId == token`` (per-tenant secret).
    * **GCP_SERVICE_ACCOUNT_JWT** — the customer's service account signs
      a short-lived JWT; ARGUS validates audience / exp / signature via
      Google's JWKS.
    * **AZURE_MANAGED_IDENTITY** — the customer assigns a Managed
      Identity to ARGUS' workload; ARGUS exchanges it for an OAuth
      token whose ``oid`` / ``tid`` claims match the customer pin.

Hard rules:

* Tokens are 32 random bytes encoded as URL-safe base64 (no ``=`` padding,
  43 chars). They are bound to ``(tenant_id, target)`` and stored
  immutably in the proof store.
* Verification is constant-time at the comparison layer (see
  :func:`_constant_time_equals`).
* DNS resolution uses the ``dnspython`` library imported lazily inside
  :meth:`OwnershipVerifier._resolve_dns` so the package stays importable
  even when DNS is misconfigured at module load time.
* DRY-RUN mode skips the network call and resolves any registered
  challenge to "valid" — used by tests / staging environments.
* All HTTP traffic uses ``httpx`` with explicit timeouts, redirect
  disabled, and TLS verification on (callers can plug in a custom
  :class:`httpx.AsyncClient` for proxies).
* Cloud SDK clients are dependency-injected via :class:`Protocol` —
  never direct ``boto3.client(...)`` instantiation in production code.
* No raw HTTP body / DNS answer / cloud SDK response / token / ARN is
  ever written into a failure summary or audit-log payload; failure
  values are drawn from a closed taxonomy and identifiers are SHA-256
  hashed (truncated to 16 hex chars).
* Cloud-method verified proofs are cached for 600 s (10 min); cache
  eviction is strict at ``verified_at + 600 s``.

The verifier returns a :class:`OwnershipProof` on success — caller is
responsible for persisting / replaying it via the
:class:`OwnershipProofStore` protocol.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import secrets
import threading
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Final, Protocol, Self, runtime_checkable
from urllib.parse import urlparse, urlunparse
from uuid import UUID, uuid4

import httpx
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    model_validator,
)

from src.policy.audit import AuditEventType, AuditLogger


_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------


_TOKEN_BYTES: Final[int] = 32
_DNS_LABEL_PREFIX: Final[str] = "_argus-ownership"
_HTTP_HEADER_NAME: Final[str] = "X-Argus-Ownership"
_WEBROOT_PATH: Final[str] = "/.well-known/argus-ownership.txt"
_DEFAULT_HTTP_TIMEOUT_S: Final[float] = 10.0
_DEFAULT_DNS_TIMEOUT_S: Final[float] = 5.0
_DEFAULT_TTL_HOURS: Final[int] = 720  # 30 days

CLOUD_IAM_TTL_S: Final[int] = 600
"""Public constant — cloud_iam verified proofs cache TTL in seconds (10 min).

Sliding window per ARG-043. Strict bound: at ``verified_at + 600 s`` the
cache entry is evicted and the next ``verify(...)`` call re-issues a
fresh cloud SDK round-trip. Externalised so tests, dashboards, and
NetworkPolicy ratelimit budgets can read a single source of truth.
"""

CLOUD_SDK_TIMEOUT_S: Final[float] = 5.0
"""Public constant — per-call timeout (seconds) for any cloud SDK round-trip.

Strict upper bound; the cloud verifier wrappers raise
:class:`OwnershipTimeoutError` (mapped to a closed-taxonomy ``*_TIMEOUT``
reason) if the SDK does not return inside this budget. Keeps malicious
cloud-side stalls bounded.
"""


# ---------------------------------------------------------------------------
# Closed-taxonomy failure summaries
# ---------------------------------------------------------------------------


_REASON_NO_PROOF: Final[str] = "ownership_proof_missing"
_REASON_TOKEN_MISMATCH: Final[str] = "ownership_token_mismatch"
_REASON_DNS_TIMEOUT: Final[str] = "ownership_dns_timeout"
_REASON_DNS_NXDOMAIN: Final[str] = "ownership_dns_nxdomain"
_REASON_DNS_ERROR: Final[str] = "ownership_dns_error"
_REASON_HTTP_TIMEOUT: Final[str] = "ownership_http_timeout"
_REASON_HTTP_ERROR: Final[str] = "ownership_http_error"
_REASON_HTTP_STATUS: Final[str] = "ownership_http_status"
_REASON_HEADER_MISSING: Final[str] = "ownership_header_missing"
_REASON_INVALID_METHOD: Final[str] = "ownership_method_invalid"
_REASON_PROOF_EXPIRED: Final[str] = "ownership_proof_expired"

# ---------------------------------------------------------------------------
# Cloud IAM closed-taxonomy reasons (ARG-043)
# ---------------------------------------------------------------------------
#
# Each reason maps to ONE concrete cloud-side outcome. Failure values
# travel into :class:`AuditEvent.failure_summary` (truncated at 64 chars
# by Pydantic) and :class:`OwnershipVerificationError.summary`. Raw
# cloud SDK responses are NEVER interpolated into these strings — that
# is the entire point of the closed taxonomy.

REASON_AWS_STS_INVALID_ARN: Final[str] = "ownership_aws_sts_invalid_arn"
REASON_AWS_STS_ACCESS_DENIED: Final[str] = "ownership_aws_sts_access_denied"
REASON_AWS_STS_REGION_MISMATCH: Final[str] = "ownership_aws_sts_region_mismatch"
REASON_AWS_STS_TIMEOUT: Final[str] = "ownership_aws_sts_timeout"

REASON_GCP_SA_JWT_INVALID_AUDIENCE: Final[str] = "ownership_gcp_sa_jwt_invalid_audience"
REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID: Final[str] = (
    "ownership_gcp_sa_jwt_expired_or_not_yet_valid"
)
REASON_GCP_SA_JWT_TIMEOUT: Final[str] = "ownership_gcp_sa_jwt_timeout"

REASON_AZURE_MI_TENANT_MISMATCH: Final[str] = "ownership_azure_mi_tenant_mismatch"
REASON_AZURE_MI_RESOURCE_NOT_OWNED: Final[str] = "ownership_azure_mi_resource_not_owned"
REASON_AZURE_MI_TOKEN_REFRESH_FAILED: Final[str] = (
    "ownership_azure_mi_token_refresh_failed"
)
REASON_AZURE_MI_TIMEOUT: Final[str] = "ownership_azure_mi_timeout"

CLOUD_IAM_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {
        REASON_AWS_STS_INVALID_ARN,
        REASON_AWS_STS_ACCESS_DENIED,
        REASON_AWS_STS_REGION_MISMATCH,
        REASON_AWS_STS_TIMEOUT,
        REASON_GCP_SA_JWT_INVALID_AUDIENCE,
        REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID,
        REASON_GCP_SA_JWT_TIMEOUT,
        REASON_AZURE_MI_TENANT_MISMATCH,
        REASON_AZURE_MI_RESOURCE_NOT_OWNED,
        REASON_AZURE_MI_TOKEN_REFRESH_FAILED,
        REASON_AZURE_MI_TIMEOUT,
    }
)
"""Public projection of the cloud-IAM failure subset.

Useful for downstream filters (e.g. dashboards that want to count
"cloud-side denials" separately from DNS/HTTP failures) without
re-listing every constant.
"""

OWNERSHIP_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {
        _REASON_NO_PROOF,
        _REASON_TOKEN_MISMATCH,
        _REASON_DNS_TIMEOUT,
        _REASON_DNS_NXDOMAIN,
        _REASON_DNS_ERROR,
        _REASON_HTTP_TIMEOUT,
        _REASON_HTTP_ERROR,
        _REASON_HTTP_STATUS,
        _REASON_HEADER_MISSING,
        _REASON_INVALID_METHOD,
        _REASON_PROOF_EXPIRED,
    }
    | CLOUD_IAM_FAILURE_REASONS
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OwnershipVerificationError(Exception):
    """Raised when a verification attempt fails.

    ``summary`` is one of :data:`OWNERSHIP_FAILURE_REASONS` (closed taxonomy);
    safe to surface to the customer.
    """

    def __init__(self, summary: str) -> None:
        super().__init__(summary)
        self.summary = summary


class OwnershipTimeoutError(OwnershipVerificationError):
    """Specialisation of :class:`OwnershipVerificationError` for timeouts.

    Cloud verifier wrappers raise this when an SDK call exceeds
    :data:`CLOUD_SDK_TIMEOUT_S`. The dispatch layer maps it to the
    closed-taxonomy ``*_TIMEOUT`` reason for the originating cloud
    provider before propagating to the audit log.
    """


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class OwnershipMethod(StrEnum):
    """Supported challenge methods.

    The DNS / HTTP family ships from Cycle 1; the cloud-IAM family
    (``AWS_STS_ASSUME_ROLE`` / ``GCP_SERVICE_ACCOUNT_JWT`` /
    ``AZURE_MANAGED_IDENTITY``) was added in Cycle 5 ARG-043 and is
    dispatched to the corresponding verifier in
    :mod:`src.policy.cloud_iam`.
    """

    DNS_TXT = "dns_txt"
    HTTP_HEADER = "http_header"
    WEBROOT = "webroot"
    AWS_STS_ASSUME_ROLE = "aws_sts_assume_role"
    GCP_SERVICE_ACCOUNT_JWT = "gcp_service_account_jwt"
    AZURE_MANAGED_IDENTITY = "azure_managed_identity"


CLOUD_IAM_METHODS: Final[frozenset[OwnershipMethod]] = frozenset(
    {
        OwnershipMethod.AWS_STS_ASSUME_ROLE,
        OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
        OwnershipMethod.AZURE_MANAGED_IDENTITY,
    }
)
"""Subset of :class:`OwnershipMethod` requiring a cloud verifier."""


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class OwnershipChallenge(BaseModel):
    """The token + target pair the customer is asked to publish."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    challenge_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    target: StrictStr = Field(min_length=1, max_length=2_048)
    method: OwnershipMethod
    token: StrictStr = Field(min_length=43, max_length=43)
    issued_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("issued_at and expires_at must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be strictly later than issued_at")
        return self


class OwnershipProof(BaseModel):
    """A successfully verified challenge — proof customer X owns target Y."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proof_id: UUID = Field(default_factory=uuid4)
    challenge_id: UUID
    tenant_id: UUID
    target: StrictStr = Field(min_length=1, max_length=2_048)
    method: OwnershipMethod
    verified_at: datetime = Field(default_factory=_utcnow)
    valid_until: datetime
    notes: StrictStr = Field(default="", max_length=256)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.verified_at.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("verified_at and valid_until must be timezone-aware")
        if self.valid_until <= self.verified_at:
            raise ValueError("valid_until must be strictly later than verified_at")
        return self


# ---------------------------------------------------------------------------
# Persistence protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class OwnershipProofStore(Protocol):
    """Persistence backend for verified proofs.

    The default implementation (:class:`InMemoryOwnershipProofStore`) is
    process-local and intended for unit tests / dev. Production deployments
    swap in a Postgres-backed store keyed on ``(tenant_id, target)``.
    """

    def save(self, proof: OwnershipProof) -> None: ...

    def get(self, *, tenant_id: UUID, target: str) -> OwnershipProof | None: ...


class InMemoryOwnershipProofStore:
    """Process-local proof store (thread-safe)."""

    def __init__(self) -> None:
        self._proofs: dict[tuple[UUID, str], OwnershipProof] = {}
        self._lock = threading.Lock()

    def save(self, proof: OwnershipProof) -> None:
        key = (proof.tenant_id, proof.target.lower())
        with self._lock:
            self._proofs[key] = proof

    def get(self, *, tenant_id: UUID, target: str) -> OwnershipProof | None:
        with self._lock:
            return self._proofs.get((tenant_id, target.lower()))


# ---------------------------------------------------------------------------
# Cloud-IAM verifier protocol (ARG-043 — DI seam for AWS / GCP / Azure)
# ---------------------------------------------------------------------------


@runtime_checkable
class CloudOwnershipVerifierProtocol(Protocol):
    """Contract for per-cloud ownership verifiers.

    The dispatch layer in :class:`OwnershipVerifier` selects an
    implementation by :class:`OwnershipMethod` and delegates
    verification to its :meth:`verify` coroutine. Implementations live
    in :mod:`src.policy.cloud_iam` (``aws.py`` / ``gcp.py`` /
    ``azure.py``) and pin their cloud SDK clients via Protocol-typed
    constructor arguments — production code MUST NOT reach for a
    real SDK directly.

    The implementation is responsible for emitting its own audit-log
    entry on each verification attempt (success and failure); the
    dispatch layer additionally records the outcome at the
    :class:`OwnershipVerifier` boundary so chain-of-custody is
    end-to-end.
    """

    cloud_provider: str
    """Short tag — ``"aws"`` / ``"gcp"`` / ``"azure"`` — used when
    composing audit-log payloads and cache keys."""

    async def verify(self, challenge: OwnershipChallenge) -> OwnershipProof:
        """Verify ``challenge`` and return a fresh :class:`OwnershipProof`.

        Implementations MUST raise :class:`OwnershipVerificationError`
        (or :class:`OwnershipTimeoutError`) on failure with a closed
        taxonomy summary — never raw cloud SDK exception text.
        """


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class OwnershipVerifier:
    """Issues challenges and verifies them via DNS / HTTP.

    Parameters
    ----------
    store
        Persistence for verified :class:`OwnershipProof` instances.
    audit_logger
        :class:`AuditLogger` to emit verification outcomes to.
    http_client
        Optional ``httpx.AsyncClient``. When ``None`` (default), each
        verification call constructs a short-lived client with strict
        timeouts and ``follow_redirects=False``.
    dns_timeout_s
        DNS resolver timeout. Strict bound; never accepts ``None`` to keep
        DNS attacks bounded.
    http_timeout_s
        HTTP client total timeout (connect + read).
    dry_run
        When ``True``, every verify call short-circuits to "ok" without
        touching the network. Useful for staging environments where DNS /
        HTTP egress is unavailable.
    """

    def __init__(
        self,
        *,
        store: OwnershipProofStore,
        audit_logger: AuditLogger,
        http_client: httpx.AsyncClient | None = None,
        dns_timeout_s: float = _DEFAULT_DNS_TIMEOUT_S,
        http_timeout_s: float = _DEFAULT_HTTP_TIMEOUT_S,
        dry_run: bool = False,
        cloud_verifiers: Mapping[OwnershipMethod, CloudOwnershipVerifierProtocol]
        | None = None,
        cloud_iam_ttl_s: int = CLOUD_IAM_TTL_S,
    ) -> None:
        if dns_timeout_s <= 0 or dns_timeout_s > 60:
            raise ValueError("dns_timeout_s must be in (0, 60]")
        if http_timeout_s <= 0 or http_timeout_s > 60:
            raise ValueError("http_timeout_s must be in (0, 60]")
        if cloud_iam_ttl_s <= 0 or cloud_iam_ttl_s > 86_400:
            raise ValueError("cloud_iam_ttl_s must be in (0, 86_400]")
        # Validate that every entry of ``cloud_verifiers`` is keyed by a
        # cloud-family enum member; misuse here is a wiring bug, not a
        # runtime condition.
        verifiers: dict[OwnershipMethod, CloudOwnershipVerifierProtocol] = {}
        for method, verifier in (cloud_verifiers or {}).items():
            if method not in CLOUD_IAM_METHODS:
                raise ValueError(
                    f"cloud_verifiers key {method.value!r} is not a cloud-IAM method"
                )
            verifiers[method] = verifier
        self._store = store
        self._audit_logger = audit_logger
        self._http_client = http_client
        self._dns_timeout_s = dns_timeout_s
        self._http_timeout_s = http_timeout_s
        self._dry_run = dry_run
        self._cloud_verifiers = verifiers
        self._cloud_iam_ttl_s = cloud_iam_ttl_s
        # Cache key: (tenant_id, target_lower, method). Value: (proof,
        # cache_expires_at). Strict TTL — see ``CLOUD_IAM_TTL_S``.
        self._cloud_cache: dict[
            tuple[UUID, str, OwnershipMethod], tuple[OwnershipProof, datetime]
        ] = {}
        self._cloud_cache_lock = threading.Lock()

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    @property
    def cloud_iam_ttl_s(self) -> int:
        """Effective cloud-IAM cache TTL (seconds)."""
        return self._cloud_iam_ttl_s

    # -- Challenge issuance --------------------------------------------------

    def issue_challenge(
        self,
        *,
        tenant_id: UUID,
        target: str,
        method: OwnershipMethod,
        ttl: timedelta | None = None,
    ) -> OwnershipChallenge:
        """Create a fresh, non-guessable challenge token.

        Tokens are URL-safe base64 of 32 cryptographically-random bytes
        (``secrets.token_urlsafe``). The 43-char output matches what
        :class:`OwnershipChallenge` expects — no padding, no slashes.
        """
        if not target.strip():
            raise ValueError("target must be non-empty")
        ttl_value = ttl if ttl is not None else timedelta(hours=_DEFAULT_TTL_HOURS)
        if ttl_value.total_seconds() <= 0:
            raise ValueError("ttl must be a positive timedelta")
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        # ``token_urlsafe`` may include padding for non-multiple-of-3 sizes,
        # so trim explicit ``=``; for 32 bytes the result is always 43 chars
        # without padding, but the strip keeps the model invariant explicit.
        token = token.rstrip("=")
        if len(token) != 43:  # pragma: no cover — defensive on stdlib drift
            raise RuntimeError("ownership token has unexpected length")
        now = _utcnow()
        return OwnershipChallenge(
            tenant_id=tenant_id,
            target=target,
            method=method,
            token=token,
            issued_at=now,
            expires_at=now + ttl_value,
        )

    # -- Verification --------------------------------------------------------

    async def verify(
        self,
        challenge: OwnershipChallenge,
        *,
        actor_id: UUID | None = None,
    ) -> OwnershipProof:
        """Resolve the challenge and persist a proof on success.

        Raises :class:`OwnershipVerificationError` (or
        :class:`OwnershipTimeoutError`) with a closed-taxonomy
        ``summary`` on failure. Audit events are emitted in both
        branches.

        Dispatch table:

        * ``DNS_TXT`` / ``HTTP_HEADER`` / ``WEBROOT`` → handled
          locally via existing helpers.
        * ``AWS_STS_ASSUME_ROLE`` / ``GCP_SERVICE_ACCOUNT_JWT`` /
          ``AZURE_MANAGED_IDENTITY`` → delegated to the
          corresponding :class:`CloudOwnershipVerifierProtocol` from
          ``cloud_verifiers`` (constructor injected). A 600 s
          (``CLOUD_IAM_TTL_S``) cache short-circuits subsequent calls.
        """
        if challenge.expires_at <= _utcnow():
            self._emit(
                challenge=challenge,
                actor_id=actor_id,
                allowed=False,
                summary=_REASON_PROOF_EXPIRED,
            )
            raise OwnershipVerificationError(_REASON_PROOF_EXPIRED)

        if self._dry_run:
            return self._record_success(challenge=challenge, actor_id=actor_id)

        if challenge.method in CLOUD_IAM_METHODS:
            return await self._verify_cloud(challenge=challenge, actor_id=actor_id)

        try:
            if challenge.method is OwnershipMethod.DNS_TXT:
                await self._verify_dns(challenge)
            elif challenge.method is OwnershipMethod.HTTP_HEADER:
                await self._verify_http_header(challenge)
            elif challenge.method is OwnershipMethod.WEBROOT:
                await self._verify_webroot(challenge)
            else:  # pragma: no cover — exhaustive enum
                raise OwnershipVerificationError(_REASON_INVALID_METHOD)
        except OwnershipVerificationError as exc:
            self._emit(
                challenge=challenge,
                actor_id=actor_id,
                allowed=False,
                summary=exc.summary,
            )
            raise

        return self._record_success(challenge=challenge, actor_id=actor_id)

    # -- Cloud-IAM dispatch (ARG-043) ----------------------------------------

    async def _verify_cloud(
        self,
        *,
        challenge: OwnershipChallenge,
        actor_id: UUID | None,
    ) -> OwnershipProof:
        """Cache-aware dispatch to the configured cloud verifier.

        On cache hit (entry younger than ``CLOUD_IAM_TTL_S`` seconds)
        the cached :class:`OwnershipProof` is returned immediately and
        a ``cache_hit=True`` audit event is emitted; the cloud SDK is
        NOT called.

        On cache miss the registered
        :class:`CloudOwnershipVerifierProtocol` is invoked. Success is
        cached + audited + persisted. Failure (any
        :class:`OwnershipVerificationError`, including
        :class:`OwnershipTimeoutError`) is audited and re-raised
        without being cached.
        """
        verifier = self._cloud_verifiers.get(challenge.method)
        if verifier is None:
            self._emit(
                challenge=challenge,
                actor_id=actor_id,
                allowed=False,
                summary=_REASON_INVALID_METHOD,
            )
            raise OwnershipVerificationError(_REASON_INVALID_METHOD)

        cache_key = (
            challenge.tenant_id,
            challenge.target.lower(),
            challenge.method,
        )
        cached = self._cache_lookup(cache_key)
        if cached is not None:
            self._emit(
                challenge=challenge,
                actor_id=actor_id,
                allowed=True,
                summary=None,
                cache_hit=True,
            )
            return cached

        try:
            proof = await verifier.verify(challenge)
        except OwnershipVerificationError as exc:
            self._emit(
                challenge=challenge,
                actor_id=actor_id,
                allowed=False,
                summary=exc.summary,
                cache_hit=False,
            )
            raise

        self._store.save(proof)
        self._cache_store(cache_key, proof)
        self._emit(
            challenge=challenge,
            actor_id=actor_id,
            allowed=True,
            summary=None,
            cache_hit=False,
        )
        return proof

    def _cache_lookup(
        self, cache_key: tuple[UUID, str, OwnershipMethod]
    ) -> OwnershipProof | None:
        """Return a cached proof iff it has not yet expired."""
        with self._cloud_cache_lock:
            entry = self._cloud_cache.get(cache_key)
            if entry is None:
                return None
            proof, cache_expires_at = entry
            if cache_expires_at <= _utcnow():
                # Strict expiry — evict and force re-verify.
                self._cloud_cache.pop(cache_key, None)
                return None
            return proof

    def _cache_store(
        self,
        cache_key: tuple[UUID, str, OwnershipMethod],
        proof: OwnershipProof,
    ) -> None:
        """Insert ``proof`` into the cache with a hard TTL of ``CLOUD_IAM_TTL_S``."""
        cache_expires_at = _utcnow() + timedelta(seconds=self._cloud_iam_ttl_s)
        with self._cloud_cache_lock:
            self._cloud_cache[cache_key] = (proof, cache_expires_at)

    def cloud_cache_clear(self) -> None:
        """Operator hook — drop every cloud cache entry.

        Useful for ``POST /admin/cloud-iam/cache/flush`` and tests that
        want an explicit reset between scenarios. Does NOT touch the
        durable :class:`OwnershipProofStore`.
        """
        with self._cloud_cache_lock:
            self._cloud_cache.clear()

    # -- Method-specific helpers --------------------------------------------

    async def _verify_dns(self, challenge: OwnershipChallenge) -> None:
        host = _extract_dns_host(challenge.target)
        record = f"{_DNS_LABEL_PREFIX}.{host}"
        try:
            answers = await self._resolve_dns(record)
        except OwnershipVerificationError:
            raise
        for value in answers:
            if _constant_time_equals(value, challenge.token):
                return
        raise OwnershipVerificationError(_REASON_TOKEN_MISMATCH)

    async def _verify_http_header(self, challenge: OwnershipChallenge) -> None:
        url = _build_http_url(challenge.target)
        client = self._http_client or self._build_http_client()
        try:
            response = await client.get(url)
        except httpx.TimeoutException as exc:
            self._log_http_error(challenge, "timeout", exc)
            raise OwnershipVerificationError(_REASON_HTTP_TIMEOUT) from exc
        except httpx.HTTPError as exc:
            self._log_http_error(challenge, "http_error", exc)
            raise OwnershipVerificationError(_REASON_HTTP_ERROR) from exc
        finally:
            if self._http_client is None:
                await client.aclose()
        if response.status_code >= 400:
            raise OwnershipVerificationError(_REASON_HTTP_STATUS)
        header = response.headers.get(_HTTP_HEADER_NAME)
        if header is None:
            raise OwnershipVerificationError(_REASON_HEADER_MISSING)
        if not _constant_time_equals(header.strip(), challenge.token):
            raise OwnershipVerificationError(_REASON_TOKEN_MISMATCH)

    async def _verify_webroot(self, challenge: OwnershipChallenge) -> None:
        url = _build_http_url(challenge.target, path=_WEBROOT_PATH)
        client = self._http_client or self._build_http_client()
        try:
            response = await client.get(url)
        except httpx.TimeoutException as exc:
            self._log_http_error(challenge, "timeout", exc)
            raise OwnershipVerificationError(_REASON_HTTP_TIMEOUT) from exc
        except httpx.HTTPError as exc:
            self._log_http_error(challenge, "http_error", exc)
            raise OwnershipVerificationError(_REASON_HTTP_ERROR) from exc
        finally:
            if self._http_client is None:
                await client.aclose()
        if response.status_code != 200:
            raise OwnershipVerificationError(_REASON_HTTP_STATUS)
        body = response.text.strip()
        if not _constant_time_equals(body, challenge.token):
            raise OwnershipVerificationError(_REASON_TOKEN_MISMATCH)

    async def _resolve_dns(self, fqdn: str) -> list[str]:
        """Resolve TXT records for ``fqdn``. ``dnspython`` is imported lazily."""
        try:
            import dns.asyncresolver as dnsresolver  # noqa: PLC0415 — lazy on purpose
            import dns.exception as dnsexc  # noqa: PLC0415 — lazy on purpose
            import dns.rdatatype as dnsrdatatype  # noqa: PLC0415 — lazy on purpose
            import dns.resolver as dnsresolver_sync  # noqa: PLC0415 — lazy on purpose
        except ImportError as exc:  # pragma: no cover — declared dep
            raise OwnershipVerificationError(_REASON_DNS_ERROR) from exc

        resolver = dnsresolver.Resolver()
        resolver.lifetime = self._dns_timeout_s
        resolver.timeout = self._dns_timeout_s
        try:
            answer = await asyncio.wait_for(
                resolver.resolve(fqdn, dnsrdatatype.TXT),
                timeout=self._dns_timeout_s,
            )
        except (dnsresolver_sync.NXDOMAIN, dnsresolver_sync.NoAnswer) as exc:
            self._log_dns_error(fqdn, "nxdomain", exc)
            raise OwnershipVerificationError(_REASON_DNS_NXDOMAIN) from exc
        except (asyncio.TimeoutError, dnsexc.Timeout) as exc:
            self._log_dns_error(fqdn, "timeout", exc)
            raise OwnershipVerificationError(_REASON_DNS_TIMEOUT) from exc
        except dnsexc.DNSException as exc:
            self._log_dns_error(fqdn, "dns_error", exc)
            raise OwnershipVerificationError(_REASON_DNS_ERROR) from exc

        out: list[str] = []
        for rdata in answer:
            try:
                strings = rdata.strings
            except AttributeError:
                continue
            for chunk in strings:
                if isinstance(chunk, bytes):
                    out.append(chunk.decode("ascii", errors="replace").strip('"'))
                else:
                    out.append(str(chunk).strip('"'))
        return out

    # -- Internal helpers ----------------------------------------------------

    def _build_http_client(self) -> httpx.AsyncClient:
        timeout = httpx.Timeout(
            self._http_timeout_s,
            connect=self._http_timeout_s,
            read=self._http_timeout_s,
        )
        limits = httpx.Limits(max_connections=4, max_keepalive_connections=0)
        return httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": "ARGUS-OwnershipVerifier/1.0"},
        )

    def _record_success(
        self,
        *,
        challenge: OwnershipChallenge,
        actor_id: UUID | None,
    ) -> OwnershipProof:
        proof = OwnershipProof(
            challenge_id=challenge.challenge_id,
            tenant_id=challenge.tenant_id,
            target=challenge.target,
            method=challenge.method,
            valid_until=challenge.expires_at,
            notes="dry-run" if self._dry_run else "",
        )
        self._store.save(proof)
        self._emit(
            challenge=challenge,
            actor_id=actor_id,
            allowed=True,
            summary=None,
        )
        return proof

    def _emit(
        self,
        *,
        challenge: OwnershipChallenge,
        actor_id: UUID | None,
        allowed: bool,
        summary: str | None,
        cache_hit: bool | None = None,
    ) -> None:
        # Sanitise identifiers BEFORE building the payload so a future
        # leak vector (someone refactoring the call site) cannot bypass
        # the SHA-256 reduction. Truncating to 16 hex chars preserves
        # cardinality discipline (~5e18 buckets) without exposing the
        # raw token / ARN / SA email.
        target_hash = hash_identifier(challenge.target)
        payload: dict[str, object] = {
            "method": challenge.method,
            "challenge_id": challenge.challenge_id,
            "target_hash": target_hash,
        }
        if cache_hit is not None:
            payload["cache_hit"] = cache_hit
        self._audit_logger.emit(
            event_type=AuditEventType.OWNERSHIP_VERIFY,
            tenant_id=challenge.tenant_id,
            actor_id=actor_id,
            decision_allowed=allowed,
            failure_summary=summary,
            payload=payload,
        )

    @staticmethod
    def _log_dns_error(fqdn: str, kind: str, exc: BaseException) -> None:
        _logger.warning(
            "policy.ownership.dns_failure",
            extra={
                "fqdn": fqdn,
                "kind": kind,
                "error_class": type(exc).__name__,
            },
        )

    @staticmethod
    def _log_http_error(
        challenge: OwnershipChallenge, kind: str, exc: BaseException
    ) -> None:
        _logger.warning(
            "policy.ownership.http_failure",
            extra={
                "method": challenge.method.value,
                "kind": kind,
                "error_class": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# URL / DNS helpers
# ---------------------------------------------------------------------------


def _extract_dns_host(target: str) -> str:
    """Return the DNS-relevant host portion of ``target`` (lowercase, no port).

    Accepts URLs (``https://example.com/path``), bare hosts
    (``api.example.com``), or fully-qualified domains.
    """
    candidate = target.strip().lower()
    if "://" in candidate:
        parsed = urlparse(candidate)
        if not parsed.hostname:
            raise OwnershipVerificationError(_REASON_INVALID_METHOD)
        return parsed.hostname
    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]
    if ":" in candidate and not candidate.startswith("["):
        candidate = candidate.split(":", 1)[0]
    if not candidate:
        raise OwnershipVerificationError(_REASON_INVALID_METHOD)
    return candidate


def _build_http_url(target: str, *, path: str | None = None) -> str:
    """Construct a verification URL from ``target``.

    Bare hosts are upgraded to ``https://<host>``. Existing schemes are
    preserved verbatim. The optional ``path`` argument replaces the
    target's path (used by the WEBROOT method).
    """
    candidate = target.strip()
    parsed = urlparse(candidate)
    if not parsed.scheme:
        parsed = urlparse(f"https://{candidate}")
    if not parsed.hostname:
        raise OwnershipVerificationError(_REASON_INVALID_METHOD)
    new_path = path if path is not None else parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, new_path, "", "", ""))


def _constant_time_equals(left: str, right: str) -> bool:
    """Constant-time string equality (UTF-8 byte comparison)."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


_HASH_PREFIX_LEN: Final[int] = 16


def hash_identifier(identifier: str) -> str:
    """Return the lowercase first-16 hex chars of ``sha256(identifier)``.

    Public utility used by both the dispatch layer and the cloud
    verifier modules so audit-log payloads always carry the SAME
    truncation. 16 hex chars = 64 bits of cardinality — sufficient for
    forensic correlation (~1.8e19 buckets) while keeping the payload
    free of raw tokens / ARNs / service-account emails / Azure object
    IDs.
    """
    digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
    return digest[:_HASH_PREFIX_LEN]


__all__ = [
    "CLOUD_IAM_FAILURE_REASONS",
    "CLOUD_IAM_METHODS",
    "CLOUD_IAM_TTL_S",
    "CLOUD_SDK_TIMEOUT_S",
    "CloudOwnershipVerifierProtocol",
    "InMemoryOwnershipProofStore",
    "OWNERSHIP_FAILURE_REASONS",
    "OwnershipChallenge",
    "OwnershipMethod",
    "OwnershipProof",
    "OwnershipProofStore",
    "OwnershipTimeoutError",
    "OwnershipVerificationError",
    "OwnershipVerifier",
    "REASON_AWS_STS_ACCESS_DENIED",
    "REASON_AWS_STS_INVALID_ARN",
    "REASON_AWS_STS_REGION_MISMATCH",
    "REASON_AWS_STS_TIMEOUT",
    "REASON_AZURE_MI_RESOURCE_NOT_OWNED",
    "REASON_AZURE_MI_TENANT_MISMATCH",
    "REASON_AZURE_MI_TIMEOUT",
    "REASON_AZURE_MI_TOKEN_REFRESH_FAILED",
    "REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID",
    "REASON_GCP_SA_JWT_INVALID_AUDIENCE",
    "REASON_GCP_SA_JWT_TIMEOUT",
    "hash_identifier",
]
