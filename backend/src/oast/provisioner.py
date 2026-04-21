"""Out-of-band token provisioner for the ARGUS OAST plane (Backlog/dev1_md §11).

The :class:`OASTProvisioner` is the issuer of every blind-vulnerability
correlation token used by the validator (sqli time-blind, ssrf, blind XSS,
RCE OAST, XXE OAST, etc.). A token bundles three orthogonal callback channels
under a single identity so the same token can be used regardless of which
listener observes the interaction first:

* ``subdomain`` — fully-qualified DNS label, e.g.
  ``argus-7f3a2b1c4e9d8a31.oast.argus.local``. Resolves to the OAST DNS
  listener. The label carries 64 bits of CSPRNG entropy (16 hex chars).
* ``path_token`` — short URL-safe token used on the canonical
  ``https://oast.argus.local/p/<path_token>`` endpoint.
* ``dns_label`` — the leading label only, useful for crafting payloads where
  the attacker controls the host portion (``GET / HTTP/1.1\\nHost: <label>.oast``).

Two concrete implementations live next to the protocol:

* :class:`InternalOASTProvisioner` — tracks issued tokens in process memory
  with TTL-based expiry. Suitable for the in-cluster development listener and
  unit tests; production deployments swap the in-memory store for a
  database-backed equivalent that follows the same protocol.
* :class:`DisabledOASTProvisioner` — short-circuits ``issue`` with
  :class:`OASTUnavailableError`. Used when the tenant policy forbids OAST or
  the operator deliberately disables the channel.

The provisioner is **synchronous and side-effect free** with respect to the
network. All DNS / HTTP / SMTP listeners live behind
:mod:`src.oast.listener_protocol`; the provisioner only mints identifiers and
manages bookkeeping.
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_validator,
    model_validator,
)
from typing_extensions import Self


_logger = logging.getLogger(__name__)


# RFC 1035 §2.3.4 — single label MUST be at most 63 octets, total domain name
# MUST be at most 253 octets. Path tokens follow the URL-safe alphabet from
# RFC 3986 ``unreserved`` (subset).
_MAX_DNS_LABEL_LEN: Final[int] = 63
_MAX_DNS_NAME_LEN: Final[int] = 253
_MAX_PATH_TOKEN_LEN: Final[int] = 64
_MIN_TTL_SECONDS: Final[int] = 30
_MAX_TTL_SECONDS: Final[int] = 24 * 3600  # 24h hard ceiling per Backlog §11
_DEFAULT_TTL: Final[timedelta] = timedelta(minutes=10)
_DEFAULT_PURGE_GRACE: Final[timedelta] = timedelta(minutes=5)

# DNS label layout: ``argus-`` prefix + 64 bits (16 hex chars) of CSPRNG entropy.
# 64 bits is the minimum that keeps brute-force token guessing infeasible at
# OAST scale (≥ 2^32 callbacks before a 50% birthday-collision). Bumped from
# 48 bits during the post-ARG-007 review.
_DNS_LABEL_PREFIX: Final[str] = "argus-"
_DNS_LABEL_HEX_BYTES: Final[int] = 8  # 16 hex chars = 64 bits of entropy
_DNS_LABEL_FULL_LEN: Final[int] = len(_DNS_LABEL_PREFIX) + _DNS_LABEL_HEX_BYTES * 2
# Reserve label length + the joining ``.`` when validating ``base_domain``.
_BASE_DOMAIN_HEADROOM: Final[int] = _DNS_LABEL_FULL_LEN + 1
_PATH_TOKEN_BYTES: Final[int] = 16  # 32 hex chars = 128 bits

_DNS_LABEL_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
)
_DNS_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)
_PATH_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")

# Family identifiers come from src.payloads.registry._FAMILY_ID_PATTERN; we
# duplicate the shape here so the provisioner does not depend on the payload
# layer at import time.
_FAMILY_HINT_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z_][a-z0-9_]{2,32}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OASTError(Exception):
    """Base for every OAST-plane error."""


class OASTUnavailableError(OASTError):
    """Raised when token issuance is impossible (disabled / unreachable)."""


class OASTProvisioningError(OASTError):
    """Raised on misconfiguration that prevents safe token construction."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class OASTBackendKind(StrEnum):
    """Discriminator for the underlying OAST listener implementation."""

    INTERNAL = "internal"
    BURP_COLLABORATOR = "burp_collaborator"
    INTERACTSH = "interactsh"
    DISABLED = "disabled"


class OASTToken(BaseModel):
    """Immutable identity for a single OAST channel binding.

    A token is minted once per validation attempt by the orchestrator and
    embedded into the payload bundle by :func:`src.oast.integration
    .attach_oast_token_to_payload_request`. The validator runs in the
    sandbox; when the target reaches out to the OAST host the listener
    captures the interaction and the correlator resolves it back to this
    token via :attr:`id` (lookup is stable and tamper-evident because the
    subdomain embeds the same id-hex as the path token).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    tenant_id: UUID
    scan_id: UUID
    validation_job_id: UUID | None = None
    subdomain: StrictStr = Field(min_length=8, max_length=_MAX_DNS_NAME_LEN)
    path_token: StrictStr = Field(min_length=8, max_length=_MAX_PATH_TOKEN_LEN)
    dns_label: StrictStr = Field(min_length=4, max_length=_MAX_DNS_LABEL_LEN)
    backend: OASTBackendKind = OASTBackendKind.INTERNAL
    created_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime
    reserved_for_family: StrictStr | None = Field(
        default=None, min_length=3, max_length=32
    )

    @field_validator("dns_label")
    @classmethod
    def _check_dns_label(cls, value: str) -> str:
        if not _DNS_LABEL_RE.fullmatch(value):
            raise ValueError(
                "dns_label must match RFC 1035 (lowercase, hyphens, "
                "1-63 chars, no leading/trailing hyphen)"
            )
        return value

    @field_validator("subdomain")
    @classmethod
    def _check_subdomain(cls, value: str) -> str:
        lowered = value.strip().rstrip(".")
        if "." not in lowered:
            raise ValueError(
                "subdomain must be a fully-qualified DNS name with at least one dot"
            )
        if not _DNS_DOMAIN_RE.fullmatch(lowered):
            raise ValueError(
                "subdomain contains characters not permitted by RFC 1035 / 1123"
            )
        for label in lowered.split("."):
            if len(label) > _MAX_DNS_LABEL_LEN:
                raise ValueError(
                    f"subdomain label {label!r} exceeds 63-character DNS limit"
                )
        return lowered

    @field_validator("path_token")
    @classmethod
    def _check_path_token(cls, value: str) -> str:
        if not _PATH_TOKEN_RE.fullmatch(value):
            raise ValueError(
                "path_token must be 8-64 chars from the URL-safe alphabet "
                "([A-Za-z0-9_-])"
            )
        return value

    @field_validator("reserved_for_family")
    @classmethod
    def _check_family(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _FAMILY_HINT_RE.fullmatch(value):
            raise ValueError("reserved_for_family must match ^[a-z_][a-z0-9_]{2,32}$")
        return value

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be strictly after created_at")
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("created_at / expires_at must be timezone-aware")
        if not self.subdomain.startswith(self.dns_label + "."):
            raise ValueError("subdomain must start with the issued dns_label")
        return self

    @property
    def http_url(self) -> str:
        """Canonical HTTPS callback URL for the path-based channel."""
        host = (
            self.subdomain.split(".", 1)[1] if "." in self.subdomain else self.subdomain
        )
        return f"https://{host}/p/{self.path_token}"

    def is_active_at(self, moment: datetime) -> bool:
        """Return ``True`` if the token has not yet expired at ``moment``."""
        if moment.tzinfo is None:
            raise ValueError("moment must be timezone-aware")
        return moment < self.expires_at


# ---------------------------------------------------------------------------
# Provisioner protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class OASTProvisioner(Protocol):
    """Contract for issuing and managing OAST tokens.

    Production deployments may choose between an in-cluster issuer
    (:class:`InternalOASTProvisioner`), a third-party Burp Collaborator
    integration, or interactsh. All of them expose the same surface so the
    orchestrator and integration helpers stay backend-agnostic.
    """

    backend: OASTBackendKind

    def issue(
        self,
        *,
        tenant_id: UUID,
        scan_id: UUID,
        validation_job_id: UUID | None = None,
        family: str | None = None,
        ttl: timedelta = _DEFAULT_TTL,
    ) -> OASTToken:
        """Mint a new OAST token bound to ``tenant_id`` and ``scan_id``."""

    def revoke(self, token_id: UUID) -> None:
        """Mark ``token_id`` inactive immediately."""

    def is_active(self, token_id: UUID) -> bool:
        """Return ``True`` when ``token_id`` is still valid."""

    def get(self, token_id: UUID) -> OASTToken | None:
        """Return the issued :class:`OASTToken` or ``None`` when absent."""


# ---------------------------------------------------------------------------
# Internal in-memory provisioner
# ---------------------------------------------------------------------------


class InternalOASTProvisioner:
    """In-process token issuer backed by a :class:`dict` and a TTL clock.

    Suitable for unit tests, single-node development environments, and the
    ``DRY_RUN`` sandbox. Production deployments would back the same
    interface with a Postgres table (so multiple workers share state) but
    keep the protocol unchanged.

    Thread safety
    -------------
    All public methods take a process-wide :class:`threading.Lock` so the
    provisioner can be used from Celery worker threads, FastAPI request
    handlers, and unit-test fixtures without external synchronisation.

    Determinism
    -----------
    Token identifiers come from :mod:`secrets` so they are not predictable.
    Tests that need deterministic IDs may inject a custom ``id_factory`` via
    the constructor.
    """

    backend: OASTBackendKind = OASTBackendKind.INTERNAL

    def __init__(
        self,
        *,
        base_domain: str,
        clock: "ClockFn | None" = None,
        id_factory: "IdFactoryFn | None" = None,
        token_factory: "TokenFactoryFn | None" = None,
    ) -> None:
        normalized = base_domain.strip().rstrip(".").lower()
        if not _DNS_DOMAIN_RE.fullmatch(normalized):
            raise OASTProvisioningError(
                f"base_domain {base_domain!r} is not a valid DNS name"
            )
        if len(normalized) > _MAX_DNS_NAME_LEN - _BASE_DOMAIN_HEADROOM:
            # Leave room for the `argus-<hex>.` prefix (22 chars + dot = 23).
            raise OASTProvisioningError(
                f"base_domain {base_domain!r} is too long to host OAST labels"
            )
        self._base_domain = normalized
        self._clock: ClockFn = clock or _utcnow
        self._id_factory: IdFactoryFn = id_factory or uuid4
        self._token_factory: TokenFactoryFn = token_factory or _default_token_hex
        self._tokens: dict[UUID, OASTToken] = {}
        self._revoked: set[UUID] = set()
        self._lock = threading.Lock()

    # -- public API ----------------------------------------------------------

    @property
    def base_domain(self) -> str:
        return self._base_domain

    def issue(
        self,
        *,
        tenant_id: UUID,
        scan_id: UUID,
        validation_job_id: UUID | None = None,
        family: str | None = None,
        ttl: timedelta = _DEFAULT_TTL,
    ) -> OASTToken:
        ttl_seconds = int(ttl.total_seconds())
        if ttl_seconds < _MIN_TTL_SECONDS or ttl_seconds > _MAX_TTL_SECONDS:
            raise OASTProvisioningError(
                f"ttl must be between {_MIN_TTL_SECONDS}s and {_MAX_TTL_SECONDS}s "
                f"(got {ttl_seconds}s)"
            )
        if family is not None and not _FAMILY_HINT_RE.fullmatch(family):
            raise OASTProvisioningError(
                f"family hint {family!r} is not snake_case / too long"
            )

        token_id = self._id_factory()
        # ``argus-<16hex>`` is 22 characters — fits comfortably in DNS label
        # bounds (63 octets) and embeds 64 bits of CSPRNG entropy (sufficient
        # to make blind label guessing infeasible at OAST scale).
        label_hex = self._token_factory(_DNS_LABEL_HEX_BYTES)
        dns_label = f"{_DNS_LABEL_PREFIX}{label_hex}".lower()
        subdomain = f"{dns_label}.{self._base_domain}"
        path_token = self._token_factory(_PATH_TOKEN_BYTES)

        now = self._clock()
        token = OASTToken(
            id=token_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
            validation_job_id=validation_job_id,
            subdomain=subdomain,
            path_token=path_token,
            dns_label=dns_label,
            backend=self.backend,
            created_at=now,
            expires_at=now + ttl,
            reserved_for_family=family,
        )
        with self._lock:
            if token_id in self._tokens:
                # Extremely unlikely (UUID4 collision) — treat as a hard
                # failure so callers do not silently overwrite state.
                raise OASTProvisioningError(
                    f"token id collision detected for {token_id}"
                )
            self._tokens[token_id] = token
        _logger.info(
            "oast.token.issued",
            extra={
                "tenant_id": str(tenant_id),
                "scan_id": str(scan_id),
                "token_id": str(token_id),
                "backend": self.backend.value,
                "family": family,
                "ttl_seconds": ttl_seconds,
            },
        )
        return token

    def revoke(self, token_id: UUID) -> None:
        with self._lock:
            self._revoked.add(token_id)
        _logger.info(
            "oast.token.revoked",
            extra={"token_id": str(token_id), "backend": self.backend.value},
        )

    def is_active(self, token_id: UUID) -> bool:
        with self._lock:
            token = self._tokens.get(token_id)
            if token is None:
                return False
            if token_id in self._revoked:
                return False
        return token.is_active_at(self._clock())

    def get(self, token_id: UUID) -> OASTToken | None:
        with self._lock:
            return self._tokens.get(token_id)

    def list_active(self) -> Iterator[OASTToken]:
        """Yield every still-active token (revoked + expired filtered out).

        The iterator is materialised under the lock so callers see a
        consistent point-in-time snapshot even in heavily concurrent
        environments.
        """
        now = self._clock()
        with self._lock:
            snapshot = list(self._tokens.items())
            revoked = set(self._revoked)
        for token_id, token in snapshot:
            if token_id in revoked:
                continue
            if not token.is_active_at(now):
                continue
            yield token

    def purge_expired(
        self,
        *,
        before: datetime | None = None,
        grace: timedelta = _DEFAULT_PURGE_GRACE,
    ) -> int:
        """Drop tokens whose ``expires_at + grace`` predates ``before``.

        Long-running scans accumulate one token per OAST-bound payload and
        the in-memory store grows monotonically until restart. This helper
        gives callers (a periodic infra task, a scan-completion hook, or a
        unit test) an explicit eviction primitive that respects the
        ``grace`` buffer so late callbacks still resolve to a known token.

        Parameters
        ----------
        before
            Reference moment. Defaults to ``self._clock()``. Must be
            timezone-aware.
        grace
            Buffer added to ``token.expires_at`` before eviction. Must be
            non-negative. Defaults to 5 minutes.

        Returns
        -------
        int
            Number of tokens evicted from the in-memory store.
        """
        if grace.total_seconds() < 0:
            raise OASTProvisioningError("grace must be non-negative")
        moment = before if before is not None else self._clock()
        if moment.tzinfo is None:
            raise OASTProvisioningError("before must be timezone-aware")

        threshold = moment - grace
        evicted = 0
        with self._lock:
            for token_id in list(self._tokens.keys()):
                token = self._tokens[token_id]
                if token.expires_at < threshold:
                    self._tokens.pop(token_id, None)
                    self._revoked.discard(token_id)
                    evicted += 1
        if evicted:
            _logger.info(
                "oast.provisioner.purged_expired",
                extra={
                    "count": evicted,
                    "grace_seconds": grace.total_seconds(),
                    "backend": self.backend.value,
                },
            )
        return evicted


# ---------------------------------------------------------------------------
# Disabled provisioner (policy-driven short-circuit)
# ---------------------------------------------------------------------------


class DisabledOASTProvisioner:
    """Stub provisioner that refuses every issue call.

    Wired in by the orchestrator when the tenant policy disables OAST or
    when the operator pulls the kill switch. Callers that need an active
    OAST channel must check :attr:`backend` and pick a fallback (canary
    mode) before calling :meth:`issue`; otherwise they receive
    :class:`OASTUnavailableError`.
    """

    backend: OASTBackendKind = OASTBackendKind.DISABLED

    def __init__(self, *, reason: str = "oast_disabled_for_tenant") -> None:
        self._reason = reason

    @property
    def reason(self) -> str:
        return self._reason

    def issue(
        self,
        *,
        tenant_id: UUID,
        scan_id: UUID,
        validation_job_id: UUID | None = None,
        family: str | None = None,
        ttl: timedelta = _DEFAULT_TTL,
    ) -> OASTToken:
        del tenant_id, scan_id, validation_job_id, family, ttl
        raise OASTUnavailableError(self._reason)

    def revoke(self, token_id: UUID) -> None:
        del token_id

    def is_active(self, token_id: UUID) -> bool:
        del token_id
        return False

    def get(self, token_id: UUID) -> OASTToken | None:
        del token_id
        return None


# ---------------------------------------------------------------------------
# Helpers / type aliases
# ---------------------------------------------------------------------------


class ClockFn(Protocol):
    """Tiny callable returning a timezone-aware ``datetime``."""

    def __call__(self) -> datetime: ...


class IdFactoryFn(Protocol):
    """Callable returning a fresh :class:`uuid.UUID`."""

    def __call__(self) -> UUID: ...


class TokenFactoryFn(Protocol):
    """Callable returning a hex string of the requested byte length.

    Implementations MUST source their randomness from a CSPRNG (the default
    is :func:`secrets.token_hex`).
    """

    def __call__(self, nbytes: int, /) -> str: ...


def _default_token_hex(nbytes: int) -> str:
    if nbytes <= 0 or nbytes > 32:
        raise OASTProvisioningError(
            "token byte size must be in (0, 32] for safe DNS label packing"
        )
    return secrets.token_hex(nbytes)


__all__ = [
    "ClockFn",
    "DisabledOASTProvisioner",
    "IdFactoryFn",
    "InternalOASTProvisioner",
    "OASTBackendKind",
    "OASTError",
    "OASTProvisioner",
    "OASTProvisioningError",
    "OASTToken",
    "OASTUnavailableError",
    "TokenFactoryFn",
]
