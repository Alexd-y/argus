"""Redis-backed emergency kill-switch / per-tenant throttle store (T31, ARG-052).

This module sits between the operator-facing ``/admin/system/emergency/*``
API (:mod:`src.api.routers.admin_emergency`) and the policy decision path
(:class:`src.policy.policy_engine.PolicyEngine`).

Storage schema (Redis, JSON-encoded values, ``decode_responses=True``):

* ``argus:emergency:global`` — global stop, **no TTL**. Stays set until an
  operator explicitly calls ``resume_all``. Schema::

      {"reason": str, "operator_subject_hash": str, "activated_at": iso8601}

* ``argus:emergency:tenant:{tenant_id}`` — per-tenant throttle with TTL.
  Schema::

      {"reason": str, "operator_subject_hash": str, "activated_at": iso8601,
       "expires_at": iso8601, "duration_seconds": int}

Design constraints honoured here:

* **PII deny-list** — the raw operator subject is hashed via
  :func:`src.core.observability.user_id_hash` BEFORE being persisted to Redis
  so emergency-stop forensic data cannot leak operator identities into the
  cache layer. The original subject is still passed to the audit-log row in
  the API handler (which has its own hashing pipeline).
* **Fail-open on read, fail-closed on write** — when the Redis client is
  ``None`` (lazy-init failure, e.g. Redis pod restart) :meth:`is_blocked`
  returns ``KillSwitchVerdict(blocked=False)`` so a temporary cache outage
  does not stop *every* tenant scan globally; writes raise
  :class:`KillSwitchUnavailableError` so operators see a clear failure when
  trying to ENABLE the kill-switch — refusing to silently no-op an
  emergency-stop request is the safer side of this trade-off.
* **No global singleton** — the service is instantiated per-request via
  FastAPI's dependency injection so unit tests can inject mocks freely.
* **Sync redis-py client** — reads/writes are sub-millisecond local Redis
  ops; the API handler offloads them to the threadpool with
  :func:`asyncio.to_thread` to keep the event-loop unblocked.

PolicyEngine integration:

Callers may inject :meth:`KillSwitchService.policy_checker` (a closure) into
:class:`src.policy.policy_engine.PolicyEngine` to short-circuit
``evaluate()`` when a global stop or per-tenant throttle is in effect.

Closed-taxonomy reasons exposed to PolicyEngine deny paths:

* ``policy_emergency_global``
* ``policy_emergency_tenant``
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from src.core.observability import user_id_hash

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public taxonomy / constants
# ---------------------------------------------------------------------------


EMERGENCY_GLOBAL_KEY: Final[str] = "argus:emergency:global"
EMERGENCY_TENANT_KEY_PREFIX: Final[str] = "argus:emergency:tenant:"

#: Operator-controlled reason text capped to defend Redis & audit log size.
EMERGENCY_REASON_MAX_LEN: Final[int] = 1000

#: Bound on how long a per-tenant throttle may be set in a single call.
TENANT_THROTTLE_MAX_SECONDS: Final[int] = 24 * 60 * 60  # 24h


class KillSwitchScope(StrEnum):
    """Closed taxonomy of reasons :meth:`KillSwitchService.is_blocked` returns."""

    GLOBAL = "global"
    TENANT = "tenant"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class KillSwitchUnavailableError(RuntimeError):
    """Raised when a write/state-changing op is attempted without a Redis client.

    The API layer maps this to HTTP 503 with the closed-taxonomy detail
    ``"emergency_store_unavailable"`` so operators get a clear signal that
    their action did NOT take effect.
    """


class EmergencyAlreadyActiveError(RuntimeError):
    """Raised when ``set_global`` is called while a global stop is in effect.

    The API layer maps this to HTTP 409 with detail ``"emergency_already_active"``
    so the operator can decide whether to ``resume_all`` first or accept that
    the existing flag remains in place.
    """


class EmergencyNotActiveError(RuntimeError):
    """Raised when ``clear_global`` finds no active global stop."""


# ---------------------------------------------------------------------------
# Models — frozen so callers cannot mutate cached state by accident.
# ---------------------------------------------------------------------------


class KillSwitchVerdict(BaseModel):
    """Output of :meth:`KillSwitchService.is_blocked` — checked per dispatch."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    blocked: bool
    scope: KillSwitchScope | None = None
    expires_at: datetime | None = None
    reason: str | None = Field(default=None, max_length=EMERGENCY_REASON_MAX_LEN)


class GlobalEmergencyState(BaseModel):
    """Snapshot of the global emergency entry (no operator identity exposed)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: str = Field(max_length=EMERGENCY_REASON_MAX_LEN)
    activated_at: datetime
    operator_subject_hash: str


class TenantThrottleState(BaseModel):
    """Snapshot of a per-tenant throttle entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str
    reason: str = Field(max_length=EMERGENCY_REASON_MAX_LEN)
    activated_at: datetime
    expires_at: datetime
    duration_seconds: int = Field(ge=0)
    operator_subject_hash: str


class KillSwitchStatus(BaseModel):
    """Aggregate posture for the status endpoint."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    global_state: GlobalEmergencyState | None = None
    tenant_throttles: tuple[TenantThrottleState, ...] = Field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _to_tenant_str(tenant_id: str | UUID) -> str:
    if isinstance(tenant_id, UUID):
        return str(tenant_id)
    return tenant_id


def _global_key() -> str:
    return EMERGENCY_GLOBAL_KEY


def _tenant_key(tenant_id: str | UUID) -> str:
    return f"{EMERGENCY_TENANT_KEY_PREFIX}{_to_tenant_str(tenant_id)}"


def _normalize_reason(reason: str) -> str:
    """Strip + truncate operator-supplied reason text for safe storage."""
    cleaned = (reason or "").strip()
    if not cleaned:
        raise ValueError("reason must be non-empty")
    if len(cleaned) > EMERGENCY_REASON_MAX_LEN:
        cleaned = cleaned[:EMERGENCY_REASON_MAX_LEN]
    return cleaned


def _serialize(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _safe_loads(raw: str | bytes | None) -> dict[str, Any] | None:
    """Best-effort JSON decode; corrupt entries are treated as absent + logged."""
    if raw is None:
        return None
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            logger.warning(
                "kill_switch.payload_decode_failed",
                extra={"event": "argus.kill_switch.payload_decode_failed"},
            )
            return None
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError):
        logger.warning(
            "kill_switch.payload_invalid_json",
            extra={"event": "argus.kill_switch.payload_invalid_json"},
        )
        return None
    return decoded if isinstance(decoded, dict) else None


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        # ``fromisoformat`` accepts ``+00:00``; normalize bare ``Z`` first.
        normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _ensure_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class KillSwitchService:
    """Thin wrapper around redis-py for emergency-stop / throttle flags.

    All methods are synchronous: redis-py is a sync client and individual
    ops complete in microseconds locally. The API layer offloads them via
    :func:`asyncio.to_thread` to avoid blocking the FastAPI event loop.
    """

    def __init__(self, redis_client: Any | None) -> None:
        self._redis = redis_client

    # -- Capability checks --------------------------------------------------

    @property
    def available(self) -> bool:
        """``True`` when a Redis client was injected at construction time."""
        return self._redis is not None

    def _require_redis(self) -> Any:
        if self._redis is None:
            raise KillSwitchUnavailableError(
                "Redis client unavailable; emergency-stop store is offline"
            )
        return self._redis

    # -- Global stop --------------------------------------------------------

    def set_global(
        self,
        *,
        reason: str,
        operator_subject: str,
        activated_at: datetime | None = None,
    ) -> GlobalEmergencyState:
        """Persist the global emergency flag (no TTL).

        Raises :class:`EmergencyAlreadyActiveError` when a global flag is
        already active so the API layer can map to HTTP 409 instead of
        silently overwriting prior operator context.

        Atomicity: uses ``SET NX`` so two concurrent super-admin callers cannot
        both observe an empty key, both write, and both emit a stale audit row
        (TOCTOU). Redis returns falsy on NX-collision; the loser raises and
        the API surface returns 409 with no audit attribution drift.
        """
        client = self._require_redis()
        normalized_reason = _normalize_reason(reason)
        ts = _ensure_aware(activated_at) or _utcnow()
        operator_subject_hash = user_id_hash(operator_subject)
        payload: dict[str, Any] = {
            "reason": normalized_reason,
            "operator_subject_hash": operator_subject_hash,
            "activated_at": ts.isoformat(),
        }
        if not client.set(_global_key(), _serialize(payload), nx=True):
            raise EmergencyAlreadyActiveError(
                "global emergency already active; resume first"
            )
        logger.info(
            "kill_switch.global.set",
            extra={
                "event": "argus.kill_switch.global.set",
                "user_id_hash": operator_subject_hash,
                "activated_at": ts.isoformat(),
                "reason_length": len(normalized_reason),
            },
        )
        return GlobalEmergencyState(
            reason=normalized_reason,
            activated_at=ts,
            operator_subject_hash=operator_subject_hash,
        )

    def clear_global(self) -> bool:
        """Remove the global flag.

        Returns ``True`` when a flag was active; raises
        :class:`EmergencyNotActiveError` when nothing was set so the API
        layer can map to HTTP 409 with closed-taxonomy detail
        ``"emergency_not_active"``.
        """
        client = self._require_redis()
        deleted = int(client.delete(_global_key()))
        if not deleted:
            raise EmergencyNotActiveError("no global emergency to clear")
        logger.info(
            "kill_switch.global.cleared",
            extra={"event": "argus.kill_switch.global.cleared"},
        )
        return True

    def get_global(self) -> GlobalEmergencyState | None:
        """Return the current global state or ``None`` (fail-open on errors)."""
        if self._redis is None:
            return None
        try:
            raw = self._redis.get(_global_key())
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(
                "kill_switch.global.read_failed",
                extra={
                    "event": "argus.kill_switch.global.read_failed",
                    "error_type": type(exc).__name__,
                },
            )
            return None
        payload = _safe_loads(raw)
        if not payload:
            return None
        ts = _ensure_aware(_parse_iso(payload.get("activated_at")))
        if ts is None:
            return None
        reason_raw = payload.get("reason")
        op_hash_raw = payload.get("operator_subject_hash")
        reason = str(reason_raw) if isinstance(reason_raw, str) else ""
        op_hash = str(op_hash_raw) if isinstance(op_hash_raw, str) else ""
        return GlobalEmergencyState(
            reason=reason[:EMERGENCY_REASON_MAX_LEN],
            activated_at=ts,
            operator_subject_hash=op_hash,
        )

    # -- Per-tenant throttle ------------------------------------------------

    def set_tenant_throttle(
        self,
        tenant_id: str | UUID,
        *,
        duration_seconds: int,
        reason: str,
        operator_subject: str,
        activated_at: datetime | None = None,
    ) -> TenantThrottleState:
        """Set a per-tenant throttle with TTL ``duration_seconds``.

        Re-issuing for the same tenant is allowed (it overwrites the prior
        entry and resets the TTL); the API layer treats this as an explicit
        operator action and emits a fresh audit row.

        Note: tenant throttle is overwritable by design — re-throttling with a
        different duration is legitimate admin behaviour, so we deliberately
        do NOT use ``SET NX`` here (unlike :meth:`set_global`).
        """
        client = self._require_redis()
        if duration_seconds <= 0:
            raise ValueError("duration_seconds must be > 0")
        if duration_seconds > TENANT_THROTTLE_MAX_SECONDS:
            raise ValueError(
                f"duration_seconds must be <= {TENANT_THROTTLE_MAX_SECONDS}"
            )
        normalized_reason = _normalize_reason(reason)
        ts = _ensure_aware(activated_at) or _utcnow()
        expires_at = ts + timedelta(seconds=duration_seconds)
        tid = _to_tenant_str(tenant_id)
        operator_subject_hash = user_id_hash(operator_subject)
        payload: dict[str, Any] = {
            "reason": normalized_reason,
            "operator_subject_hash": operator_subject_hash,
            "activated_at": ts.isoformat(),
            "expires_at": expires_at.isoformat(),
            "duration_seconds": int(duration_seconds),
        }
        client.set(_tenant_key(tid), _serialize(payload), ex=int(duration_seconds))
        logger.info(
            "kill_switch.tenant.set",
            extra={
                "event": "argus.kill_switch.tenant.set",
                "tenant_id_set": True,  # raw tenant id never logged
                "user_id_hash": operator_subject_hash,
                "duration_seconds": int(duration_seconds),
                "expires_at": expires_at.isoformat(),
                "reason_length": len(normalized_reason),
            },
        )
        return TenantThrottleState(
            tenant_id=tid,
            reason=normalized_reason,
            activated_at=ts,
            expires_at=expires_at,
            duration_seconds=int(duration_seconds),
            operator_subject_hash=operator_subject_hash,
        )

    def clear_tenant_throttle(self, tenant_id: str | UUID) -> bool:
        """Remove a per-tenant throttle. Returns ``True`` when one existed."""
        client = self._require_redis()
        deleted = int(client.delete(_tenant_key(tenant_id)))
        if deleted:
            logger.info(
                "kill_switch.tenant.cleared",
                extra={"event": "argus.kill_switch.tenant.cleared"},
            )
        return bool(deleted)

    def get_tenant_throttle(self, tenant_id: str | UUID) -> TenantThrottleState | None:
        """Return active throttle for ``tenant_id`` or ``None``."""
        if self._redis is None:
            return None
        tid = _to_tenant_str(tenant_id)
        try:
            raw = self._redis.get(_tenant_key(tid))
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(
                "kill_switch.tenant.read_failed",
                extra={
                    "event": "argus.kill_switch.tenant.read_failed",
                    "error_type": type(exc).__name__,
                },
            )
            return None
        payload = _safe_loads(raw)
        if not payload:
            return None
        activated_at = _ensure_aware(_parse_iso(payload.get("activated_at")))
        expires_at = _ensure_aware(_parse_iso(payload.get("expires_at")))
        if activated_at is None or expires_at is None:
            return None
        if expires_at <= _utcnow():
            return None
        reason_raw = payload.get("reason")
        op_hash_raw = payload.get("operator_subject_hash")
        duration_raw = payload.get("duration_seconds")
        try:
            duration = int(duration_raw) if duration_raw is not None else 0
        except (TypeError, ValueError):
            duration = 0
        return TenantThrottleState(
            tenant_id=tid,
            reason=(
                str(reason_raw)[:EMERGENCY_REASON_MAX_LEN]
                if isinstance(reason_raw, str)
                else ""
            ),
            activated_at=activated_at,
            expires_at=expires_at,
            duration_seconds=max(duration, 0),
            operator_subject_hash=(
                str(op_hash_raw) if isinstance(op_hash_raw, str) else ""
            ),
        )

    # -- Combined verdict ---------------------------------------------------

    def is_blocked(self, tenant_id: str | UUID) -> KillSwitchVerdict:
        """Resolve whether dispatch for ``tenant_id`` is currently blocked.

        Order of evaluation:

        1. Global stop wins — returns immediately when set.
        2. Per-tenant throttle (active + non-expired).
        3. Otherwise ``KillSwitchVerdict(blocked=False)``.
        """
        global_state = self.get_global()
        if global_state is not None:
            return KillSwitchVerdict(
                blocked=True,
                scope=KillSwitchScope.GLOBAL,
                expires_at=None,
                reason=global_state.reason,
            )
        tenant_state = self.get_tenant_throttle(tenant_id)
        if tenant_state is not None:
            return KillSwitchVerdict(
                blocked=True,
                scope=KillSwitchScope.TENANT,
                expires_at=tenant_state.expires_at,
                reason=tenant_state.reason,
            )
        return KillSwitchVerdict(blocked=False)

    # -- Status aggregation -------------------------------------------------

    def get_status(
        self,
        *,
        tenant_ids: Iterable[str | UUID] | None = None,
    ) -> KillSwitchStatus:
        """Snapshot global + per-tenant flags for the operator status view.

        ``tenant_ids`` filters the per-tenant lookup. When ``None``, the
        service falls back to ``SCAN`` (``argus:emergency:tenant:*``) — the
        scan is bounded internally to a hard ceiling defined by
        ``_status_scan_count`` to avoid blocking the event loop on a
        pathologically large keyspace.
        """
        global_state = self.get_global()
        throttles: list[TenantThrottleState] = []
        if tenant_ids is not None:
            seen: set[str] = set()
            for tid in tenant_ids:
                key = _to_tenant_str(tid)
                if key in seen:
                    continue
                seen.add(key)
                state = self.get_tenant_throttle(key)
                if state is not None:
                    throttles.append(state)
        elif self._redis is not None:
            for key in self._scan_tenant_keys():
                tid = key.removeprefix(EMERGENCY_TENANT_KEY_PREFIX)
                if not tid:
                    continue
                state = self.get_tenant_throttle(tid)
                if state is not None:
                    throttles.append(state)
        return KillSwitchStatus(
            global_state=global_state,
            tenant_throttles=tuple(throttles),
        )

    _status_scan_count: int = 1024

    def _scan_tenant_keys(self) -> Iterable[str]:
        """Iterate matching tenant keys via SCAN; bounded by ``_status_scan_count``."""
        client = self._redis
        if client is None:
            return ()
        try:
            scan_iter = client.scan_iter(
                match=f"{EMERGENCY_TENANT_KEY_PREFIX}*",
                count=100,
            )
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(
                "kill_switch.scan_failed",
                extra={
                    "event": "argus.kill_switch.scan_failed",
                    "error_type": type(exc).__name__,
                },
            )
            return ()
        out: list[str] = []
        for raw_key in scan_iter:
            if isinstance(raw_key, bytes):
                try:
                    key = raw_key.decode("utf-8")
                except UnicodeDecodeError:
                    continue
            else:
                key = str(raw_key)
            out.append(key)
            if len(out) >= self._status_scan_count:
                break
        return out

    # -- PolicyEngine integration ------------------------------------------

    def policy_checker(self) -> Callable[[str | UUID], KillSwitchVerdict]:
        """Return a callable suitable for ``PolicyEngine`` injection.

        Bound to ``self`` so the engine can stay completely stateless / pure
        and the I/O surface lives entirely in this module.
        """
        return self.is_blocked


# ---------------------------------------------------------------------------
# Module-level dependency factory (for FastAPI ``Depends(...)``)
# ---------------------------------------------------------------------------


def get_kill_switch_service() -> KillSwitchService:
    """FastAPI dependency: build a :class:`KillSwitchService` per request.

    Mirrors the lazy pattern of :func:`src.core.redis_client.get_redis` so
    a transient Redis outage at startup does not poison the cached client
    forever; each request re-resolves ``get_redis()`` and the kill-switch
    service either gets a working client or fails gracefully.
    """
    from src.core.redis_client import get_redis  # local import: avoid cycles

    return KillSwitchService(get_redis())


__all__ = [
    "EMERGENCY_GLOBAL_KEY",
    "EMERGENCY_REASON_MAX_LEN",
    "EMERGENCY_TENANT_KEY_PREFIX",
    "EmergencyAlreadyActiveError",
    "EmergencyNotActiveError",
    "GlobalEmergencyState",
    "KillSwitchScope",
    "KillSwitchService",
    "KillSwitchStatus",
    "KillSwitchUnavailableError",
    "KillSwitchVerdict",
    "TENANT_THROTTLE_MAX_SECONDS",
    "TenantThrottleState",
    "get_kill_switch_service",
]
