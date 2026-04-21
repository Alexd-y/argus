"""Unit tests for :mod:`src.policy.kill_switch` (T31, ARG-052).

Covers the synchronous Redis-backed kill-switch service used by the
``/admin/system/emergency/*`` endpoints AND injected as a checker into
:class:`src.policy.policy_engine.PolicyEngine`. ``fakeredis`` is NOT in the
project dependencies, so a deterministic in-memory MagicMock that mirrors
the redis-py surface (``get`` / ``set`` / ``delete`` / ``scan_iter``) is
used here — the test assertions exercise the data-flow contract, not the
real Redis state machine.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from src.core.observability import user_id_hash
from src.policy.kill_switch import (
    EMERGENCY_GLOBAL_KEY,
    EMERGENCY_TENANT_KEY_PREFIX,
    TENANT_THROTTLE_MAX_SECONDS,
    EmergencyAlreadyActiveError,
    EmergencyNotActiveError,
    KillSwitchScope,
    KillSwitchService,
    KillSwitchUnavailableError,
)


# ---------------------------------------------------------------------------
# Fake Redis — minimal redis-py-compatible surface used by KillSwitchService.
# ---------------------------------------------------------------------------


class _FakeRedis:
    """Minimal in-memory redis-py stand-in (no TTL eviction simulation).

    ``KillSwitchService`` only calls ``get``, ``set``, ``delete``, and
    ``scan_iter`` — implementing more would invite drift from the real
    surface. TTL is recorded but NOT enforced by wall-clock; tests that need
    expiry semantics manipulate :attr:`_now` directly.
    """

    def __init__(self) -> None:
        self._data: dict[str, str] = {}
        self._ttls: dict[str, int] = {}

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(
        self,
        key: str,
        value: str,
        *,
        ex: int | None = None,
        nx: bool = False,
    ) -> bool:
        # Mirror redis-py SET NX semantics: when nx=True and the key exists,
        # return False (key not written); otherwise write and return True.
        if nx and key in self._data:
            return False
        self._data[key] = value
        if ex is not None:
            self._ttls[key] = int(ex)
        else:
            self._ttls.pop(key, None)
        return True

    def delete(self, key: str) -> int:
        existed = key in self._data
        self._data.pop(key, None)
        self._ttls.pop(key, None)
        return 1 if existed else 0

    def scan_iter(self, *, match: str, count: int = 100) -> list[str]:
        if not match.endswith("*"):
            return [k for k in self._data if k == match]
        prefix = match[:-1]
        return [k for k in self._data if k.startswith(prefix)]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_redis() -> _FakeRedis:
    return _FakeRedis()


@pytest.fixture()
def service(fake_redis: _FakeRedis) -> KillSwitchService:
    return KillSwitchService(fake_redis)


@pytest.fixture()
def offline_service() -> KillSwitchService:
    return KillSwitchService(redis_client=None)


@pytest.fixture()
def tenant_a() -> UUID:
    return UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


@pytest.fixture()
def tenant_b() -> UUID:
    return UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


@pytest.fixture()
def operator_subject() -> str:
    return "operator-1@argus.example"


# ---------------------------------------------------------------------------
# Global stop
# ---------------------------------------------------------------------------


class TestGlobalStop:
    def test_set_global_persists_payload_with_hashed_subject(
        self,
        service: KillSwitchService,
        fake_redis: _FakeRedis,
        operator_subject: str,
    ) -> None:
        state = service.set_global(
            reason="Critical incident in flight; halt scans",
            operator_subject=operator_subject,
        )

        raw = fake_redis.get(EMERGENCY_GLOBAL_KEY)
        assert raw is not None
        payload = json.loads(raw)
        assert payload["operator_subject_hash"] == user_id_hash(operator_subject)
        assert operator_subject not in raw, (
            "raw operator subject must never be persisted to Redis"
        )
        assert state.reason == payload["reason"]
        assert state.activated_at.tzinfo is not None
        assert payload["operator_subject_hash"] == state.operator_subject_hash

    def test_set_global_raises_when_already_active(
        self, service: KillSwitchService, operator_subject: str
    ) -> None:
        service.set_global(
            reason="first emergency justification",
            operator_subject=operator_subject,
        )
        with pytest.raises(EmergencyAlreadyActiveError):
            service.set_global(
                reason="second attempt while still active",
                operator_subject=operator_subject,
            )

    def test_set_global_setnx_blocks_concurrent_writer(
        self, operator_subject: str
    ) -> None:
        """Two concurrent super-admins MUST NOT both observe an empty key,
        both write, and both emit a stale audit row (TOCTOU). With ``SET NX``
        the second writer's redis-py call returns falsy, the service raises
        :class:`EmergencyAlreadyActiveError`, the API surface returns 409, and
        the persisted payload remains the FIRST winner — not silently
        overwritten by the loser.
        """
        client: Any = MagicMock()
        # First call: NX succeeds (truthy). Second call: NX collides (falsy).
        client.set.side_effect = [True, None]
        svc = KillSwitchService(client)

        first = svc.set_global(
            reason="initial halt — first writer",
            operator_subject=operator_subject,
        )
        assert first.reason == "initial halt — first writer"

        with pytest.raises(EmergencyAlreadyActiveError):
            svc.set_global(
                reason="losing concurrent writer — must 409",
                operator_subject=operator_subject,
            )

        # Both calls MUST have used nx=True; otherwise the second would have
        # silently overwritten the first.
        assert client.set.call_count == 2
        for call in client.set.call_args_list:
            assert call.kwargs.get("nx") is True, (
                "set_global must use SET NX for atomic write-or-fail"
            )

    def test_set_global_strips_and_caps_reason(
        self, service: KillSwitchService, operator_subject: str
    ) -> None:
        long_reason = "  " + ("x" * 5_000) + "  "
        state = service.set_global(
            reason=long_reason, operator_subject=operator_subject
        )
        assert state.reason == "x" * 1000
        assert len(state.reason) == 1000

    def test_set_global_rejects_blank_reason(
        self, service: KillSwitchService, operator_subject: str
    ) -> None:
        with pytest.raises(ValueError):
            service.set_global(reason="   ", operator_subject=operator_subject)

    def test_clear_global_returns_true_and_emits_no_payload(
        self,
        service: KillSwitchService,
        fake_redis: _FakeRedis,
        operator_subject: str,
    ) -> None:
        service.set_global(
            reason="initial halt for incident", operator_subject=operator_subject
        )
        assert service.clear_global() is True
        assert fake_redis.get(EMERGENCY_GLOBAL_KEY) is None

    def test_clear_global_raises_when_not_set(self, service: KillSwitchService) -> None:
        with pytest.raises(EmergencyNotActiveError):
            service.clear_global()

    def test_get_global_returns_state_when_present(
        self, service: KillSwitchService, operator_subject: str
    ) -> None:
        service.set_global(
            reason="incident response halt", operator_subject=operator_subject
        )
        state = service.get_global()
        assert state is not None
        assert state.reason == "incident response halt"
        assert state.operator_subject_hash == user_id_hash(operator_subject)

    def test_get_global_returns_none_on_corrupt_payload(
        self, service: KillSwitchService, fake_redis: _FakeRedis
    ) -> None:
        fake_redis.set(EMERGENCY_GLOBAL_KEY, "not-json-{")
        assert service.get_global() is None


# ---------------------------------------------------------------------------
# Tenant throttle
# ---------------------------------------------------------------------------


class TestTenantThrottle:
    def test_set_tenant_throttle_persists_with_ttl(
        self,
        service: KillSwitchService,
        fake_redis: _FakeRedis,
        tenant_a: UUID,
        operator_subject: str,
    ) -> None:
        state = service.set_tenant_throttle(
            tenant_a,
            duration_seconds=900,
            reason="incident scoped to one tenant",
            operator_subject=operator_subject,
        )

        key = f"{EMERGENCY_TENANT_KEY_PREFIX}{tenant_a}"
        raw = fake_redis.get(key)
        assert raw is not None
        assert fake_redis._ttls[key] == 900
        payload = json.loads(raw)
        assert payload["operator_subject_hash"] == user_id_hash(operator_subject)
        assert operator_subject not in raw
        assert state.duration_seconds == 900
        assert state.expires_at - state.activated_at == timedelta(seconds=900)

    def test_set_tenant_throttle_rejects_invalid_durations(
        self, service: KillSwitchService, tenant_a: UUID, operator_subject: str
    ) -> None:
        with pytest.raises(ValueError):
            service.set_tenant_throttle(
                tenant_a,
                duration_seconds=0,
                reason="zero duration not allowed",
                operator_subject=operator_subject,
            )
        with pytest.raises(ValueError):
            service.set_tenant_throttle(
                tenant_a,
                duration_seconds=TENANT_THROTTLE_MAX_SECONDS + 1,
                reason="too long",
                operator_subject=operator_subject,
            )

    def test_clear_tenant_throttle_returns_true_when_present(
        self, service: KillSwitchService, tenant_a: UUID, operator_subject: str
    ) -> None:
        service.set_tenant_throttle(
            tenant_a,
            duration_seconds=600,
            reason="set then clear quickly",
            operator_subject=operator_subject,
        )
        assert service.clear_tenant_throttle(tenant_a) is True
        assert service.get_tenant_throttle(tenant_a) is None

    def test_clear_tenant_throttle_returns_false_when_absent(
        self, service: KillSwitchService, tenant_a: UUID
    ) -> None:
        assert service.clear_tenant_throttle(tenant_a) is False

    def test_get_tenant_throttle_filters_expired_entries(
        self,
        service: KillSwitchService,
        fake_redis: _FakeRedis,
        tenant_a: UUID,
        operator_subject: str,
    ) -> None:
        past = datetime.now(tz=timezone.utc) - timedelta(seconds=10)
        service.set_tenant_throttle(
            tenant_a,
            duration_seconds=5,
            reason="originally short ttl",
            operator_subject=operator_subject,
            activated_at=past,
        )
        assert service.get_tenant_throttle(tenant_a) is None


# ---------------------------------------------------------------------------
# is_blocked / verdicts
# ---------------------------------------------------------------------------


class TestIsBlocked:
    def test_global_stop_takes_precedence_over_tenant_state(
        self,
        service: KillSwitchService,
        tenant_a: UUID,
        operator_subject: str,
    ) -> None:
        service.set_global(
            reason="global halt for incident response",
            operator_subject=operator_subject,
        )
        service.set_tenant_throttle(
            tenant_a,
            duration_seconds=600,
            reason="tenant throttle masked by global",
            operator_subject=operator_subject,
        )
        verdict = service.is_blocked(tenant_a)
        assert verdict.blocked is True
        assert verdict.scope == KillSwitchScope.GLOBAL
        assert verdict.expires_at is None
        assert verdict.reason == "global halt for incident response"

    def test_tenant_throttle_blocks_only_target_tenant(
        self,
        service: KillSwitchService,
        tenant_a: UUID,
        tenant_b: UUID,
        operator_subject: str,
    ) -> None:
        service.set_tenant_throttle(
            tenant_a,
            duration_seconds=600,
            reason="throttled per-tenant test",
            operator_subject=operator_subject,
        )
        v_a = service.is_blocked(tenant_a)
        v_b = service.is_blocked(tenant_b)
        assert v_a.blocked is True
        assert v_a.scope == KillSwitchScope.TENANT
        assert v_b.blocked is False

    def test_no_flags_returns_unblocked(
        self, service: KillSwitchService, tenant_a: UUID
    ) -> None:
        verdict = service.is_blocked(tenant_a)
        assert verdict.blocked is False
        assert verdict.scope is None
        assert verdict.reason is None


# ---------------------------------------------------------------------------
# Status aggregation
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status_reports_global_and_per_tenant_throttles(
        self,
        service: KillSwitchService,
        tenant_a: UUID,
        tenant_b: UUID,
        operator_subject: str,
    ) -> None:
        service.set_global(
            reason="cross-tenant incident response",
            operator_subject=operator_subject,
        )
        service.set_tenant_throttle(
            tenant_a,
            duration_seconds=300,
            reason="tenant a throttle",
            operator_subject=operator_subject,
        )
        service.set_tenant_throttle(
            tenant_b,
            duration_seconds=600,
            reason="tenant b throttle",
            operator_subject=operator_subject,
        )

        status = service.get_status()
        assert status.global_state is not None
        assert {t.tenant_id for t in status.tenant_throttles} == {
            str(tenant_a),
            str(tenant_b),
        }

    def test_status_filters_to_provided_tenant_ids(
        self,
        service: KillSwitchService,
        tenant_a: UUID,
        tenant_b: UUID,
        operator_subject: str,
    ) -> None:
        service.set_tenant_throttle(
            tenant_a,
            duration_seconds=300,
            reason="tenant a only filter",
            operator_subject=operator_subject,
        )
        service.set_tenant_throttle(
            tenant_b,
            duration_seconds=300,
            reason="tenant b filter test",
            operator_subject=operator_subject,
        )

        status = service.get_status(tenant_ids=[tenant_a])
        assert {t.tenant_id for t in status.tenant_throttles} == {str(tenant_a)}


# ---------------------------------------------------------------------------
# Fail-open / fail-closed semantics
# ---------------------------------------------------------------------------


class TestFailOpenClosedSemantics:
    def test_read_path_fails_open_when_redis_unavailable(
        self, offline_service: KillSwitchService, tenant_a: UUID
    ) -> None:
        verdict = offline_service.is_blocked(tenant_a)
        assert verdict.blocked is False, (
            "read path must fail-open so a transient Redis outage does not "
            "block every tenant scan globally"
        )
        assert offline_service.get_global() is None
        assert offline_service.get_tenant_throttle(tenant_a) is None

    def test_write_path_fails_closed_when_redis_unavailable(
        self, offline_service: KillSwitchService, operator_subject: str
    ) -> None:
        with pytest.raises(KillSwitchUnavailableError):
            offline_service.set_global(
                reason="should refuse to silently noop a halt",
                operator_subject=operator_subject,
            )

    def test_clear_global_fails_closed_when_redis_unavailable(
        self, offline_service: KillSwitchService
    ) -> None:
        with pytest.raises(KillSwitchUnavailableError):
            offline_service.clear_global()


# ---------------------------------------------------------------------------
# PolicyEngine integration adapter
# ---------------------------------------------------------------------------


class TestPolicyChecker:
    def test_policy_checker_returns_callable_bound_to_service(
        self,
        service: KillSwitchService,
        tenant_a: UUID,
        operator_subject: str,
    ) -> None:
        service.set_global(
            reason="bound checker integration test",
            operator_subject=operator_subject,
        )
        checker = service.policy_checker()
        verdict = checker(tenant_a)
        assert verdict.blocked is True
        assert verdict.scope == KillSwitchScope.GLOBAL


# ---------------------------------------------------------------------------
# Defensive parsing — guards against legacy / corrupt payloads.
# ---------------------------------------------------------------------------


class TestPayloadParsing:
    def test_missing_activated_at_yields_none(
        self, service: KillSwitchService, fake_redis: _FakeRedis
    ) -> None:
        fake_redis.set(
            EMERGENCY_GLOBAL_KEY,
            json.dumps({"reason": "x" * 12, "operator_subject_hash": "abc"}),
        )
        assert service.get_global() is None

    def test_invalid_iso_timestamp_yields_none(
        self, service: KillSwitchService, fake_redis: _FakeRedis
    ) -> None:
        fake_redis.set(
            EMERGENCY_GLOBAL_KEY,
            json.dumps(
                {
                    "reason": "x" * 12,
                    "operator_subject_hash": "abc",
                    "activated_at": "not-a-timestamp",
                }
            ),
        )
        assert service.get_global() is None

    def test_redis_get_exception_returns_none_on_read_path(
        self,
    ) -> None:
        client: Any = MagicMock()
        client.get.side_effect = ConnectionError("boom")
        svc = KillSwitchService(client)
        assert svc.get_global() is None
