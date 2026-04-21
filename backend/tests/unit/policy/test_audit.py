"""Unit tests for :mod:`src.policy.audit`.

Covers payload coercion (allow / reject branches), the SHA-256 hash chain,
``InMemoryAuditSink`` thread-safety guards, and the tamper-detection
contract enforced by :meth:`AuditLogger.verify_chain`.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from src.policy.audit import (
    GENESIS_HASH,
    AuditChainError,
    AuditEvent,
    AuditEventType,
    AuditLogger,
    AuditPayloadError,
    AuditSink,
    InMemoryAuditSink,
)


# ---------------------------------------------------------------------------
# AuditEvent — payload coercion
# ---------------------------------------------------------------------------


class TestPayloadCoercion:
    def test_minimal_payload_accepted(self, tenant_id: UUID) -> None:
        event = AuditEvent(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
        )
        assert event.payload == {}
        assert event.event_hash != ""

    def test_payload_with_safe_leaves(self, tenant_id: UUID) -> None:
        event = AuditEvent(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
            payload={
                "rule_index": 0,
                "matched": True,
                "summary": None,
            },
        )
        assert event.payload == {"rule_index": 0, "matched": True, "summary": None}

    def test_uuid_value_coerced_to_str(self, tenant_id: UUID) -> None:
        sub_id = uuid4()
        event = AuditEvent(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
            payload={"decision_id": sub_id},
        )
        assert event.payload["decision_id"] == str(sub_id)

    def test_str_enum_lowered(self, tenant_id: UUID) -> None:
        event = AuditEvent(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
            payload={"event_type": AuditEventType.PREFLIGHT_PASS},
        )
        assert event.payload["event_type"] == "preflight.pass"

    def test_long_string_truncated(self, tenant_id: UUID) -> None:
        big = "A" * 1024
        event = AuditEvent(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
            payload={"summary": big},
        )
        truncated = event.payload["summary"]
        assert isinstance(truncated, str)
        assert len(truncated) == 256
        assert truncated.endswith("\u2026")

    def test_oversize_list_rejected(self, tenant_id: UUID) -> None:
        with pytest.raises(ValidationError) as exc_info:
            AuditEvent(
                event_type=AuditEventType.SCOPE_CHECK,
                tenant_id=tenant_id,
                decision_allowed=True,
                payload={"items": list(range(64))},
            )
        assert "audit payload list/tuple" in str(exc_info.value)

    def test_oversize_dict_rejected(self, tenant_id: UUID) -> None:
        big: dict[str, object] = {f"k{i}": i for i in range(64)}
        with pytest.raises(ValidationError) as exc_info:
            AuditEvent(
                event_type=AuditEventType.SCOPE_CHECK,
                tenant_id=tenant_id,
                decision_allowed=True,
                payload=big,
            )
        assert "audit payload dict" in str(exc_info.value)

    @pytest.mark.parametrize(
        "key",
        ["BadKey", "1starts_with_digit", "has-dash", "with space", ""],
    )
    def test_bad_keys_rejected(self, tenant_id: UUID, key: str) -> None:
        with pytest.raises(ValidationError):
            AuditEvent(
                event_type=AuditEventType.SCOPE_CHECK,
                tenant_id=tenant_id,
                decision_allowed=True,
                payload={key: 1},
            )

    def test_object_payload_rejected(self, tenant_id: UUID) -> None:
        class _Foo:
            pass

        with pytest.raises(ValidationError):
            AuditEvent(
                event_type=AuditEventType.SCOPE_CHECK,
                tenant_id=tenant_id,
                decision_allowed=True,
                payload={"foo": _Foo()},
            )


# ---------------------------------------------------------------------------
# Hash chain semantics
# ---------------------------------------------------------------------------


class TestHashChain:
    def test_event_hash_is_deterministic_under_same_inputs(
        self, tenant_id: UUID
    ) -> None:
        ts = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
        eid = uuid4()
        e1 = AuditEvent(
            event_id=eid,
            event_type=AuditEventType.SCOPE_CHECK,
            occurred_at=ts,
            tenant_id=tenant_id,
            decision_allowed=True,
            payload={"k": 1},
        )
        e2 = AuditEvent(
            event_id=eid,
            event_type=AuditEventType.SCOPE_CHECK,
            occurred_at=ts,
            tenant_id=tenant_id,
            decision_allowed=True,
            payload={"k": 1},
        )
        assert e1.event_hash == e2.event_hash

    def test_event_hash_changes_when_payload_changes(self, tenant_id: UUID) -> None:
        e1 = AuditEvent(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
            payload={"k": 1},
        )
        e2 = AuditEvent(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
            payload={"k": 2},
        )
        assert e1.event_hash != e2.event_hash

    def test_explicit_event_hash_must_match_recomputation(
        self, tenant_id: UUID
    ) -> None:
        with pytest.raises(AuditChainError) as exc_info:
            AuditEvent(
                event_type=AuditEventType.SCOPE_CHECK,
                tenant_id=tenant_id,
                decision_allowed=True,
                event_hash="0" * 64,
            )
        assert "event_hash mismatch" in str(exc_info.value)

    def test_logger_links_events_into_chain(self, tenant_id: UUID) -> None:
        sink = InMemoryAuditSink()
        logger = AuditLogger(sink)
        e1 = logger.emit(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
        )
        e2 = logger.emit(
            event_type=AuditEventType.POLICY_DECISION,
            tenant_id=tenant_id,
            decision_allowed=True,
        )
        assert e1.prev_event_hash == GENESIS_HASH
        assert e2.prev_event_hash == e1.event_hash
        assert logger.verify_chain(tenant_id=tenant_id) == 2

    def test_distinct_tenants_have_independent_chains(self, tenant_id: UUID) -> None:
        sink = InMemoryAuditSink()
        logger = AuditLogger(sink)
        other_tenant = uuid4()
        e1 = logger.emit(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
        )
        e2 = logger.emit(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=other_tenant,
            decision_allowed=True,
        )
        assert e1.prev_event_hash == GENESIS_HASH
        assert e2.prev_event_hash == GENESIS_HASH
        assert logger.verify_chain(tenant_id=tenant_id) == 1
        assert logger.verify_chain(tenant_id=other_tenant) == 1


# ---------------------------------------------------------------------------
# Tamper detection — verify_chain
# ---------------------------------------------------------------------------


class _MutableSink:
    """Sink double that lets tests mutate the events list (simulate attack)."""

    def __init__(self) -> None:
        self._events: dict[UUID, list[AuditEvent]] = {}
        self._latest: dict[UUID, str] = {}

    def append(self, event: AuditEvent) -> None:
        self._events.setdefault(event.tenant_id, []).append(event)
        self._latest[event.tenant_id] = event.event_hash

    def latest_hash(self, *, tenant_id: UUID) -> str:
        return self._latest.get(tenant_id, GENESIS_HASH)

    def iter_events(self, *, tenant_id: UUID) -> list[AuditEvent]:
        return list(self._events.get(tenant_id, []))

    def force_replace(self, tenant_id: UUID, index: int, event: AuditEvent) -> None:
        """Bypass the append guard (simulate tampered storage)."""
        self._events[tenant_id][index] = event


class TestTamperDetection:
    def test_swapped_middle_event_breaks_chain_at_successor(
        self, tenant_id: UUID
    ) -> None:
        sink = _MutableSink()
        assert isinstance(sink, AuditSink)
        logger = AuditLogger(sink)
        logger.emit(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
        )
        e2 = logger.emit(
            event_type=AuditEventType.POLICY_DECISION,
            tenant_id=tenant_id,
            decision_allowed=True,
        )
        # Anchor e3 to the ORIGINAL e2.event_hash so swapping e2 below
        # leaves a dangling pointer that verify_chain catches.
        logger.emit(
            event_type=AuditEventType.PREFLIGHT_PASS,
            tenant_id=tenant_id,
            decision_allowed=True,
        )
        # Replace event #2 with a self-consistent forgery (its own
        # event_hash matches its contents). The recomputed e3 still
        # points to the OLD e2.event_hash, so the chain link breaks at
        # e3 → ``AuditChainError``.
        forged = AuditEvent(
            event_id=e2.event_id,
            event_type=AuditEventType.POLICY_DECISION,
            occurred_at=e2.occurred_at,
            tenant_id=tenant_id,
            decision_allowed=False,
            failure_summary="forged",
            prev_event_hash=e2.prev_event_hash,
            payload={"forged": True},
        )
        sink.force_replace(tenant_id, 1, forged)
        with pytest.raises(AuditChainError) as exc_info:
            logger.verify_chain(tenant_id=tenant_id)
        assert "chain break" in str(exc_info.value)

    def test_chain_break_when_prev_hash_doesnt_match_predecessor(
        self, tenant_id: UUID
    ) -> None:
        sink = _MutableSink()
        logger = AuditLogger(sink)
        logger.emit(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
        )
        e2 = logger.emit(
            event_type=AuditEventType.POLICY_DECISION,
            tenant_id=tenant_id,
            decision_allowed=True,
        )
        # Build a replacement whose ``prev_event_hash`` is wrong — produce
        # a self-consistent event (its event_hash matches the contents) so
        # the chain-break detector fires the prev_event_hash branch.
        forged = AuditEvent(
            event_id=e2.event_id,
            event_type=e2.event_type,
            occurred_at=e2.occurred_at,
            tenant_id=tenant_id,
            decision_allowed=True,
            prev_event_hash="b" * 64,
            payload=dict(e2.payload),
        )
        sink.force_replace(tenant_id, 1, forged)
        with pytest.raises(AuditChainError) as exc_info:
            logger.verify_chain(tenant_id=tenant_id)
        assert "chain break" in str(exc_info.value)


# ---------------------------------------------------------------------------
# InMemoryAuditSink edge cases
# ---------------------------------------------------------------------------


class TestInMemorySink:
    def test_genesis_for_new_tenant(self, tenant_id: UUID) -> None:
        sink = InMemoryAuditSink()
        assert sink.latest_hash(tenant_id=tenant_id) == GENESIS_HASH

    def test_iter_returns_append_order(self, tenant_id: UUID) -> None:
        sink = InMemoryAuditSink()
        logger = AuditLogger(sink)
        ids = []
        for _ in range(3):
            ev = logger.emit(
                event_type=AuditEventType.SCOPE_CHECK,
                tenant_id=tenant_id,
                decision_allowed=True,
            )
            ids.append(ev.event_id)
        events = list(sink.iter_events(tenant_id=tenant_id))
        assert [e.event_id for e in events] == ids

    def test_duplicate_event_id_rejected(self, tenant_id: UUID) -> None:
        sink = InMemoryAuditSink()
        ev = AuditEvent(
            event_type=AuditEventType.SCOPE_CHECK,
            tenant_id=tenant_id,
            decision_allowed=True,
        )
        sink.append(ev)
        with pytest.raises(AuditChainError):
            sink.append(ev)

    def test_thread_safe_concurrent_emit(self, tenant_id: UUID) -> None:
        sink = InMemoryAuditSink()
        logger = AuditLogger(sink)

        def emit_n(n: int) -> None:
            for _ in range(n):
                logger.emit(
                    event_type=AuditEventType.SCOPE_CHECK,
                    tenant_id=tenant_id,
                    decision_allowed=True,
                )

        threads = [threading.Thread(target=emit_n, args=(20,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert logger.verify_chain(tenant_id=tenant_id) == 80


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


class TestMiscellaneous:
    def test_audit_event_extra_fields_forbidden(self, tenant_id: UUID) -> None:
        with pytest.raises(ValidationError):
            AuditEvent.model_validate(
                {
                    "event_type": "scope.check",
                    "tenant_id": str(tenant_id),
                    "decision_allowed": True,
                    "extra": "nope",
                }
            )

    def test_payload_top_level_must_be_mapping(self, tenant_id: UUID) -> None:
        with pytest.raises(ValidationError):
            AuditEvent.model_validate(
                {
                    "event_type": "scope.check",
                    "tenant_id": str(tenant_id),
                    "decision_allowed": True,
                    "payload": "scalar",
                }
            )

    def test_payload_error_is_distinct_class(self) -> None:
        assert issubclass(AuditPayloadError, Exception)
        assert not issubclass(AuditPayloadError, AuditChainError)
