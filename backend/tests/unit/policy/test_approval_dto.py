"""Structural unit tests for :mod:`src.policy.approval_dto` (T02 follow-up).

These tests are **complementary** to ``test_approval.py`` — they cover
the *DTO* layer specifically, not the :class:`ApprovalService` business
logic. The goal is to lock in the structural guarantees that the cycle
break depends on:

* The pure-DTO module imports nothing beyond stdlib + pydantic. If this
  regresses, ``preflight`` would once again drag ``signing`` / ``audit``
  into a half-built ``policy`` package and the cycle returns.
* Every DTO round-trips losslessly through pydantic JSON serialisation,
  obeys ``extra=forbid`` / ``frozen=True``, and rejects naive datetimes.
* The canonical signing payload (``_canonical_approval_payload``) is
  byte-identical for the same input across runs, sorted, compact, and
  excludes the ``created_at`` field — those properties protect the
  Ed25519 signature contract from silent drift.
"""

from __future__ import annotations

import ast
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from src.policy import approval_dto
from src.policy.approval_dto import (
    APPROVAL_FAILURE_REASONS,
    ApprovalAction,
    ApprovalError,
    ApprovalRequest,
    ApprovalSignature,
    ApprovalStatus,
    _canonical_approval_payload,
    _utcnow,
)

# Roots ``approval_dto`` is allowed to import. Anything outside this set
# combined with ``sys.stdlib_module_names`` indicates a regression of the
# pure-layer contract.
_ALLOWED_THIRD_PARTY_ROOTS: frozenset[str] = frozenset({"pydantic"})

# Deterministic UUIDs reused across tests so failures show stable diffs.
_TENANT_ID: UUID = UUID("11111111-1111-4111-8111-111111111111")
_SCAN_ID: UUID = UUID("22222222-2222-4222-8222-222222222222")


# ---------------------------------------------------------------------------
# Local factories — purposely NOT pytest fixtures
# ---------------------------------------------------------------------------
#
# Fixtures would force every test to depend on conftest plumbing
# (key_manager, audit_logger, etc.) that the structural tests do not need.
# Plain factories keep this file self-contained and explicit.


def _utc_now() -> datetime:
    """Return a fixed tz-aware UTC instant for deterministic tests."""
    return datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)


def _make_request(**overrides: Any) -> ApprovalRequest:
    """Build a valid :class:`ApprovalRequest` with overridable defaults."""
    now = _utc_now()
    base: dict[str, Any] = {
        "tenant_id": _TENANT_ID,
        "action": ApprovalAction.HIGH,
        "tool_id": "burp_active",
        "target": "https://example.com/api",
        "justification": "approved by lead via security review",
        "created_at": now,
        "expires_at": now + timedelta(hours=1),
    }
    base.update(overrides)
    return ApprovalRequest(**base)


def _make_signature(**overrides: Any) -> ApprovalSignature:
    """Build a valid :class:`ApprovalSignature` with overridable defaults."""
    base: dict[str, Any] = {
        "request_id": uuid4(),
        "signer_key_id": "0123456789abcdef",  # exactly 16 hex chars
        "signature_b64": "A" * 86,  # min length for ed25519 base64
        "signed_at": _utc_now(),
    }
    base.update(overrides)
    return ApprovalSignature(**base)


# ---------------------------------------------------------------------------
# Module-level structural invariants
# ---------------------------------------------------------------------------


class TestModuleStructure:
    """Static checks on the source itself; no runtime state involved."""

    def test_module_imports_only_stdlib_and_pydantic(self) -> None:
        """Static AST walk: approval_dto must NOT depend on signing / audit.

        If this regresses, the cycle protection from T02 is brittle —
        the whole point of the DTO split is that the pure layer never
        drags in :mod:`src.sandbox.signing` or :mod:`src.policy.audit`.
        """
        source_path = Path(approval_dto.__file__)
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        allowed: frozenset[str] = (
            sys.stdlib_module_names | _ALLOWED_THIRD_PARTY_ROOTS
        )
        offending: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    if root not in allowed:
                        offending.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                # Relative imports would mean the DTO module reaches into
                # sibling policy modules — exactly what T02 forbids.
                if node.level > 0:
                    offending.append(
                        f"{'.' * node.level}{node.module or ''}"
                    )
                    continue
                if node.module is None:
                    continue
                root = node.module.split(".", 1)[0]
                if root not in allowed:
                    offending.append(node.module)
        assert not offending, (
            f"approval_dto.py imports forbidden modules: {offending!r}. "
            "The pure-DTO layer must depend only on stdlib + pydantic."
        )

    def test_public_all_lists_every_documented_export(self) -> None:
        """``__all__`` MUST include every public symbol callers rely on."""
        expected = {
            "APPROVAL_FAILURE_REASONS",
            "ApprovalAction",
            "ApprovalError",
            "ApprovalRequest",
            "ApprovalSignature",
            "ApprovalStatus",
        }
        assert set(approval_dto.__all__) == expected
        for name in expected:
            assert hasattr(approval_dto, name), (
                f"{name} missing from approval_dto runtime namespace"
            )


# ---------------------------------------------------------------------------
# Failure taxonomy
# ---------------------------------------------------------------------------


class TestFailureTaxonomy:
    def test_reasons_set_is_frozen(self) -> None:
        """Closed taxonomy: external code must not mutate the set."""
        assert isinstance(APPROVAL_FAILURE_REASONS, frozenset)

    def test_every_reason_is_namespaced(self) -> None:
        """All summaries share the ``approval_*`` prefix for log grepping."""
        for summary in APPROVAL_FAILURE_REASONS:
            assert isinstance(summary, str)
            assert summary.startswith("approval_")

    def test_reasons_set_is_non_empty(self) -> None:
        """An empty taxonomy would silently disable downstream validation."""
        assert len(APPROVAL_FAILURE_REASONS) > 0

    @pytest.mark.parametrize(
        "constant_name",
        [
            "_REASON_NO_APPROVAL",
            "_REASON_EXPIRED",
            "_REASON_INVALID_SIG",
            "_REASON_TARGET_MISMATCH",
            "_REASON_ACTION_MISMATCH",
            "_REASON_DUAL_CONTROL",
            "_REASON_UNKNOWN_KEY",
            "_REASON_REVOKED",
        ],
    )
    def test_private_constant_value_in_public_set(
        self, constant_name: str
    ) -> None:
        """Every private ``_REASON_*`` constant is reachable via the public set.

        ``ApprovalService`` raises ``ApprovalError(_REASON_X)`` with the
        private constant; callers MUST be able to assert the summary
        belongs to :data:`APPROVAL_FAILURE_REASONS` without importing
        the private name themselves.
        """
        value = getattr(approval_dto, constant_name)
        assert value in APPROVAL_FAILURE_REASONS


# ---------------------------------------------------------------------------
# ApprovalError
# ---------------------------------------------------------------------------


class TestApprovalError:
    def test_error_subclass_of_exception(self) -> None:
        """``ApprovalError`` is raisable via standard ``except`` blocks."""
        assert issubclass(ApprovalError, Exception)

    def test_error_carries_summary_attribute(self) -> None:
        """The ``summary`` attribute is what the policy plane logs / surfaces."""
        err = ApprovalError("approval_missing")
        assert err.summary == "approval_missing"

    def test_error_str_returns_summary(self) -> None:
        """``str(err)`` returns the summary so log lines stay deterministic."""
        err = ApprovalError("approval_expired")
        assert str(err) == "approval_expired"

    def test_error_args_tuple_holds_summary(self) -> None:
        """``args`` holds the summary so legacy ``except E as e: e.args`` works."""
        err = ApprovalError("approval_unknown_key")
        assert err.args == ("approval_unknown_key",)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_action_values_are_lowercase_strings(self) -> None:
        """``ApprovalAction`` is wire-compatible with lowercase string IO."""
        assert ApprovalAction.HIGH.value == "high"
        assert ApprovalAction.DESTRUCTIVE.value == "destructive"

    def test_status_lifecycle_values_complete(self) -> None:
        """``ApprovalStatus`` covers the full request lifecycle."""
        assert {s.value for s in ApprovalStatus} == {
            "pending",
            "granted",
            "denied",
            "revoked",
            "expired",
        }

    @pytest.mark.parametrize("action", list(ApprovalAction))
    def test_action_roundtrips_through_string(
        self, action: ApprovalAction
    ) -> None:
        """StrEnum lets callers compare enum to plain string identically."""
        assert action == action.value
        assert ApprovalAction(action.value) is action

    @pytest.mark.parametrize("status", list(ApprovalStatus))
    def test_status_roundtrips_through_string(
        self, status: ApprovalStatus
    ) -> None:
        """StrEnum behaviour mirrors :class:`ApprovalAction`."""
        assert status == status.value
        assert ApprovalStatus(status.value) is status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_utcnow_returns_tz_aware_utc(self) -> None:
        """``_utcnow`` MUST return tz-aware UTC; naive datetimes are rejected."""
        now = _utcnow()
        assert now.tzinfo is timezone.utc


# ---------------------------------------------------------------------------
# ApprovalRequest — schema + JSON round-trip
# ---------------------------------------------------------------------------


class TestApprovalRequestSchema:
    def test_round_trip_via_model_dump_json(self) -> None:
        """Request → JSON → Request is lossless and yields an equal model."""
        req = _make_request(scan_id=_SCAN_ID)
        as_json = req.model_dump_json()
        restored = ApprovalRequest.model_validate_json(as_json)
        assert restored == req

    def test_round_trip_preserves_uuid_types(self) -> None:
        """Re-parsed request keeps :class:`UUID` typing on identifier fields."""
        req = _make_request(scan_id=_SCAN_ID)
        restored = ApprovalRequest.model_validate_json(req.model_dump_json())
        assert isinstance(restored.tenant_id, UUID)
        assert isinstance(restored.scan_id, UUID)
        assert isinstance(restored.request_id, UUID)

    def test_request_id_default_factory_emits_unique_uuids(self) -> None:
        """No explicit ``request_id`` falls back to ``uuid4`` per call."""
        req1 = _make_request()
        req2 = _make_request()
        assert req1.request_id != req2.request_id
        assert isinstance(req1.request_id, UUID)

    def test_request_id_explicit_overrides_default(self) -> None:
        """An explicit ``request_id`` wins over the default factory."""
        explicit = uuid4()
        req = _make_request(request_id=explicit)
        assert req.request_id == explicit

    def test_scan_id_optional_defaults_to_none(self) -> None:
        """``scan_id`` is optional — internal/admin actions skip the field."""
        req = _make_request()
        assert req.scan_id is None

    def test_created_at_default_factory_is_tz_aware_utc(self) -> None:
        """Default ``created_at`` factory yields tz-aware UTC instant.

        ``expires_at`` MUST be strictly later than the (defaulted)
        ``created_at`` — using the *fixed* :func:`_utc_now` helper here
        anchors the check to 2026-04-17, which is in the past relative
        to the wall clock the default factory reads. Anchoring
        ``expires_at`` to ``datetime.now(tz=UTC) + 1h`` keeps the test
        focused on the default factory and free from time drift.
        """
        req = ApprovalRequest(
            tenant_id=_TENANT_ID,
            action=ApprovalAction.HIGH,
            tool_id="burp_active",
            target="https://example.com/api",
            justification="approved by lead via security review",
            expires_at=datetime.now(tz=timezone.utc) + timedelta(hours=1),
        )
        assert req.created_at.tzinfo is not None
        assert req.created_at.utcoffset() == timedelta(0)

    def test_extra_fields_forbidden(self) -> None:
        """``extra=forbid`` blocks accidental schema drift."""
        with pytest.raises(ValidationError):
            ApprovalRequest.model_validate(
                {
                    "tenant_id": str(_TENANT_ID),
                    "action": "high",
                    "tool_id": "burp_active",
                    "target": "https://example.com",
                    "justification": "approved by lead via security review",
                    "created_at": _utc_now().isoformat(),
                    "expires_at": (_utc_now() + timedelta(hours=1)).isoformat(),
                    "extra_field": "should_be_rejected",
                }
            )

    def test_model_is_frozen(self) -> None:
        """Immutability protects request bytes after they are signed."""
        req = _make_request()
        with pytest.raises(ValidationError):
            req.target = "https://different.example.com"  # type: ignore[misc]

    @pytest.mark.parametrize(
        ("field", "bad_value"),
        [
            ("tool_id", "x"),  # below min_length=2
            ("tool_id", "z" * 65),  # above max_length=64
            ("target", ""),  # below min_length=1
            ("target", "x" * 2049),  # above max_length=2048
            ("justification", "tooshort"),  # 8 chars, below min_length=10
            ("justification", "j" * 513),  # above max_length=512
        ],
    )
    def test_string_bounds_enforced(self, field: str, bad_value: str) -> None:
        """Length bounds defend against pathological / malformed payloads."""
        with pytest.raises(ValidationError):
            _make_request(**{field: bad_value})

    def test_naive_expires_at_rejected(self) -> None:
        """Naive ``expires_at`` is ambiguous; UTC awareness is mandatory."""
        with pytest.raises(ValidationError):
            ApprovalRequest(
                tenant_id=_TENANT_ID,
                action=ApprovalAction.HIGH,
                tool_id="burp_active",
                target="https://example.com",
                justification="approved by lead via security review",
                created_at=_utc_now(),
                expires_at=datetime(2026, 4, 17, 13, 0, 0),  # naive
            )

    def test_naive_created_at_rejected(self) -> None:
        """Naive ``created_at`` is similarly rejected by the validator."""
        # ``expires_at`` is supplied tz-aware so the validator gates on
        # ``created_at`` rather than short-circuiting on the first check.
        now = _utc_now()
        with pytest.raises(ValidationError):
            ApprovalRequest(
                tenant_id=_TENANT_ID,
                action=ApprovalAction.HIGH,
                tool_id="burp_active",
                target="https://example.com",
                justification="approved by lead via security review",
                created_at=datetime(2026, 4, 17, 12, 0, 0),  # naive
                expires_at=now + timedelta(hours=1),
            )

    def test_expires_before_created_rejected(self) -> None:
        """``expires_at`` MUST be strictly later than ``created_at``."""
        now = _utc_now()
        with pytest.raises(ValidationError):
            _make_request(created_at=now, expires_at=now - timedelta(seconds=1))

    def test_expires_equals_created_rejected(self) -> None:
        """Strict inequality — equal expires_at and created_at is invalid."""
        now = _utc_now()
        with pytest.raises(ValidationError):
            _make_request(created_at=now, expires_at=now)


# ---------------------------------------------------------------------------
# ApprovalSignature — schema + JSON round-trip
# ---------------------------------------------------------------------------


class TestApprovalSignatureSchema:
    def test_round_trip_via_model_dump_json(self) -> None:
        """Signature → JSON → Signature is lossless."""
        sig = _make_signature()
        restored = ApprovalSignature.model_validate_json(sig.model_dump_json())
        assert restored == sig

    def test_round_trip_preserves_optional_actor_id(self) -> None:
        """An explicit ``signer_actor_id`` survives the round trip."""
        actor = uuid4()
        sig = _make_signature(signer_actor_id=actor)
        restored = ApprovalSignature.model_validate_json(sig.model_dump_json())
        assert restored.signer_actor_id == actor

    def test_signer_actor_id_optional_defaults_to_none(self) -> None:
        """``signer_actor_id`` is optional — anonymous service accounts."""
        sig = _make_signature()
        assert sig.signer_actor_id is None

    def test_signed_at_default_is_tz_aware_utc(self) -> None:
        """Default factory yields tz-aware UTC instant."""
        sig = ApprovalSignature(
            request_id=uuid4(),
            signer_key_id="0123456789abcdef",
            signature_b64="A" * 86,
        )
        assert sig.signed_at.tzinfo is not None
        assert sig.signed_at.utcoffset() == timedelta(0)

    @pytest.mark.parametrize(
        ("field", "bad_value"),
        [
            ("signer_key_id", "short"),  # below min_length=16
            ("signer_key_id", "x" * 17),  # above max_length=16
            ("signature_b64", "z" * 85),  # below min_length=86
            ("signature_b64", "z" * 129),  # above max_length=128
        ],
    )
    def test_string_bounds_enforced(self, field: str, bad_value: str) -> None:
        """Length bounds match the Ed25519 wire format we expect."""
        with pytest.raises(ValidationError):
            _make_signature(**{field: bad_value})

    def test_extra_fields_forbidden(self) -> None:
        """``extra=forbid`` keeps signatures strictly typed."""
        with pytest.raises(ValidationError):
            ApprovalSignature.model_validate(
                {
                    "request_id": str(uuid4()),
                    "signer_key_id": "0123456789abcdef",
                    "signature_b64": "A" * 86,
                    "signed_at": _utc_now().isoformat(),
                    "extra": "nope",
                }
            )

    def test_naive_signed_at_rejected(self) -> None:
        """Naive ``signed_at`` is invalid — every audit field is UTC."""
        with pytest.raises(ValidationError):
            ApprovalSignature(
                request_id=uuid4(),
                signer_key_id="0123456789abcdef",
                signature_b64="A" * 86,
                signed_at=datetime(2026, 4, 17, 12, 0, 0),  # naive
            )

    def test_model_is_frozen(self) -> None:
        """Signatures are immutable post-construction."""
        sig = _make_signature()
        with pytest.raises(ValidationError):
            sig.signer_key_id = "ffffffffffffffff"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Canonical signing payload — deterministic byte stability
# ---------------------------------------------------------------------------


class TestCanonicalPayload:
    """The signing bytes MUST be byte-stable to keep Ed25519 verification sound."""

    def test_payload_is_byte_stable_for_same_input(self) -> None:
        """Two calls on the same model yield exactly the same bytes."""
        req = _make_request()
        first = _canonical_approval_payload(req)
        second = _canonical_approval_payload(req)
        assert first == second
        assert isinstance(first, bytes)

    def test_payload_byte_stable_for_equal_models(self) -> None:
        """Two structurally equal models produce identical bytes.

        The signature contract treats the request as a value type — any
        request with the same fields must hash to the same bytes.
        """
        explicit_id = uuid4()
        now = _utc_now()
        req1 = _make_request(
            request_id=explicit_id, created_at=now, expires_at=now + timedelta(hours=1)
        )
        req2 = _make_request(
            request_id=explicit_id, created_at=now, expires_at=now + timedelta(hours=1)
        )
        assert req1 == req2
        assert _canonical_approval_payload(req1) == _canonical_approval_payload(req2)

    def test_canonical_bytes_method_delegates_to_helper(self) -> None:
        """``request.canonical_bytes()`` must delegate to the module helper."""
        req = _make_request()
        assert req.canonical_bytes() == _canonical_approval_payload(req)

    def test_payload_excludes_created_at(self) -> None:
        """``created_at`` is mutable platform metadata — never signed."""
        now = _utc_now()
        req1 = _make_request(created_at=now, expires_at=now + timedelta(hours=1))
        # Same request_id but different created_at → bytes must NOT change,
        # otherwise re-issuing a saved approval invalidates its signature.
        req2 = ApprovalRequest(
            request_id=req1.request_id,
            tenant_id=req1.tenant_id,
            scan_id=req1.scan_id,
            action=req1.action,
            tool_id=req1.tool_id,
            target=req1.target,
            justification=req1.justification,
            created_at=now - timedelta(minutes=30),
            expires_at=req1.expires_at,
        )
        assert _canonical_approval_payload(req1) == _canonical_approval_payload(req2)

    def test_payload_keys_are_sorted(self) -> None:
        """``sort_keys=True`` lets verifiers byte-compare without re-parsing."""
        req = _make_request()
        decoded = json.loads(_canonical_approval_payload(req).decode("utf-8"))
        keys = list(decoded.keys())
        assert keys == sorted(keys), f"Canonical payload keys not sorted: {keys}"

    def test_payload_uses_compact_separators(self) -> None:
        """No whitespace between separators — wire-compact + stable bytes."""
        req = _make_request()
        raw = _canonical_approval_payload(req)
        assert b": " not in raw, "Whitespace after ':' breaks byte stability"
        assert b", " not in raw, "Whitespace after ',' breaks byte stability"

    def test_payload_target_change_changes_bytes(self) -> None:
        """Changing operator-meaningful fields changes the signed payload."""
        req1 = _make_request(target="https://a.example.com")
        req2 = ApprovalRequest(
            request_id=req1.request_id,
            tenant_id=req1.tenant_id,
            scan_id=req1.scan_id,
            action=req1.action,
            tool_id=req1.tool_id,
            target="https://b.example.com",
            justification=req1.justification,
            created_at=req1.created_at,
            expires_at=req1.expires_at,
        )
        assert _canonical_approval_payload(req1) != _canonical_approval_payload(req2)

    def test_payload_includes_scan_id_when_set(self) -> None:
        """``scan_id`` is part of the signed bytes when present."""
        req_with = _make_request(scan_id=_SCAN_ID)
        req_without = ApprovalRequest(
            request_id=req_with.request_id,
            tenant_id=req_with.tenant_id,
            scan_id=None,
            action=req_with.action,
            tool_id=req_with.tool_id,
            target=req_with.target,
            justification=req_with.justification,
            created_at=req_with.created_at,
            expires_at=req_with.expires_at,
        )
        bytes_with = _canonical_approval_payload(req_with)
        bytes_without = _canonical_approval_payload(req_without)
        assert bytes_with != bytes_without
        # Sanity: the ``scan_id`` UUID literal MUST appear in the signed
        # bytes when set, otherwise the binding is silent.
        assert str(_SCAN_ID).encode("ascii") in bytes_with

    def test_payload_normalises_expiry_to_utc(self) -> None:
        """Equivalent instants in different tz produce identical bytes.

        ``_canonical_approval_payload`` calls
        ``expires_at.astimezone(timezone.utc).isoformat()`` so two
        datetimes representing the same instant in different timezones
        MUST collapse to the same wire bytes.
        """
        now = _utc_now()
        utc_req = _make_request(
            created_at=now, expires_at=now + timedelta(hours=1)
        )
        non_utc_expires = (now + timedelta(hours=1)).astimezone(
            timezone(timedelta(hours=5))
        )
        non_utc_req = ApprovalRequest(
            request_id=utc_req.request_id,
            tenant_id=utc_req.tenant_id,
            scan_id=utc_req.scan_id,
            action=utc_req.action,
            tool_id=utc_req.tool_id,
            target=utc_req.target,
            justification=utc_req.justification,
            created_at=utc_req.created_at,
            expires_at=non_utc_expires,
        )
        assert _canonical_approval_payload(utc_req) == _canonical_approval_payload(
            non_utc_req
        )

    def test_payload_is_valid_utf8_json(self) -> None:
        """The bytes MUST decode as UTF-8 JSON for portable verification."""
        req = _make_request()
        raw = _canonical_approval_payload(req)
        decoded = raw.decode("utf-8")
        parsed = json.loads(decoded)
        assert isinstance(parsed, dict)
        # Verify the fields the signature contract guarantees are present.
        for required in (
            "request_id",
            "tenant_id",
            "scan_id",
            "action",
            "tool_id",
            "target",
            "justification",
            "expires_at",
        ):
            assert required in parsed, f"Canonical payload missing {required!r}"
        # And ``created_at`` MUST NOT leak in.
        assert "created_at" not in parsed
