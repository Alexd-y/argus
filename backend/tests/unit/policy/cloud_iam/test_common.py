"""Unit tests for :mod:`src.policy.cloud_iam._common` (ARG-043)."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from uuid import UUID

import pytest

from src.policy.audit import AuditEventType, AuditLogger, InMemoryAuditSink
from src.policy.cloud_iam import _common as common
from src.policy.cloud_iam._common import (
    CLOUD_METHOD_METADATA,
    CLOUD_PROOF_DEFAULT_TTL,
    CloudPrincipalDescriptor,
    constant_time_str_equal,
    descriptor_from_challenge,
    emit_cloud_attempt,
    hash_identifier,
    make_proof,
    metadata_for,
    redact_token,
    run_with_timeout,
    utcnow,
)
from src.policy.ownership import (
    REASON_AWS_STS_TIMEOUT,
    REASON_AZURE_MI_TIMEOUT,
    REASON_GCP_SA_JWT_TIMEOUT,
    OwnershipChallenge,
    OwnershipMethod,
    OwnershipTimeoutError,
    OwnershipVerificationError,
)


# ---------------------------------------------------------------------------
# utcnow / constant-time compare / hash_identifier
# ---------------------------------------------------------------------------


class TestPureHelpers:
    def test_utcnow_is_timezone_aware(self) -> None:
        now = utcnow()
        assert now.tzinfo is not None
        assert now.utcoffset() == timedelta(0)

    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ("hello", "hello", True),
            ("hello", "Hello", False),
            ("", "", True),
            ("a", "ab", False),
            ("\u00e9", "\u00e9", True),  # accented char round-trip
        ],
    )
    def test_constant_time_str_equal(
        self, left: str, right: str, expected: bool
    ) -> None:
        assert constant_time_str_equal(left, right) is expected

    def test_hash_identifier_is_deterministic(self) -> None:
        a = hash_identifier("arn:aws:iam::123:role/argus")
        b = hash_identifier("arn:aws:iam::123:role/argus")
        c = hash_identifier("arn:aws:iam::999:role/argus")
        assert a == b
        assert a != c

    def test_hash_identifier_truncated_to_16_hex_chars(self) -> None:
        assert len(hash_identifier("anything")) == 16
        assert all(c in "0123456789abcdef" for c in hash_identifier("x"))


# ---------------------------------------------------------------------------
# Descriptor + audit payload
# ---------------------------------------------------------------------------


class TestDescriptor:
    def test_descriptor_renders_only_hashed_strings(self) -> None:
        descriptor = CloudPrincipalDescriptor(
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_hash=hash_identifier("arn:aws:iam::123:role/argus"),
            target_hash=hash_identifier("arn:aws:iam::123:role/argus"),
        )
        payload = descriptor.to_audit_payload()
        assert set(payload) == {
            "cloud_provider",
            "principal_kind",
            "principal_hash",
            "target_hash",
        }
        assert all(isinstance(v, str) for v in payload.values())

    def test_descriptor_from_challenge_hashes_inputs(self) -> None:
        challenge = _challenge(target="arn:aws:iam::123:role/argus")
        descriptor = descriptor_from_challenge(
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier="arn:aws:iam::123:role/argus",
            challenge=challenge,
        )
        assert "arn:aws" not in descriptor.principal_hash
        assert "arn:aws" not in descriptor.target_hash
        assert descriptor.principal_hash == descriptor.target_hash


# ---------------------------------------------------------------------------
# make_proof
# ---------------------------------------------------------------------------


class TestMakeProof:
    def test_default_ttl_is_capped_to_one_hour(self) -> None:
        challenge = _challenge(ttl=timedelta(hours=12))
        proof = make_proof(challenge=challenge)

        assert proof.tenant_id == challenge.tenant_id
        assert proof.target == challenge.target
        assert proof.method is challenge.method
        assert proof.valid_until - proof.verified_at <= CLOUD_PROOF_DEFAULT_TTL

    def test_proof_capped_against_challenge_expires_at(self) -> None:
        challenge = _challenge(ttl=timedelta(minutes=5))  # shorter than 1h
        proof = make_proof(challenge=challenge)
        assert proof.valid_until <= challenge.expires_at

    def test_negative_ttl_rejected(self) -> None:
        challenge = _challenge()
        with pytest.raises(ValueError):
            make_proof(challenge=challenge, ttl=timedelta(seconds=0))
        with pytest.raises(ValueError):
            make_proof(challenge=challenge, ttl=timedelta(seconds=-1))

    def test_long_notes_truncated_to_256_chars(self) -> None:
        challenge = _challenge()
        proof = make_proof(challenge=challenge, notes="x" * 1024)
        assert len(proof.notes) == 256


# ---------------------------------------------------------------------------
# run_with_timeout
# ---------------------------------------------------------------------------


class TestRunWithTimeout:
    @pytest.mark.asyncio
    async def test_returns_value_when_under_budget(self) -> None:
        async def _work() -> int:
            return 42

        result = await run_with_timeout(
            _work,
            timeout_s=1.0,
            timeout_reason=REASON_AWS_STS_TIMEOUT,
        )
        assert result == 42

    @pytest.mark.asyncio
    async def test_raises_ownership_timeout_with_closed_taxonomy(self) -> None:
        async def _slow() -> None:
            await asyncio.sleep(0.5)

        with pytest.raises(OwnershipTimeoutError) as exc:
            await run_with_timeout(
                _slow,
                timeout_s=0.05,
                timeout_reason=REASON_GCP_SA_JWT_TIMEOUT,
            )
        assert exc.value.summary == REASON_GCP_SA_JWT_TIMEOUT

    @pytest.mark.asyncio
    async def test_open_taxonomy_reason_rejected(self) -> None:
        async def _work() -> None:
            return None

        with pytest.raises(ValueError):
            await run_with_timeout(
                _work,
                timeout_s=1.0,
                timeout_reason="not_a_real_reason",
            )

    @pytest.mark.asyncio
    async def test_zero_or_negative_timeout_rejected(self) -> None:
        async def _work() -> None:
            return None

        with pytest.raises(ValueError):
            await run_with_timeout(
                _work,
                timeout_s=0,
                timeout_reason=REASON_AZURE_MI_TIMEOUT,
            )
        with pytest.raises(ValueError):
            await run_with_timeout(
                _work,
                timeout_s=-1.0,
                timeout_reason=REASON_AZURE_MI_TIMEOUT,
            )

    @pytest.mark.asyncio
    async def test_default_reads_constant_at_call_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(common, "CLOUD_SDK_TIMEOUT_S", 0.05)

        async def _slow() -> None:
            await asyncio.sleep(0.5)

        with pytest.raises(OwnershipTimeoutError):
            await run_with_timeout(_slow, timeout_reason=REASON_AWS_STS_TIMEOUT)


# ---------------------------------------------------------------------------
# emit_cloud_attempt
# ---------------------------------------------------------------------------


class TestEmitCloudAttempt:
    def test_payload_carries_only_hashes(self) -> None:
        sink = InMemoryAuditSink()
        logger = AuditLogger(sink)
        challenge = _challenge(target="arn:aws:iam::123:role/argus")
        descriptor = descriptor_from_challenge(
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier="arn:aws:iam::123:role/argus",
            challenge=challenge,
        )

        emit_cloud_attempt(
            audit_logger=logger,
            challenge=challenge,
            actor_id=None,
            descriptor=descriptor,
            allowed=True,
            summary=None,
        )

        events = list(sink.iter_events(tenant_id=challenge.tenant_id))
        assert len(events) == 1
        ev = events[0]
        assert ev.event_type is AuditEventType.OWNERSHIP_VERIFY
        assert ev.decision_allowed is True
        assert ev.failure_summary is None

        flat = repr(dict(ev.payload))
        assert "arn:aws" not in flat
        assert challenge.target not in flat
        assert descriptor.target_hash in flat
        assert descriptor.principal_hash in flat

    def test_extra_blocks_known_secret_fields(self) -> None:
        sink = InMemoryAuditSink()
        logger = AuditLogger(sink)
        challenge = _challenge()
        descriptor = descriptor_from_challenge(
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier="arn:aws:iam::1:role/x",
            challenge=challenge,
        )

        for forbidden in (
            "principal_arn",
            "principal_email",
            "token",
            "jwt",
            "external_id",
            "client_secret",
            "access_token",
            "id_token",
            "raw_response",
        ):
            with pytest.raises(ValueError):
                emit_cloud_attempt(
                    audit_logger=logger,
                    challenge=challenge,
                    actor_id=None,
                    descriptor=descriptor,
                    allowed=True,
                    summary=None,
                    extra={forbidden: "leak-me"},
                )

    def test_summary_propagates_when_failure(self) -> None:
        sink = InMemoryAuditSink()
        logger = AuditLogger(sink)
        challenge = _challenge()
        descriptor = descriptor_from_challenge(
            cloud_provider="azure",
            principal_kind="managed_identity_object_id",
            principal_identifier="oid-x",
            challenge=challenge,
        )

        emit_cloud_attempt(
            audit_logger=logger,
            challenge=challenge,
            actor_id=None,
            descriptor=descriptor,
            allowed=False,
            summary="ownership_azure_mi_token_refresh_failed",
        )

        ev = next(iter(sink.iter_events(tenant_id=challenge.tenant_id)))
        assert ev.decision_allowed is False
        assert ev.failure_summary == "ownership_azure_mi_token_refresh_failed"


# ---------------------------------------------------------------------------
# redact_token
# ---------------------------------------------------------------------------


class TestRedactToken:
    @pytest.mark.parametrize(
        "value,expected_prefix",
        [
            ("abcdefgh-very-long", "abcd"),
            ("xyz", "<redacted>"),
        ],
    )
    def test_keeps_at_most_4_chars(self, value: str, expected_prefix: str) -> None:
        out = redact_token(value, keep=10)  # caller asks 10, capped to 4
        assert out.startswith(expected_prefix)

    def test_none_handled(self) -> None:
        assert redact_token(None) == "<none>"

    def test_short_value_fully_redacted(self) -> None:
        assert redact_token("abc", keep=4) == "<redacted>"

    def test_does_not_leak_token_length_for_short_values(self) -> None:
        out = redact_token("abc", keep=4)
        assert "len=" not in out


# ---------------------------------------------------------------------------
# Cloud-method metadata
# ---------------------------------------------------------------------------


class TestCloudMethodMetadata:
    def test_metadata_covers_all_cloud_methods(self) -> None:
        assert set(CLOUD_METHOD_METADATA) == {
            OwnershipMethod.AWS_STS_ASSUME_ROLE,
            OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
            OwnershipMethod.AZURE_MANAGED_IDENTITY,
        }

    @pytest.mark.parametrize(
        "method,provider",
        [
            (OwnershipMethod.AWS_STS_ASSUME_ROLE, "aws"),
            (OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT, "gcp"),
            (OwnershipMethod.AZURE_MANAGED_IDENTITY, "azure"),
        ],
    )
    def test_metadata_for_returns_provider(
        self, method: OwnershipMethod, provider: str
    ) -> None:
        assert metadata_for(method).cloud_provider == provider

    def test_metadata_for_rejects_non_cloud_methods(self) -> None:
        with pytest.raises(OwnershipVerificationError):
            metadata_for(OwnershipMethod.DNS_TXT)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _challenge(
    *,
    target: str = "arn:aws:iam::123456789012:role/argus-prod",
    method: OwnershipMethod = OwnershipMethod.AWS_STS_ASSUME_ROLE,
    ttl: timedelta = timedelta(hours=1),
    token: str = "TestExternalIdTestExternalIdTestExternalIdT",
) -> OwnershipChallenge:
    issued_at = utcnow()
    return OwnershipChallenge(
        tenant_id=UUID("00000000-0000-4000-8000-000000000010"),
        target=target,
        method=method,
        token=token,
        issued_at=issued_at,
        expires_at=issued_at + ttl,
    )
