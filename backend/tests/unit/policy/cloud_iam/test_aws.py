"""Unit tests for :mod:`src.policy.cloud_iam.aws` (ARG-043).

These tests never touch ``boto3``; the AWS STS surface is replaced by
in-memory :class:`StsClientProtocol` stubs. Coverage spans:

* ARN parsing edge cases
* successful AssumeRole round-trip → :class:`OwnershipProof`
* every closed-taxonomy failure reason (invalid ARN, access denied,
  region mismatch, timeout)
* audit-log discipline (no raw secrets in the payload)
* timeout enforcement bounded by
  :data:`src.policy.ownership.CLOUD_SDK_TIMEOUT_S`
* DI safety — verifier rejects mis-keyed cloud_verifier mappings
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from src.policy.audit import AuditLogger, InMemoryAuditSink
from src.policy.cloud_iam._common import hash_identifier
from src.policy.cloud_iam.aws import (
    AssumeRoleResponse,
    AwsStsVerifier,
    BotoStsAdapter,
    StsClientProtocol,
    parse_role_arn,
)
from src.policy.ownership import (
    REASON_AWS_STS_ACCESS_DENIED,
    REASON_AWS_STS_INVALID_ARN,
    REASON_AWS_STS_REGION_MISMATCH,
    REASON_AWS_STS_TIMEOUT,
    OwnershipMethod,
    OwnershipVerificationError,
)
from tests.unit.policy.cloud_iam.conftest import make_challenge


# ---------------------------------------------------------------------------
# Stub STS client
# ---------------------------------------------------------------------------


class _StubSts:
    """In-memory :class:`StsClientProtocol` used to drive tests."""

    cloud_provider = "aws"

    def __init__(
        self,
        *,
        responses: list[AssumeRoleResponse | Exception] | None = None,
        sleep_s: float = 0.0,
    ) -> None:
        self._responses = list(responses or [])
        self.calls: list[dict[str, Any]] = []
        self._sleep_s = sleep_s

    async def assume_role(
        self,
        *,
        role_arn: str,
        role_session_name: str,
        external_id: str,
        duration_seconds: int,
    ) -> AssumeRoleResponse:
        self.calls.append(
            {
                "role_arn": role_arn,
                "role_session_name": role_session_name,
                "external_id": external_id,
                "duration_seconds": duration_seconds,
            }
        )
        if self._sleep_s > 0:
            await asyncio.sleep(self._sleep_s)
        if not self._responses:
            raise AssertionError("stub exhausted — test forgot to seed a response")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok_response(account: str = "123456789012") -> AssumeRoleResponse:
    return AssumeRoleResponse(
        Account=account,
        AssumedRoleUser={
            "Arn": f"arn:aws:sts::{account}:assumed-role/argus-ownership/test-session",
            "AssumedRoleId": "AROAEXAMPLEXXXXX:test-session",
        },
    )


# ---------------------------------------------------------------------------
# parse_role_arn
# ---------------------------------------------------------------------------


class TestParseRoleArn:
    def test_valid_role_arn(self) -> None:
        result = parse_role_arn("arn:aws:iam::123456789012:role/argus-ownership")
        assert result["partition"] == "aws"
        assert result["account_id"] == "123456789012"
        assert result["role_name"] == "argus-ownership"

    def test_govcloud_role_arn(self) -> None:
        result = parse_role_arn("arn:aws-us-gov:iam::123456789012:role/svc")
        assert result["partition"] == "aws-us-gov"

    def test_china_role_arn(self) -> None:
        result = parse_role_arn("arn:aws-cn:iam::987654321098:role/cn-role")
        assert result["partition"] == "aws-cn"

    def test_role_path(self) -> None:
        result = parse_role_arn("arn:aws:iam::123456789012:role/team/argus")
        assert result["role_name"] == "team/argus"

    def test_too_short_account_rejected(self) -> None:
        with pytest.raises(OwnershipVerificationError) as exc:
            parse_role_arn("arn:aws:iam::1234567890:role/x")  # 10 digits
        assert exc.value.summary == REASON_AWS_STS_INVALID_ARN

    def test_unknown_partition_rejected(self) -> None:
        with pytest.raises(OwnershipVerificationError) as exc:
            parse_role_arn("arn:notaws:iam::123456789012:role/x")
        assert exc.value.summary == REASON_AWS_STS_INVALID_ARN

    def test_blank_arn_rejected(self) -> None:
        with pytest.raises(OwnershipVerificationError):
            parse_role_arn("")

    def test_too_long_arn_rejected(self) -> None:
        with pytest.raises(OwnershipVerificationError):
            parse_role_arn("arn:aws:iam::123456789012:role/" + "a" * 5_000)

    def test_user_arn_rejected(self) -> None:
        with pytest.raises(OwnershipVerificationError):
            parse_role_arn("arn:aws:iam::123456789012:user/jane")


# ---------------------------------------------------------------------------
# AwsStsVerifier — happy path + dispatch
# ---------------------------------------------------------------------------


class TestAwsStsVerifier:
    def test_constructor_rejects_short_session_duration(self) -> None:
        sts = _StubSts()
        with pytest.raises(ValueError):
            AwsStsVerifier(sts_client=sts, session_duration_s=300)

    def test_constructor_rejects_oversized_prefix(self) -> None:
        sts = _StubSts()
        with pytest.raises(ValueError):
            AwsStsVerifier(sts_client=sts, role_session_name_prefix="x" * 64)

    def test_constructor_rejects_non_alnum_prefix(self) -> None:
        sts = _StubSts()
        with pytest.raises(ValueError):
            AwsStsVerifier(sts_client=sts, role_session_name_prefix="argus_owner!")

    def test_cloud_provider_attribute(self) -> None:
        sts = _StubSts()
        verifier = AwsStsVerifier(sts_client=sts)
        assert verifier.cloud_provider == "aws"

    @pytest.mark.asyncio
    async def test_happy_path_returns_proof(
        self, aws_challenge_token: str
    ) -> None:
        sts = _StubSts(responses=[_ok_response()])
        verifier = AwsStsVerifier(sts_client=sts)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        proof = await verifier.verify(challenge)
        assert proof.tenant_id == challenge.tenant_id
        assert proof.method is OwnershipMethod.AWS_STS_ASSUME_ROLE
        assert proof.target == challenge.target
        assert sts.calls[0]["external_id"] == aws_challenge_token
        assert sts.calls[0]["duration_seconds"] == 900

    @pytest.mark.asyncio
    async def test_session_name_derived_from_challenge(
        self, aws_challenge_token: str
    ) -> None:
        sts = _StubSts(responses=[_ok_response()])
        verifier = AwsStsVerifier(sts_client=sts)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        await verifier.verify(challenge)
        session_name = sts.calls[0]["role_session_name"]
        assert session_name.startswith("argus-ownership-")
        assert challenge.challenge_id.hex[:24] in session_name
        assert len(session_name) <= 64

    @pytest.mark.asyncio
    async def test_method_mismatch_raises_invalid_arn(
        self, aws_challenge_token: str
    ) -> None:
        sts = _StubSts()
        verifier = AwsStsVerifier(sts_client=sts)
        challenge = make_challenge(
            method=OwnershipMethod.DNS_TXT,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_AWS_STS_INVALID_ARN
        assert sts.calls == []  # no SDK call made

    @pytest.mark.asyncio
    async def test_invalid_arn_short_circuits(
        self, aws_challenge_token: str
    ) -> None:
        sts = _StubSts()
        verifier = AwsStsVerifier(sts_client=sts)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="not-an-arn",
            token=aws_challenge_token,
        )
        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_AWS_STS_INVALID_ARN
        assert sts.calls == []

    @pytest.mark.asyncio
    async def test_account_mismatch_raises_region_mismatch(
        self, aws_challenge_token: str
    ) -> None:
        sts = _StubSts(responses=[_ok_response(account="999999999999")])
        verifier = AwsStsVerifier(sts_client=sts)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_AWS_STS_REGION_MISMATCH

    @pytest.mark.asyncio
    async def test_role_name_mismatch_raises_invalid_arn(
        self, aws_challenge_token: str
    ) -> None:
        bad_response = AssumeRoleResponse(
            Account="123456789012",
            AssumedRoleUser={
                "Arn": "arn:aws:sts::123456789012:assumed-role/wrong-role/sess",
            },
        )
        sts = _StubSts(responses=[bad_response])
        verifier = AwsStsVerifier(sts_client=sts)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_AWS_STS_INVALID_ARN

    @pytest.mark.asyncio
    async def test_resolver_account_mismatch(self, aws_challenge_token: str) -> None:
        sts = _StubSts(responses=[_ok_response()])
        verifier = AwsStsVerifier(
            sts_client=sts,
            expected_account_resolver=lambda _ch: "000000000000",
        )
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_AWS_STS_REGION_MISMATCH


# ---------------------------------------------------------------------------
# Boto-error mapping
# ---------------------------------------------------------------------------


class AccessDeniedException(Exception):
    """Mirrors boto3's STS ``AccessDeniedException`` class name."""


class ValidationError(Exception):
    """Mirrors boto3's STS ``ValidationError`` class name."""


class TestBotoErrorMapping:
    @pytest.mark.asyncio
    async def test_access_denied_mapped(self, aws_challenge_token: str) -> None:
        sts = _StubSts(responses=[AccessDeniedException("denied")])
        verifier = AwsStsVerifier(sts_client=sts)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_AWS_STS_ACCESS_DENIED

    @pytest.mark.asyncio
    async def test_validation_error_mapped(self, aws_challenge_token: str) -> None:
        sts = _StubSts(responses=[ValidationError("bad input")])
        verifier = AwsStsVerifier(sts_client=sts)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_AWS_STS_INVALID_ARN

    @pytest.mark.asyncio
    async def test_unknown_exception_defaults_to_access_denied(
        self, aws_challenge_token: str
    ) -> None:
        class MysteryError(Exception):
            pass

        sts = _StubSts(responses=[MysteryError("???")])
        verifier = AwsStsVerifier(sts_client=sts)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_AWS_STS_ACCESS_DENIED


# ---------------------------------------------------------------------------
# Timeout enforcement
# ---------------------------------------------------------------------------


class TestTimeout:
    @pytest.mark.asyncio
    async def test_sdk_stall_raises_timeout(
        self, aws_challenge_token: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sts = _StubSts(responses=[_ok_response()], sleep_s=10.0)
        verifier = AwsStsVerifier(sts_client=sts)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        # Patch the configured timeout down to a tiny value so the test
        # does not actually wait 5s.
        from src.policy.cloud_iam import _common as common

        monkeypatch.setattr(common, "CLOUD_SDK_TIMEOUT_S", 0.05)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_AWS_STS_TIMEOUT


# ---------------------------------------------------------------------------
# Audit-log discipline
# ---------------------------------------------------------------------------


class TestAuditDiscipline:
    @pytest.mark.asyncio
    async def test_audit_payload_only_carries_hashes(
        self,
        aws_challenge_token: str,
        cloud_audit_logger: AuditLogger,
        cloud_audit_sink: InMemoryAuditSink,
    ) -> None:
        sts = _StubSts(responses=[_ok_response()])
        verifier = AwsStsVerifier(sts_client=sts, audit_logger=cloud_audit_logger)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        await verifier.verify(challenge)
        events = list(cloud_audit_sink.iter_events(tenant_id=challenge.tenant_id))
        assert len(events) == 1
        event = events[0]
        payload = dict(event.payload)
        assert payload["cloud_provider"] == "aws"
        assert payload["principal_kind"] == "role_arn"
        assert payload["principal_hash"] == hash_identifier(challenge.target)
        for forbidden in ("Account", "Credentials", "principal_arn", "external_id"):
            assert forbidden not in payload
        rendered = " ".join(str(v) for v in payload.values())
        assert aws_challenge_token not in rendered
        assert "argus-ownership" not in rendered

    @pytest.mark.asyncio
    async def test_audit_emitted_on_failure(
        self,
        aws_challenge_token: str,
        cloud_audit_logger: AuditLogger,
        cloud_audit_sink: InMemoryAuditSink,
    ) -> None:
        sts = _StubSts(responses=[AccessDeniedException("nope")])
        verifier = AwsStsVerifier(sts_client=sts, audit_logger=cloud_audit_logger)
        challenge = make_challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target="arn:aws:iam::123456789012:role/argus-ownership",
            token=aws_challenge_token,
        )
        with pytest.raises(OwnershipVerificationError):
            await verifier.verify(challenge)
        events = list(cloud_audit_sink.iter_events(tenant_id=challenge.tenant_id))
        assert len(events) == 1
        assert events[0].decision_allowed is False
        assert events[0].failure_summary == REASON_AWS_STS_ACCESS_DENIED


# ---------------------------------------------------------------------------
# BotoStsAdapter type guards
# ---------------------------------------------------------------------------


class TestBotoStsAdapter:
    def test_rejects_client_without_assume_role(self) -> None:
        with pytest.raises(TypeError):
            BotoStsAdapter(sts_client=object())

    def test_implements_protocol(self) -> None:
        class _Fake:
            def assume_role(self, **_: Any) -> dict[str, Any]:  # noqa: ANN401
                return {}

        adapter = BotoStsAdapter(sts_client=_Fake())
        assert isinstance(adapter, StsClientProtocol)
