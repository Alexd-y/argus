"""Unit tests for :mod:`src.policy.cloud_iam.azure` (ARG-043)."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest

from src.policy.audit import AuditLogger, InMemoryAuditSink
from src.policy.cloud_iam._common import (
    CLOUD_PROOF_DEFAULT_TTL,
    utcnow,
)
from src.policy.cloud_iam.azure import (
    AccessTokenResult,
    AzureCredentialProtocol,
    AzureManagedIdentityAdapter,
    AzureManagedIdentityVerifier,
    _parse_target,
)
from src.policy.ownership import (
    REASON_AZURE_MI_RESOURCE_NOT_OWNED,
    REASON_AZURE_MI_TENANT_MISMATCH,
    REASON_AZURE_MI_TIMEOUT,
    REASON_AZURE_MI_TOKEN_REFRESH_FAILED,
    OwnershipChallenge,
    OwnershipMethod,
    OwnershipVerificationError,
    hash_identifier,
)


AZ_TENANT = "11111111-2222-3333-4444-555555555555"
AZ_OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AZ_MI_RESOURCE = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourcegroups/argus/providers/microsoft.managedidentity"
    "/userassignedidentities/argus-prod-mi"
)
TARGET = f"{AZ_TENANT}|{AZ_OID}|{AZ_MI_RESOURCE}"


def _ok_claims(
    *,
    tenant: str = AZ_TENANT,
    oid: str = AZ_OID,
    mi: str = AZ_MI_RESOURCE,
    exp_offset: int = 600,
) -> dict[str, Any]:
    now = int(utcnow().timestamp())
    return {
        "tid": tenant,
        "oid": oid,
        "xms_mirid": mi,
        "iss": f"https://sts.windows.net/{tenant}/",
        "aud": "https://management.azure.com/",
        "iat": now - 5,
        "nbf": now - 5,
        "exp": now + exp_offset,
    }


def _ok_token_result(claims: dict[str, Any] | None = None) -> AccessTokenResult:
    return AccessTokenResult(
        token="header.payload.signature",
        expires_on=int(utcnow().timestamp()) + 600,
        claims=claims if claims is not None else _ok_claims(),
    )


class _StubCredential:
    """Minimal :class:`AzureCredentialProtocol` for tests."""

    def __init__(
        self,
        *,
        result: AccessTokenResult | None = None,
        raise_exc: BaseException | None = None,
        delay_s: float | None = None,
    ) -> None:
        self.result = result
        self.raise_exc = raise_exc
        self.delay_s = delay_s
        self.calls: list[Mapping[str, str]] = []

    async def get_token_with_claims(
        self, *, scope: str, client_request_id: str
    ) -> AccessTokenResult:
        self.calls.append({"scope": scope, "client_request_id": client_request_id})
        if self.delay_s is not None:
            await asyncio.sleep(self.delay_s)
        if self.raise_exc is not None:
            raise self.raise_exc
        if self.result is None:
            raise AssertionError("stub result unset")
        return self.result


# ---------------------------------------------------------------------------
# Constructor + adapter sanity
# ---------------------------------------------------------------------------


class TestVerifierConstruction:
    def test_provider_attribute(self) -> None:
        assert AzureManagedIdentityVerifier.cloud_provider == "azure"

    def test_scope_must_be_short(self) -> None:
        cred = _StubCredential(result=_ok_token_result())
        with pytest.raises(ValueError):
            AzureManagedIdentityVerifier(credential=cred, scope="")
        with pytest.raises(ValueError):
            AzureManagedIdentityVerifier(credential=cred, scope="x" * 257)

    def test_runtime_protocol_check_for_adapter(self) -> None:
        adapter = AzureManagedIdentityAdapter()
        assert isinstance(adapter, AzureCredentialProtocol)


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------


class TestTargetParsing:
    def test_happy_path(self) -> None:
        parsed = _parse_target(TARGET)
        assert parsed.tenant_id == AZ_TENANT
        assert parsed.object_id == AZ_OID
        assert parsed.mi_resource_id == AZ_MI_RESOURCE.lower()

    def test_must_have_three_parts(self) -> None:
        with pytest.raises(OwnershipVerificationError) as exc:
            _parse_target(f"{AZ_TENANT}|{AZ_OID}")
        assert exc.value.summary == REASON_AZURE_MI_TENANT_MISMATCH

    def test_tenant_must_be_uuid_length(self) -> None:
        with pytest.raises(OwnershipVerificationError) as exc:
            _parse_target(f"short-tenant|{AZ_OID}|{AZ_MI_RESOURCE}")
        assert exc.value.summary == REASON_AZURE_MI_TENANT_MISMATCH

    def test_oid_must_be_uuid_length(self) -> None:
        with pytest.raises(OwnershipVerificationError) as exc:
            _parse_target(f"{AZ_TENANT}|short-oid|{AZ_MI_RESOURCE}")
        assert exc.value.summary == REASON_AZURE_MI_TENANT_MISMATCH

    def test_mi_resource_must_be_arm_path(self) -> None:
        with pytest.raises(OwnershipVerificationError) as exc:
            _parse_target(f"{AZ_TENANT}|{AZ_OID}|not-an-arm-path")
        assert exc.value.summary == REASON_AZURE_MI_RESOURCE_NOT_OWNED

    def test_mi_resource_too_long_rejected(self) -> None:
        long_id = "/subscriptions/" + ("x" * 1100)
        with pytest.raises(OwnershipVerificationError) as exc:
            _parse_target(f"{AZ_TENANT}|{AZ_OID}|{long_id}")
        assert exc.value.summary == REASON_AZURE_MI_RESOURCE_NOT_OWNED


# ---------------------------------------------------------------------------
# Verify happy path + method enforcement
# ---------------------------------------------------------------------------


class TestAzureVerifierHappyPath:
    @pytest.mark.asyncio
    async def test_happy_path(
        self,
        cloud_audit_logger: AuditLogger,
        cloud_audit_sink: InMemoryAuditSink,
        azure_challenge_token: str,
    ) -> None:
        cred = _StubCredential(result=_ok_token_result())
        verifier = AzureManagedIdentityVerifier(
            credential=cred, audit_logger=cloud_audit_logger
        )
        challenge = _challenge(token=azure_challenge_token)

        proof = await verifier.verify(challenge)

        assert proof.method is OwnershipMethod.AZURE_MANAGED_IDENTITY
        assert proof.target == TARGET
        assert proof.valid_until <= challenge.expires_at
        assert proof.valid_until - proof.verified_at <= CLOUD_PROOF_DEFAULT_TTL

        # client_request_id must propagate verbatim — Azure echoes it for
        # audit-side correlation; the verifier never reads back the value
        assert cred.calls == [
            {
                "scope": "https://management.azure.com/.default",
                "client_request_id": azure_challenge_token,
            }
        ]

        events = list(cloud_audit_sink.iter_events(tenant_id=challenge.tenant_id))
        assert len(events) == 1
        assert events[0].decision_allowed is True
        assert events[0].failure_summary is None

    @pytest.mark.asyncio
    async def test_method_mismatch(
        self, cloud_audit_logger: AuditLogger, azure_challenge_token: str
    ) -> None:
        cred = _StubCredential(result=_ok_token_result())
        verifier = AzureManagedIdentityVerifier(
            credential=cred, audit_logger=cloud_audit_logger
        )
        challenge = _challenge(
            token=azure_challenge_token,
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
        )

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_AZURE_MI_TENANT_MISMATCH
        assert cred.calls == []

    @pytest.mark.asyncio
    async def test_custom_scope_propagates(
        self, azure_challenge_token: str
    ) -> None:
        cred = _StubCredential(result=_ok_token_result())
        custom_scope = "https://graph.microsoft.com/.default"
        verifier = AzureManagedIdentityVerifier(credential=cred, scope=custom_scope)

        await verifier.verify(_challenge(token=azure_challenge_token))
        assert cred.calls[0]["scope"] == custom_scope


# ---------------------------------------------------------------------------
# Claim validation
# ---------------------------------------------------------------------------


class TestAzureClaimValidation:
    @pytest.mark.asyncio
    async def test_tenant_mismatch(self, azure_challenge_token: str) -> None:
        bad = _ok_token_result(_ok_claims(tenant="99999999-9999-9999-9999-999999999999"))
        cred = _StubCredential(result=bad)
        verifier = AzureManagedIdentityVerifier(credential=cred)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=azure_challenge_token))
        assert exc.value.summary == REASON_AZURE_MI_TENANT_MISMATCH

    @pytest.mark.asyncio
    async def test_oid_mismatch(self, azure_challenge_token: str) -> None:
        bad = _ok_token_result(_ok_claims(oid="ffffffff-ffff-ffff-ffff-ffffffffffff"))
        cred = _StubCredential(result=bad)
        verifier = AzureManagedIdentityVerifier(credential=cred)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=azure_challenge_token))
        assert exc.value.summary == REASON_AZURE_MI_RESOURCE_NOT_OWNED

    @pytest.mark.asyncio
    async def test_mi_resource_mismatch(self, azure_challenge_token: str) -> None:
        bad_claims = _ok_claims(
            mi="/subscriptions/different/resourcegroups/x/providers/y/userassignedidentities/z"
        )
        cred = _StubCredential(result=_ok_token_result(bad_claims))
        verifier = AzureManagedIdentityVerifier(credential=cred)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=azure_challenge_token))
        assert exc.value.summary == REASON_AZURE_MI_RESOURCE_NOT_OWNED

    @pytest.mark.asyncio
    async def test_missing_mi_claim(self, azure_challenge_token: str) -> None:
        claims = _ok_claims()
        del claims["xms_mirid"]
        cred = _StubCredential(result=_ok_token_result(claims))
        verifier = AzureManagedIdentityVerifier(credential=cred)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=azure_challenge_token))
        assert exc.value.summary == REASON_AZURE_MI_RESOURCE_NOT_OWNED

    @pytest.mark.asyncio
    async def test_alternate_mi_claim_name_mi_res_id(
        self, azure_challenge_token: str
    ) -> None:
        claims = _ok_claims()
        del claims["xms_mirid"]
        claims["mi_res_id"] = AZ_MI_RESOURCE
        cred = _StubCredential(result=_ok_token_result(claims))
        verifier = AzureManagedIdentityVerifier(credential=cred)

        proof = await verifier.verify(_challenge(token=azure_challenge_token))
        assert proof.method is OwnershipMethod.AZURE_MANAGED_IDENTITY

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self, azure_challenge_token: str) -> None:
        cred = _StubCredential(
            result=_ok_token_result(_ok_claims(exp_offset=-600))
        )
        verifier = AzureManagedIdentityVerifier(credential=cred)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=azure_challenge_token))
        assert exc.value.summary == REASON_AZURE_MI_TOKEN_REFRESH_FAILED


# ---------------------------------------------------------------------------
# SDK error mapping + timeouts
# ---------------------------------------------------------------------------


class TestAzureSdkErrors:
    @pytest.mark.asyncio
    async def test_arbitrary_exception_maps_to_token_refresh_failure(
        self, azure_challenge_token: str
    ) -> None:
        cred = _StubCredential(raise_exc=RuntimeError("imds unreachable"))
        verifier = AzureManagedIdentityVerifier(credential=cred)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=azure_challenge_token))
        assert exc.value.summary == REASON_AZURE_MI_TOKEN_REFRESH_FAILED

    @pytest.mark.asyncio
    async def test_propagates_explicit_verification_error(
        self, azure_challenge_token: str
    ) -> None:
        explicit = OwnershipVerificationError(REASON_AZURE_MI_TENANT_MISMATCH)
        cred = _StubCredential(raise_exc=explicit)
        verifier = AzureManagedIdentityVerifier(credential=cred)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=azure_challenge_token))
        assert exc.value.summary == REASON_AZURE_MI_TENANT_MISMATCH


class TestAzureTimeout:
    @pytest.mark.asyncio
    async def test_timeout(
        self, monkeypatch: pytest.MonkeyPatch, azure_challenge_token: str
    ) -> None:
        from src.policy.cloud_iam import _common as common_module

        monkeypatch.setattr(common_module, "CLOUD_SDK_TIMEOUT_S", 0.05)
        cred = _StubCredential(result=_ok_token_result(), delay_s=1.0)
        verifier = AzureManagedIdentityVerifier(credential=cred)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=azure_challenge_token))
        assert exc.value.summary == REASON_AZURE_MI_TIMEOUT


# ---------------------------------------------------------------------------
# Audit-log discipline
# ---------------------------------------------------------------------------


class TestAzureAuditDiscipline:
    @pytest.mark.asyncio
    async def test_audit_payload_only_carries_hashes(
        self,
        cloud_audit_sink: InMemoryAuditSink,
        cloud_audit_logger: AuditLogger,
        azure_challenge_token: str,
    ) -> None:
        cred = _StubCredential(result=_ok_token_result())
        verifier = AzureManagedIdentityVerifier(
            credential=cred, audit_logger=cloud_audit_logger
        )
        challenge = _challenge(token=azure_challenge_token)

        await verifier.verify(challenge)

        events = list(cloud_audit_sink.iter_events(tenant_id=challenge.tenant_id))
        assert len(events) == 1
        ev = events[0]
        payload: dict[str, Any] = dict(ev.payload)

        flat = repr(payload)
        assert azure_challenge_token not in flat
        assert "header.payload.signature" not in flat  # raw token must not leak
        assert AZ_TENANT not in flat
        assert AZ_OID not in flat
        assert AZ_MI_RESOURCE.lower() not in flat
        assert hash_identifier(TARGET) in flat


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _challenge(
    *,
    token: str,
    target: str = TARGET,
    method: OwnershipMethod = OwnershipMethod.AZURE_MANAGED_IDENTITY,
) -> OwnershipChallenge:
    issued_at = utcnow()
    return OwnershipChallenge(
        tenant_id=UUID("00000000-0000-4000-8000-000000000002"),
        target=target,
        method=method,
        token=token,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=1),
    )
