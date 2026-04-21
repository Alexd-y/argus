"""End-to-end integration tests for cloud-IAM ownership dispatch (ARG-043).

These tests exercise the full :class:`OwnershipVerifier` pipeline:

* dispatch from :meth:`verify` → cloud-family branch,
* protocol-level call to the registered cloud verifier,
* ``CLOUD_IAM_TTL_S`` cache short-circuit on subsequent calls,
* persistence into :class:`InMemoryOwnershipProofStore`,
* audit-log discipline (closed taxonomy + ``cache_hit`` flag).

Stub :class:`CloudOwnershipVerifierProtocol` implementations stand in
for the real AWS / GCP / Azure SDK adapters so the integration runs
without any network access.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest

from src.policy.audit import AuditEventType, AuditLogger, InMemoryAuditSink
from src.policy.cloud_iam._common import make_proof, utcnow
from src.policy.ownership import (
    CLOUD_IAM_TTL_S,
    REASON_AWS_STS_INVALID_ARN,
    REASON_GCP_SA_JWT_INVALID_AUDIENCE,
    InMemoryOwnershipProofStore,
    OwnershipChallenge,
    OwnershipMethod,
    OwnershipProof,
    OwnershipVerificationError,
    OwnershipVerifier,
    hash_identifier,
)


AWS_TARGET = "arn:aws:iam::123456789012:role/argus-prod"
AWS_TOKEN = "AwsExternalIdAwsExternalIdAwsExternalIdAwsa"

GCP_TARGET = (
    "verifier@argus-prod.iam.gserviceaccount.com|https://ownership.argus.io/argus-prod"
)
GCP_TOKEN = "GcpArgusTokenGcpArgusTokenGcpArgusTokenGcpA"

AZ_TENANT = "11111111-2222-3333-4444-555555555555"
AZ_OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AZ_MI = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourcegroups/argus/providers/microsoft.managedidentity"
    "/userassignedidentities/argus-prod-mi"
)
AZ_TARGET = f"{AZ_TENANT}|{AZ_OID}|{AZ_MI}"
AZ_TOKEN = "AzureClientReqIdAzureClientReqIdAzureClient"

TENANT_ID = UUID("00000000-0000-4000-8000-000000000099")


class _StubCloudVerifier:
    """Stand-in :class:`CloudOwnershipVerifierProtocol` that counts calls."""

    def __init__(
        self,
        *,
        method: OwnershipMethod,
        cloud_provider: str,
        principal_kind: str,
        principal_identifier: str,
        raise_exc: BaseException | None = None,
    ) -> None:
        self.method = method
        self.cloud_provider = cloud_provider
        self.principal_kind = principal_kind
        self.principal_identifier = principal_identifier
        self.raise_exc = raise_exc
        self.call_count = 0

    async def verify(self, challenge: OwnershipChallenge) -> OwnershipProof:
        self.call_count += 1
        if self.raise_exc is not None:
            raise self.raise_exc
        if challenge.method is not self.method:  # pragma: no cover — defensive
            raise OwnershipVerificationError("ownership_method_invalid")
        return make_proof(challenge=challenge, notes=f"{self.cloud_provider}_stub")


def _challenge(
    *, method: OwnershipMethod, target: str, token: str, ttl: timedelta = timedelta(hours=1)
) -> OwnershipChallenge:
    issued_at = utcnow()
    return OwnershipChallenge(
        tenant_id=TENANT_ID,
        target=target,
        method=method,
        token=token,
        issued_at=issued_at,
        expires_at=issued_at + ttl,
    )


def _verifier(
    *,
    aws: _StubCloudVerifier | None = None,
    gcp: _StubCloudVerifier | None = None,
    azure: _StubCloudVerifier | None = None,
    cloud_iam_ttl_s: int = CLOUD_IAM_TTL_S,
) -> tuple[OwnershipVerifier, InMemoryOwnershipProofStore, InMemoryAuditSink]:
    sink = InMemoryAuditSink()
    logger = AuditLogger(sink)
    store = InMemoryOwnershipProofStore()
    cloud: dict[OwnershipMethod, Any] = {}
    if aws is not None:
        cloud[OwnershipMethod.AWS_STS_ASSUME_ROLE] = aws
    if gcp is not None:
        cloud[OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT] = gcp
    if azure is not None:
        cloud[OwnershipMethod.AZURE_MANAGED_IDENTITY] = azure
    verifier = OwnershipVerifier(
        store=store,
        audit_logger=logger,
        cloud_verifiers=cloud,
        cloud_iam_ttl_s=cloud_iam_ttl_s,
    )
    return verifier, store, sink


# ---------------------------------------------------------------------------
# Constructor wiring
# ---------------------------------------------------------------------------


class TestVerifierConstructor:
    def test_invalid_cloud_iam_ttl_rejected(self) -> None:
        sink = InMemoryAuditSink()
        store = InMemoryOwnershipProofStore()
        with pytest.raises(ValueError):
            OwnershipVerifier(
                store=store,
                audit_logger=AuditLogger(sink),
                cloud_iam_ttl_s=0,
            )
        with pytest.raises(ValueError):
            OwnershipVerifier(
                store=store,
                audit_logger=AuditLogger(sink),
                cloud_iam_ttl_s=86_401,
            )

    def test_non_cloud_method_in_cloud_verifiers_rejected(self) -> None:
        sink = InMemoryAuditSink()
        store = InMemoryOwnershipProofStore()
        stub = _StubCloudVerifier(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier="arn:aws:iam::1:role/x",
        )
        with pytest.raises(ValueError):
            OwnershipVerifier(
                store=store,
                audit_logger=AuditLogger(sink),
                cloud_verifiers={OwnershipMethod.DNS_TXT: stub},  # wrong family
            )


# ---------------------------------------------------------------------------
# Dispatch to cloud verifiers
# ---------------------------------------------------------------------------


class TestCloudDispatch:
    @pytest.mark.asyncio
    async def test_aws_dispatch_routes_to_registered_verifier(self) -> None:
        aws = _StubCloudVerifier(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier=AWS_TARGET,
        )
        verifier, store, _ = _verifier(aws=aws)
        challenge = _challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target=AWS_TARGET,
            token=AWS_TOKEN,
        )

        proof = await verifier.verify(challenge)

        assert aws.call_count == 1
        assert proof.method is OwnershipMethod.AWS_STS_ASSUME_ROLE
        assert proof.target == AWS_TARGET
        # Proof must be persisted via the durable store
        persisted = store.get(tenant_id=TENANT_ID, target=AWS_TARGET)
        assert persisted is not None
        assert persisted.proof_id == proof.proof_id

    @pytest.mark.asyncio
    async def test_unregistered_cloud_method_rejected(self) -> None:
        verifier, _, sink = _verifier()  # no cloud_verifiers registered
        challenge = _challenge(
            method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
            target=GCP_TARGET,
            token=GCP_TOKEN,
        )

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        # Closed-taxonomy reason; not GCP-specific
        assert exc.value.summary == "ownership_method_invalid"

        events = list(sink.iter_events(tenant_id=TENANT_ID))
        assert len(events) == 1
        assert events[0].decision_allowed is False

    @pytest.mark.asyncio
    async def test_each_cloud_method_dispatched_independently(self) -> None:
        aws = _StubCloudVerifier(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier=AWS_TARGET,
        )
        gcp = _StubCloudVerifier(
            method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
            cloud_provider="gcp",
            principal_kind="service_account",
            principal_identifier=GCP_TARGET,
        )
        azure = _StubCloudVerifier(
            method=OwnershipMethod.AZURE_MANAGED_IDENTITY,
            cloud_provider="azure",
            principal_kind="managed_identity_object_id",
            principal_identifier=AZ_OID,
        )
        verifier, _, _ = _verifier(aws=aws, gcp=gcp, azure=azure)

        await verifier.verify(
            _challenge(
                method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
                target=AWS_TARGET,
                token=AWS_TOKEN,
            )
        )
        await verifier.verify(
            _challenge(
                method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
                target=GCP_TARGET,
                token=GCP_TOKEN,
            )
        )
        await verifier.verify(
            _challenge(
                method=OwnershipMethod.AZURE_MANAGED_IDENTITY,
                target=AZ_TARGET,
                token=AZ_TOKEN,
            )
        )
        assert (aws.call_count, gcp.call_count, azure.call_count) == (1, 1, 1)


# ---------------------------------------------------------------------------
# Cache short-circuit
# ---------------------------------------------------------------------------


class TestCloudCache:
    @pytest.mark.asyncio
    async def test_repeated_call_is_served_from_cache(self) -> None:
        gcp = _StubCloudVerifier(
            method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
            cloud_provider="gcp",
            principal_kind="service_account",
            principal_identifier=GCP_TARGET,
        )
        verifier, _, sink = _verifier(gcp=gcp)
        challenge = _challenge(
            method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
            target=GCP_TARGET,
            token=GCP_TOKEN,
        )

        first = await verifier.verify(challenge)

        challenge2 = _challenge(
            method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
            target=GCP_TARGET,
            token=GCP_TOKEN,
        )
        second = await verifier.verify(challenge2)

        assert gcp.call_count == 1  # second call was cached
        assert first.proof_id == second.proof_id

        events = list(sink.iter_events(tenant_id=TENANT_ID))
        assert len(events) == 2
        assert events[0].payload.get("cache_hit") is False
        assert events[1].payload.get("cache_hit") is True

    @pytest.mark.asyncio
    async def test_cache_miss_after_ttl_expires(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        aws = _StubCloudVerifier(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier=AWS_TARGET,
        )
        verifier, _, _ = _verifier(aws=aws, cloud_iam_ttl_s=1)
        challenge = _challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target=AWS_TARGET,
            token=AWS_TOKEN,
        )

        await verifier.verify(challenge)

        # Move clock forward beyond TTL via a custom utcnow patch on the
        # ownership module. We patch the *module-level* helper used by
        # the cache eviction logic.
        from src.policy import ownership as ownership_module

        future = utcnow() + timedelta(seconds=5)
        monkeypatch.setattr(ownership_module, "_utcnow", lambda: future)

        await verifier.verify(challenge)
        assert aws.call_count == 2  # cache miss → re-verify

    @pytest.mark.asyncio
    async def test_cache_keyed_per_tenant(self) -> None:
        aws = _StubCloudVerifier(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier=AWS_TARGET,
        )
        verifier, _, _ = _verifier(aws=aws)
        other_tenant = UUID("00000000-0000-4000-8000-000000000098")

        await verifier.verify(
            _challenge(
                method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
                target=AWS_TARGET,
                token=AWS_TOKEN,
            )
        )
        # Different tenant → cache key differs → SDK called again.
        issued_at = utcnow()
        c2 = OwnershipChallenge(
            tenant_id=other_tenant,
            target=AWS_TARGET,
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            token=AWS_TOKEN,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(hours=1),
        )
        await verifier.verify(c2)

        assert aws.call_count == 2

    @pytest.mark.asyncio
    async def test_cache_keyed_per_method(self) -> None:
        aws = _StubCloudVerifier(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier=AWS_TARGET,
        )
        gcp = _StubCloudVerifier(
            method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
            cloud_provider="gcp",
            principal_kind="service_account",
            principal_identifier="x",
        )
        verifier, _, _ = _verifier(aws=aws, gcp=gcp)
        # Same target but different method → distinct cache entries.
        await verifier.verify(
            _challenge(
                method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
                target=AWS_TARGET,
                token=AWS_TOKEN,
            )
        )
        await verifier.verify(
            _challenge(
                method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
                target=AWS_TARGET,  # weird-but-legal collision
                token=GCP_TOKEN,
            )
        )
        assert aws.call_count == 1
        assert gcp.call_count == 1

    @pytest.mark.asyncio
    async def test_failures_are_not_cached(self) -> None:
        aws = _StubCloudVerifier(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier=AWS_TARGET,
            raise_exc=OwnershipVerificationError(REASON_AWS_STS_INVALID_ARN),
        )
        verifier, _, _ = _verifier(aws=aws)

        for _ in range(3):
            with pytest.raises(OwnershipVerificationError):
                await verifier.verify(
                    _challenge(
                        method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
                        target=AWS_TARGET,
                        token=AWS_TOKEN,
                    )
                )
        assert aws.call_count == 3  # never cached

    @pytest.mark.asyncio
    async def test_cloud_cache_clear_evicts_everything(self) -> None:
        aws = _StubCloudVerifier(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier=AWS_TARGET,
        )
        verifier, _, _ = _verifier(aws=aws)
        challenge = _challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target=AWS_TARGET,
            token=AWS_TOKEN,
        )
        await verifier.verify(challenge)
        assert aws.call_count == 1

        verifier.cloud_cache_clear()

        await verifier.verify(challenge)
        assert aws.call_count == 2


# ---------------------------------------------------------------------------
# Audit-log cache_hit flag + closed-taxonomy summary
# ---------------------------------------------------------------------------


class TestCloudAuditDiscipline:
    @pytest.mark.asyncio
    async def test_failure_summary_propagates_unchanged(self) -> None:
        gcp = _StubCloudVerifier(
            method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
            cloud_provider="gcp",
            principal_kind="service_account",
            principal_identifier=GCP_TARGET,
            raise_exc=OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE),
        )
        verifier, _, sink = _verifier(gcp=gcp)
        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(
                _challenge(
                    method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
                    target=GCP_TARGET,
                    token=GCP_TOKEN,
                )
            )
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE

        events = list(sink.iter_events(tenant_id=TENANT_ID))
        assert len(events) == 1
        assert events[0].failure_summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE
        assert events[0].payload.get("cache_hit") is False

    @pytest.mark.asyncio
    async def test_audit_payload_hashes_target(self) -> None:
        azure = _StubCloudVerifier(
            method=OwnershipMethod.AZURE_MANAGED_IDENTITY,
            cloud_provider="azure",
            principal_kind="managed_identity_object_id",
            principal_identifier=AZ_OID,
        )
        verifier, _, sink = _verifier(azure=azure)
        challenge = _challenge(
            method=OwnershipMethod.AZURE_MANAGED_IDENTITY,
            target=AZ_TARGET,
            token=AZ_TOKEN,
        )
        await verifier.verify(challenge)

        events = list(sink.iter_events(tenant_id=TENANT_ID))
        assert len(events) == 1
        flat = repr(dict(events[0].payload))
        assert AZ_TARGET not in flat
        assert hash_identifier(AZ_TARGET) in flat
        assert AZ_TOKEN not in flat

    @pytest.mark.asyncio
    async def test_event_type_is_ownership_verify(self) -> None:
        aws = _StubCloudVerifier(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier=AWS_TARGET,
        )
        verifier, _, sink = _verifier(aws=aws)
        await verifier.verify(
            _challenge(
                method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
                target=AWS_TARGET,
                token=AWS_TOKEN,
            )
        )
        events = list(sink.iter_events(tenant_id=TENANT_ID))
        assert all(ev.event_type is AuditEventType.OWNERSHIP_VERIFY for ev in events)


# ---------------------------------------------------------------------------
# Concurrency: cache must be thread-safe across asyncio gather
# ---------------------------------------------------------------------------


class TestCloudConcurrency:
    @pytest.mark.asyncio
    async def test_parallel_calls_share_cache(self) -> None:
        aws = _StubCloudVerifier(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier=AWS_TARGET,
        )
        verifier, _, _ = _verifier(aws=aws)
        challenge = _challenge(
            method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
            target=AWS_TARGET,
            token=AWS_TOKEN,
        )
        await verifier.verify(challenge)
        # Even ten parallel cached lookups must not invoke the SDK.
        results = await asyncio.gather(
            *(verifier.verify(challenge) for _ in range(10))
        )
        assert all(r.proof_id == results[0].proof_id for r in results)
        assert aws.call_count == 1
