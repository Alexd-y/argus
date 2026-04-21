"""Unit tests for :mod:`src.policy.cloud_iam.gcp` (ARG-043)."""

from __future__ import annotations

import asyncio
import re
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
from src.policy.cloud_iam.gcp import (
    GcpIamProtocol,
    GcpServiceAccountJwtVerifier,
    GoogleAuthIamAdapter,
    JwtClaims,
    _parse_target,
)
from src.policy.ownership import (
    REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID,
    REASON_GCP_SA_JWT_INVALID_AUDIENCE,
    REASON_GCP_SA_JWT_TIMEOUT,
    OwnershipChallenge,
    OwnershipMethod,
    OwnershipVerificationError,
    hash_identifier,
)


SA_EMAIL = "verifier@argus-prod.iam.gserviceaccount.com"
AUDIENCE = "https://ownership.argus.io/argus-prod"
TARGET = f"{SA_EMAIL}|{AUDIENCE}"


def _ok_claims(*, token: str, sa: str = SA_EMAIL, aud: str = AUDIENCE) -> JwtClaims:
    now = int(utcnow().timestamp())
    return {
        "iss": sa,
        "sub": sa,
        "aud": aud,
        "iat": now - 5,
        "exp": now + 600,
        "nbf": now - 5,
        "argus_token": token,
    }


class _StubIam:
    """Minimal :class:`GcpIamProtocol` implementation for tests."""

    def __init__(
        self,
        *,
        claims: JwtClaims | None = None,
        raise_exc: BaseException | None = None,
        delay_s: float | None = None,
    ) -> None:
        self.claims = claims
        self.raise_exc = raise_exc
        self.delay_s = delay_s
        self.calls: list[Mapping[str, str]] = []

    async def verify_service_account_jwt(
        self,
        *,
        service_account_email: str,
        expected_audience: str,
        expected_argus_token: str,
    ) -> JwtClaims:
        self.calls.append(
            {
                "service_account_email": service_account_email,
                "expected_audience": expected_audience,
                "expected_argus_token": expected_argus_token,
            }
        )
        if self.delay_s is not None:
            await asyncio.sleep(self.delay_s)
        if self.raise_exc is not None:
            raise self.raise_exc
        if self.claims is None:
            raise AssertionError("stub claims unset")
        return self.claims


# ---------------------------------------------------------------------------
# Constructor + provider metadata
# ---------------------------------------------------------------------------


class TestVerifierConstruction:
    def test_provider_attribute(self) -> None:
        assert GcpServiceAccountJwtVerifier.cloud_provider == "gcp"

    def test_leeway_must_be_in_range(self) -> None:
        iam = _StubIam(claims={})
        with pytest.raises(ValueError):
            GcpServiceAccountJwtVerifier(iam_client=iam, leeway_s=-1)
        with pytest.raises(ValueError):
            GcpServiceAccountJwtVerifier(iam_client=iam, leeway_s=301)
        GcpServiceAccountJwtVerifier(iam_client=iam, leeway_s=0)
        GcpServiceAccountJwtVerifier(iam_client=iam, leeway_s=300)

    def test_runtime_protocol_check_for_adapter(self) -> None:
        adapter = GoogleAuthIamAdapter()
        assert isinstance(adapter, GcpIamProtocol)


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------


class TestTargetParsing:
    def test_happy_path(self) -> None:
        parsed = _parse_target(TARGET)
        assert parsed.service_account_email == SA_EMAIL
        assert parsed.audience == AUDIENCE

    def test_missing_separator(self) -> None:
        with pytest.raises(OwnershipVerificationError) as exc:
            _parse_target("no-pipe-here")
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE

    def test_audience_must_have_prefix(self) -> None:
        with pytest.raises(OwnershipVerificationError) as exc:
            _parse_target(f"{SA_EMAIL}|https://attacker.example.com/path")
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE

    def test_sa_must_be_gserviceaccount(self) -> None:
        with pytest.raises(OwnershipVerificationError) as exc:
            _parse_target(f"alice@example.com|{AUDIENCE}")
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE

    def test_sa_must_have_at_sign(self) -> None:
        with pytest.raises(OwnershipVerificationError) as exc:
            _parse_target(f"verifier-argus-prod.iam.gserviceaccount.com|{AUDIENCE}")
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE

    def test_audience_too_long_rejected(self) -> None:
        long_aud = "https://ownership.argus.io/" + ("x" * 1100)
        with pytest.raises(OwnershipVerificationError) as exc:
            _parse_target(f"{SA_EMAIL}|{long_aud}")
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE


# ---------------------------------------------------------------------------
# Verifier happy path + method enforcement
# ---------------------------------------------------------------------------


class TestGcpVerifierHappyPath:
    @pytest.mark.asyncio
    async def test_happy_path(
        self,
        cloud_audit_logger: AuditLogger,
        cloud_audit_sink: InMemoryAuditSink,
        gcp_challenge_token: str,
    ) -> None:
        iam = _StubIam(claims=_ok_claims(token=gcp_challenge_token))
        verifier = GcpServiceAccountJwtVerifier(
            iam_client=iam, audit_logger=cloud_audit_logger
        )
        challenge = _challenge(token=gcp_challenge_token)

        proof = await verifier.verify(challenge)

        assert proof.method is OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT
        assert proof.target == TARGET
        # ``valid_until`` is capped against ``challenge.expires_at``
        assert proof.valid_until <= challenge.expires_at
        assert proof.valid_until - proof.verified_at <= CLOUD_PROOF_DEFAULT_TTL

        assert iam.calls == [
            {
                "service_account_email": SA_EMAIL,
                "expected_audience": AUDIENCE,
                "expected_argus_token": gcp_challenge_token,
            }
        ]

        events = list(cloud_audit_sink.iter_events(tenant_id=challenge.tenant_id))
        assert len(events) == 1
        assert events[0].decision_allowed is True
        assert events[0].failure_summary is None

    @pytest.mark.asyncio
    async def test_method_mismatch(
        self, cloud_audit_logger: AuditLogger, gcp_challenge_token: str
    ) -> None:
        iam = _StubIam(claims=_ok_claims(token=gcp_challenge_token))
        verifier = GcpServiceAccountJwtVerifier(
            iam_client=iam, audit_logger=cloud_audit_logger
        )
        challenge = _challenge(
            token=gcp_challenge_token, method=OwnershipMethod.AWS_STS_ASSUME_ROLE
        )

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE
        assert iam.calls == []  # no SDK side-effect when method mismatches


# ---------------------------------------------------------------------------
# Claim validation
# ---------------------------------------------------------------------------


class TestClaimValidation:
    @pytest.mark.asyncio
    async def test_audience_mismatch(self, gcp_challenge_token: str) -> None:
        bogus = _ok_claims(token=gcp_challenge_token, aud="https://ownership.argus.io/other")
        iam = _StubIam(claims=bogus)
        verifier = GcpServiceAccountJwtVerifier(iam_client=iam)
        challenge = _challenge(token=gcp_challenge_token)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(challenge)
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE

    @pytest.mark.asyncio
    async def test_subject_mismatch(self, gcp_challenge_token: str) -> None:
        bogus = _ok_claims(
            token=gcp_challenge_token,
            sa="other@argus-prod.iam.gserviceaccount.com",
        )
        bogus["iss"] = SA_EMAIL  # leave iss correct, force sub-only mismatch
        iam = _StubIam(claims=bogus)
        verifier = GcpServiceAccountJwtVerifier(iam_client=iam)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=gcp_challenge_token))
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE

    @pytest.mark.asyncio
    async def test_argus_token_mismatch(self, gcp_challenge_token: str) -> None:
        wrong = "x" * 43
        bogus = _ok_claims(token=wrong)
        iam = _StubIam(claims=bogus)
        verifier = GcpServiceAccountJwtVerifier(iam_client=iam)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=gcp_challenge_token))
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE

    @pytest.mark.asyncio
    async def test_expired_token(self, gcp_challenge_token: str) -> None:
        claims = _ok_claims(token=gcp_challenge_token)
        now = int(utcnow().timestamp())
        claims["exp"] = now - 600
        claims["iat"] = now - 1200
        iam = _StubIam(claims=claims)
        verifier = GcpServiceAccountJwtVerifier(iam_client=iam)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=gcp_challenge_token))
        assert exc.value.summary == REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID

    @pytest.mark.asyncio
    async def test_iat_in_future(self, gcp_challenge_token: str) -> None:
        claims = _ok_claims(token=gcp_challenge_token)
        now = int(utcnow().timestamp())
        claims["iat"] = now + 600
        iam = _StubIam(claims=claims)
        verifier = GcpServiceAccountJwtVerifier(iam_client=iam)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=gcp_challenge_token))
        assert exc.value.summary == REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID

    @pytest.mark.asyncio
    async def test_nbf_in_future(self, gcp_challenge_token: str) -> None:
        claims = _ok_claims(token=gcp_challenge_token)
        now = int(utcnow().timestamp())
        claims["nbf"] = now + 600
        iam = _StubIam(claims=claims)
        verifier = GcpServiceAccountJwtVerifier(iam_client=iam)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=gcp_challenge_token))
        assert exc.value.summary == REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID

    @pytest.mark.asyncio
    async def test_missing_exp(self, gcp_challenge_token: str) -> None:
        claims = _ok_claims(token=gcp_challenge_token)
        claims.pop("exp")
        iam = _StubIam(claims=claims)
        verifier = GcpServiceAccountJwtVerifier(iam_client=iam)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=gcp_challenge_token))
        assert exc.value.summary == REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID


# ---------------------------------------------------------------------------
# SDK error mapping + timeouts
# ---------------------------------------------------------------------------


class TestSdkErrors:
    @pytest.mark.asyncio
    async def test_arbitrary_exception_maps_to_expired(
        self, gcp_challenge_token: str
    ) -> None:
        iam = _StubIam(raise_exc=RuntimeError("boom"))
        verifier = GcpServiceAccountJwtVerifier(iam_client=iam)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=gcp_challenge_token))
        assert exc.value.summary == REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID

    @pytest.mark.asyncio
    async def test_propagates_explicit_verification_error(
        self, gcp_challenge_token: str
    ) -> None:
        explicit = OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)
        iam = _StubIam(raise_exc=explicit)
        verifier = GcpServiceAccountJwtVerifier(iam_client=iam)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=gcp_challenge_token))
        assert exc.value.summary == REASON_GCP_SA_JWT_INVALID_AUDIENCE


class TestTimeout:
    @pytest.mark.asyncio
    async def test_timeout(
        self, monkeypatch: pytest.MonkeyPatch, gcp_challenge_token: str
    ) -> None:
        from src.policy.cloud_iam import _common as common_module

        monkeypatch.setattr(common_module, "CLOUD_SDK_TIMEOUT_S", 0.05)
        iam = _StubIam(claims=_ok_claims(token=gcp_challenge_token), delay_s=1.0)
        verifier = GcpServiceAccountJwtVerifier(iam_client=iam)

        with pytest.raises(OwnershipVerificationError) as exc:
            await verifier.verify(_challenge(token=gcp_challenge_token))
        assert exc.value.summary == REASON_GCP_SA_JWT_TIMEOUT


# ---------------------------------------------------------------------------
# Audit-log discipline
# ---------------------------------------------------------------------------


class TestAuditDiscipline:
    @pytest.mark.asyncio
    async def test_audit_payload_no_jwt_or_claims(
        self,
        cloud_audit_sink: InMemoryAuditSink,
        cloud_audit_logger: AuditLogger,
        gcp_challenge_token: str,
    ) -> None:
        iam = _StubIam(claims=_ok_claims(token=gcp_challenge_token))
        verifier = GcpServiceAccountJwtVerifier(
            iam_client=iam, audit_logger=cloud_audit_logger
        )
        challenge = _challenge(token=gcp_challenge_token)

        await verifier.verify(challenge)

        events = list(cloud_audit_sink.iter_events(tenant_id=challenge.tenant_id))
        assert len(events) == 1
        ev = events[0]
        payload: dict[str, Any] = dict(ev.payload)

        for key in ("argus_token", "exp", "iat", "nbf", "claims"):
            assert key not in payload
        flat = repr(payload)
        assert gcp_challenge_token not in flat
        assert "BEGIN PRIVATE KEY" not in flat
        assert "Bearer " not in flat
        assert SA_EMAIL not in flat  # principal must be hashed
        assert AUDIENCE not in flat
        target_hash = hash_identifier(TARGET)
        assert target_hash in flat
        assert (
            re.search(
                r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b", flat
            )
            is None
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _challenge(
    *,
    token: str,
    target: str = TARGET,
    method: OwnershipMethod = OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
) -> OwnershipChallenge:
    issued_at = utcnow()
    return OwnershipChallenge(
        tenant_id=UUID("00000000-0000-4000-8000-000000000001"),
        target=target,
        method=method,
        token=token,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=1),
    )
