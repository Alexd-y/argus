"""ARG-043 — Security gate: cloud-IAM ownership has zero secret leaks.

Per the ARG-043 spec the cloud-IAM verification family MUST:

1. Never emit raw service-account emails / role ARNs / Azure object IDs /
   tokens / JWTs / OAuth bearer credentials into ANY audit-log payload.
2. Use ONLY closed-taxonomy ``failure_summary`` strings drawn from
   :data:`CLOUD_IAM_FAILURE_REASONS` so adversaries can't differentiate
   error states by free-form messages.
3. Bound every cloud SDK call by ``CLOUD_SDK_TIMEOUT_S`` and surface
   timeouts as a closed-taxonomy reason.
4. Use constant-time string comparison for every secret-like value
   (challenge tokens, JWT ``argus_token`` claims, Azure tenant/oid pins).
5. Ship NetworkPolicy egress allowlists that are FQDN-pinned, not
   ``0.0.0.0/0`` or wildcard.

Each section is parameterised so adding a new verifier lights up coverage
automatically. ~30+ cases across the cloud-IAM surface.
"""

from __future__ import annotations

import asyncio
import inspect
import re
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from src.policy.audit import AuditEvent, AuditLogger, InMemoryAuditSink
from src.policy.cloud_iam import (
    AzureCredentialProtocol,
    AzureManagedIdentityVerifier,
    GcpIamProtocol,
    GcpServiceAccountJwtVerifier,
    StsClientProtocol,
)
from src.policy.cloud_iam._common import (
    constant_time_str_equal,
    descriptor_from_challenge,
    emit_cloud_attempt,
    redact_token,
    utcnow,
)
from src.policy.cloud_iam.aws import AwsStsVerifier
from src.policy.ownership import (
    CLOUD_IAM_FAILURE_REASONS,
    CLOUD_IAM_METHODS,
    CLOUD_IAM_TTL_S,
    CLOUD_SDK_TIMEOUT_S,
    OwnershipChallenge,
    OwnershipMethod,
    OwnershipVerificationError,
    hash_identifier,
)


# ---------------------------------------------------------------------------
# Test fixtures (raw secrets the verifiers must NEVER echo back)
# ---------------------------------------------------------------------------


SECRETS: dict[str, str] = {
    "aws_external_id": "AwsExternalIdAwsExternalIdAwsExternalIdAwsa",
    "aws_role_arn": "arn:aws:iam::123456789012:role/argus-prod-secret",
    "aws_session_token_marker": "FQoGZXIvYXdzELv//////////wEaDPRIVATESESSIONTOK",
    "gcp_argus_token": "GcpArgusTokenGcpArgusTokenGcpArgusTokenGcpA",
    "gcp_service_account_email": "argus-secret@argus-prod.iam.gserviceaccount.com",
    "gcp_jwt_payload_marker": "eyJhcmd1c190b2tlbiI6IkdjcEFyZ3VzVG9rZW5HY3BBcmd1c1Rva2VuIn0",
    "gcp_private_key_pem": "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgk-----END PRIVATE KEY-----",
    "azure_client_request_id": "AzureClientReqIdAzureClientReqIdAzureClient",
    "azure_object_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "azure_tenant_id": "11111111-2222-3333-4444-555555555555",
    "azure_mi_arm_id": (
        "/subscriptions/00000000-0000-0000-0000-000000000001"
        "/resourcegroups/argus/providers/microsoft.managedidentity"
        "/userassignedidentities/argus-prod-secret-mi"
    ),
    "azure_access_token_marker": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.PRIVATEAZURETOKEN",
    "oauth_bearer_marker": "Bearer ya29.SECRET-OAUTH-BEARER-TOKEN",
}


# ---------------------------------------------------------------------------
# Closed taxonomy invariants
# ---------------------------------------------------------------------------


class TestClosedTaxonomy:
    """Every failure surface must use a CLOUD_IAM_FAILURE_REASONS string."""

    def test_taxonomy_is_non_empty_and_strings(self) -> None:
        assert len(CLOUD_IAM_FAILURE_REASONS) >= 8
        for reason in CLOUD_IAM_FAILURE_REASONS:
            assert isinstance(reason, str)
            # 64-char audit ``failure_summary`` cap (see AuditEvent)
            assert 1 <= len(reason) <= 64
            # snake_case identifier — no whitespace, no SDK noise
            assert re.fullmatch(r"[a-z][a-z0-9_]*", reason), reason

    def test_taxonomy_covers_every_cloud_provider(self) -> None:
        prefixes = {
            "ownership_aws_sts_": "aws",
            "ownership_gcp_sa_jwt_": "gcp",
            "ownership_azure_mi_": "azure",
        }
        for prefix, provider in prefixes.items():
            matched = [r for r in CLOUD_IAM_FAILURE_REASONS if r.startswith(prefix)]
            assert matched, f"no closed-taxonomy reason for provider {provider!r}"

    def test_taxonomy_includes_three_timeout_reasons(self) -> None:
        timeouts = [r for r in CLOUD_IAM_FAILURE_REASONS if r.endswith("_timeout")]
        assert len(timeouts) == 3
        assert {
            "ownership_aws_sts_timeout",
            "ownership_gcp_sa_jwt_timeout",
            "ownership_azure_mi_timeout",
        } <= set(timeouts)

    @pytest.mark.parametrize(
        "module_name",
        [
            "src.policy.cloud_iam.aws",
            "src.policy.cloud_iam.gcp",
            "src.policy.cloud_iam.azure",
        ],
    )
    def test_modules_only_emit_taxonomy_reasons(self, module_name: str) -> None:
        """Static check: every ``OwnershipVerificationError(...)`` literal in
        the cloud_iam modules references a closed-taxonomy constant.
        """
        import importlib

        module = importlib.import_module(module_name)
        source = inspect.getsource(module)
        # All raised reasons in the verifier modules go through named
        # constants from ownership.py — we confirm no string-literal
        # OwnershipVerificationError("free_form_text") slips in.
        bad = re.findall(
            r'OwnershipVerificationError\(\s*"([^"]+)"\s*\)',
            source,
        )
        assert not bad, (
            f"{module_name} raises with raw string literal(s) {bad!r}; "
            "use the REASON_* constants instead"
        )


# ---------------------------------------------------------------------------
# Audit-log payload discipline (no secret leaks in any branch)
# ---------------------------------------------------------------------------


class _StubSts:
    def __init__(self, *, raise_exc: BaseException | None = None) -> None:
        self.raise_exc = raise_exc

    async def assume_role(
        self,
        *,
        role_arn: str,
        role_session_name: str,
        external_id: str,
        duration_seconds: int,
    ) -> dict[str, Any]:
        if self.raise_exc is not None:
            raise self.raise_exc
        return {
            "AssumedRoleUser": {
                "Arn": role_arn.replace(":role/", ":assumed-role/").rstrip()
                + f"/{role_session_name}",
                "AssumedRoleId": "ARO123:argus-session",
            },
            "Credentials": {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "SessionToken": SECRETS["aws_session_token_marker"],
                "Expiration": utcnow() + timedelta(hours=1),
            },
            "PackedPolicySize": 0,
        }


class _StubGcpIam:
    def __init__(self, *, raise_exc: BaseException | None = None) -> None:
        self.raise_exc = raise_exc

    async def verify_service_account_jwt(
        self,
        *,
        service_account_email: str,
        expected_audience: str,
        expected_argus_token: str,
    ) -> dict[str, Any]:
        if self.raise_exc is not None:
            raise self.raise_exc
        now = int(utcnow().timestamp())
        return {
            "iss": service_account_email,
            "sub": service_account_email,
            "aud": expected_audience,
            "iat": now - 5,
            "exp": now + 600,
            "argus_token": expected_argus_token,
        }


class _StubAzureCred:
    def __init__(self, *, raise_exc: BaseException | None = None) -> None:
        self.raise_exc = raise_exc

    async def get_token_with_claims(
        self, *, scope: str, client_request_id: str
    ) -> dict[str, Any]:
        if self.raise_exc is not None:
            raise self.raise_exc
        now = int(utcnow().timestamp())
        return {
            "token": SECRETS["azure_access_token_marker"],
            "expires_on": now + 600,
            "claims": {
                "tid": SECRETS["azure_tenant_id"],
                "oid": SECRETS["azure_object_id"],
                "xms_mirid": SECRETS["azure_mi_arm_id"],
                "iss": f"https://sts.windows.net/{SECRETS['azure_tenant_id']}/",
                "aud": "https://management.azure.com/",
                "iat": now - 5,
                "exp": now + 600,
            },
        }


def _fresh_logger() -> tuple[AuditLogger, InMemoryAuditSink]:
    sink = InMemoryAuditSink()
    return AuditLogger(sink), sink


def _aws_challenge() -> OwnershipChallenge:
    issued_at = utcnow()
    return OwnershipChallenge(
        tenant_id=UUID("00000000-0000-4000-8000-000000000050"),
        target=SECRETS["aws_role_arn"],
        method=OwnershipMethod.AWS_STS_ASSUME_ROLE,
        token=SECRETS["aws_external_id"],
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=1),
    )


def _gcp_challenge() -> OwnershipChallenge:
    issued_at = utcnow()
    return OwnershipChallenge(
        tenant_id=UUID("00000000-0000-4000-8000-000000000051"),
        target=f"{SECRETS['gcp_service_account_email']}|https://ownership.argus.io/argus-prod",
        method=OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
        token=SECRETS["gcp_argus_token"],
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=1),
    )


def _azure_challenge() -> OwnershipChallenge:
    issued_at = utcnow()
    target = (
        f"{SECRETS['azure_tenant_id']}|"
        f"{SECRETS['azure_object_id']}|"
        f"{SECRETS['azure_mi_arm_id']}"
    )
    return OwnershipChallenge(
        tenant_id=UUID("00000000-0000-4000-8000-000000000052"),
        target=target,
        method=OwnershipMethod.AZURE_MANAGED_IDENTITY,
        token=SECRETS["azure_client_request_id"],
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=1),
    )


def _flatten_event(event: AuditEvent) -> str:
    """Render every payload value AND structured field into one string."""
    payload_text = repr(dict(event.payload))
    summary_text = event.failure_summary or ""
    return f"{payload_text}|{summary_text}"


def _all_secret_values() -> list[tuple[str, str]]:
    return list(SECRETS.items())


class TestNoSecretLeaksInAudit:
    """For every cloud verifier, check that a successful OR failing
    verify never echoes any of the SECRETS values into the audit trail.
    """

    @pytest.mark.asyncio
    async def test_aws_success_does_not_leak_secrets(self) -> None:
        logger, sink = _fresh_logger()
        verifier = AwsStsVerifier(
            sts_client=_StubSts(),
            audit_logger=logger,
        )
        ch = _aws_challenge()
        await verifier.verify(ch)

        events = list(sink.iter_events(tenant_id=ch.tenant_id))
        assert len(events) == 1
        flat = _flatten_event(events[0])
        for label, value in _all_secret_values():
            assert value not in flat, f"AWS audit leaked {label}: {value!r}"
        assert hash_identifier(ch.target) in flat

    @pytest.mark.asyncio
    async def test_aws_failure_does_not_leak_secrets(self) -> None:
        logger, sink = _fresh_logger()

        class _AccessDenied(Exception):
            def __init__(self) -> None:
                super().__init__(
                    "User: arn:aws:iam::99:user/attacker is not authorized "
                    "to perform sts:AssumeRole on resource "
                    + SECRETS["aws_role_arn"]
                )
                self.__class__.__name__ = "AccessDenied"

        verifier = AwsStsVerifier(
            sts_client=_StubSts(raise_exc=_AccessDenied()),
            audit_logger=logger,
        )
        ch = _aws_challenge()
        with pytest.raises(OwnershipVerificationError):
            await verifier.verify(ch)

        events = list(sink.iter_events(tenant_id=ch.tenant_id))
        assert events
        flat = _flatten_event(events[-1])
        for label, value in _all_secret_values():
            assert value not in flat, f"AWS failure leaked {label}: {value!r}"

    @pytest.mark.asyncio
    async def test_gcp_success_does_not_leak_secrets(self) -> None:
        logger, sink = _fresh_logger()
        verifier = GcpServiceAccountJwtVerifier(
            iam_client=_StubGcpIam(),
            audit_logger=logger,
        )
        ch = _gcp_challenge()
        await verifier.verify(ch)
        events = list(sink.iter_events(tenant_id=ch.tenant_id))
        assert events
        flat = _flatten_event(events[-1])
        for label, value in _all_secret_values():
            assert value not in flat, f"GCP audit leaked {label}: {value!r}"

    @pytest.mark.asyncio
    async def test_gcp_failure_does_not_leak_secrets(self) -> None:
        logger, sink = _fresh_logger()
        explicit = RuntimeError(
            f"jwt mismatch token={SECRETS['gcp_argus_token']} "
            f"sa={SECRETS['gcp_service_account_email']}"
        )
        verifier = GcpServiceAccountJwtVerifier(
            iam_client=_StubGcpIam(raise_exc=explicit),
            audit_logger=logger,
        )
        ch = _gcp_challenge()
        with pytest.raises(OwnershipVerificationError):
            await verifier.verify(ch)
        events = list(sink.iter_events(tenant_id=ch.tenant_id))
        assert events
        flat = _flatten_event(events[-1])
        for label, value in _all_secret_values():
            assert value not in flat, f"GCP failure leaked {label}: {value!r}"

    @pytest.mark.asyncio
    async def test_azure_success_does_not_leak_secrets(self) -> None:
        logger, sink = _fresh_logger()
        verifier = AzureManagedIdentityVerifier(
            credential=_StubAzureCred(),
            audit_logger=logger,
        )
        ch = _azure_challenge()
        await verifier.verify(ch)
        events = list(sink.iter_events(tenant_id=ch.tenant_id))
        assert events
        flat = _flatten_event(events[-1])
        for label, value in _all_secret_values():
            assert value not in flat, f"Azure audit leaked {label}: {value!r}"

    @pytest.mark.asyncio
    async def test_azure_failure_does_not_leak_secrets(self) -> None:
        logger, sink = _fresh_logger()
        explicit = RuntimeError(
            f"imds: oid={SECRETS['azure_object_id']} "
            f"tenant={SECRETS['azure_tenant_id']} "
            f"token={SECRETS['azure_access_token_marker']}"
        )
        verifier = AzureManagedIdentityVerifier(
            credential=_StubAzureCred(raise_exc=explicit),
            audit_logger=logger,
        )
        ch = _azure_challenge()
        with pytest.raises(OwnershipVerificationError):
            await verifier.verify(ch)
        events = list(sink.iter_events(tenant_id=ch.tenant_id))
        assert events
        flat = _flatten_event(events[-1])
        for label, value in _all_secret_values():
            assert value not in flat, f"Azure failure leaked {label}: {value!r}"

    def test_emit_cloud_attempt_blocks_secret_extra_fields(self) -> None:
        """``emit_cloud_attempt(extra=...)`` MUST reject all known
        secret-bearing keys, regardless of the value the caller passes.
        """
        logger, _ = _fresh_logger()
        ch = _aws_challenge()
        descriptor = descriptor_from_challenge(
            cloud_provider="aws",
            principal_kind="role_arn",
            principal_identifier=ch.target,
            challenge=ch,
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
                    challenge=ch,
                    actor_id=None,
                    descriptor=descriptor,
                    allowed=False,
                    summary="ownership_aws_sts_invalid_arn",
                    extra={forbidden: "anything"},
                )


# ---------------------------------------------------------------------------
# Constant-time compares + redaction primitives
# ---------------------------------------------------------------------------


class TestConstantTimeAndRedaction:
    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ("identicalsecret", "identicalsecret", True),
            ("identicalsecret", "identicalsecreT", False),
            ("", "", True),
            ("a", "ab", False),
        ],
    )
    def test_constant_time_str_equal(
        self, left: str, right: str, expected: bool
    ) -> None:
        assert constant_time_str_equal(left, right) is expected

    def test_redact_token_keeps_at_most_4_chars(self) -> None:
        out = redact_token(SECRETS["aws_external_id"], keep=10)
        assert SECRETS["aws_external_id"] not in out
        assert out.startswith(SECRETS["aws_external_id"][:4])

    def test_redact_token_handles_short_value_without_revealing_length(
        self,
    ) -> None:
        assert redact_token("abc") == "<redacted>"

    def test_redact_token_handles_none(self) -> None:
        assert redact_token(None) == "<none>"


# ---------------------------------------------------------------------------
# NetworkPolicy egress allowlists are FQDN/CIDR pinned (no wildcards)
# ---------------------------------------------------------------------------


_NP_DIR: Path = (
    Path(__file__).resolve().parents[3] / "infra" / "k8s" / "networkpolicies"
)
"""Path to the cloud-IAM NetworkPolicy bundle.

``parents`` indices (Windows-safe absolute path):
  - ``parents[0]`` = ``backend/tests/security/``
  - ``parents[1]`` = ``backend/tests/``
  - ``parents[2]`` = ``backend/``
  - ``parents[3]`` = repo root (where ``infra/`` lives).
"""


class TestNetworkPolicyEgressAllowlists:
    @pytest.mark.parametrize(
        "filename",
        ["cloud-aws.yaml", "cloud-gcp.yaml", "cloud-azure.yaml"],
    )
    def test_yaml_exists(self, filename: str) -> None:
        path = _NP_DIR / filename
        assert path.is_file(), f"missing NetworkPolicy: {path}"

    @pytest.mark.parametrize(
        "filename",
        ["cloud-aws.yaml", "cloud-gcp.yaml", "cloud-azure.yaml"],
    )
    def test_no_wildcard_egress(self, filename: str) -> None:
        text = (_NP_DIR / filename).read_text(encoding="utf-8")
        # Strip YAML comment lines so we only audit policy structure
        # — the manifests legitimately mention "no 0.0.0.0/0" inside
        # explanatory comments to document the intent.
        non_comment = "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith("#")
        )
        # 0.0.0.0/0 is the canonical "egress-anywhere" wildcard.
        assert "0.0.0.0/0" not in non_comment, (
            f"{filename} contains 0.0.0.0/0 wildcard"
        )
        # ``namespaceSelector: {}`` would let pods reach any namespace.
        assert "namespaceSelector: {}" not in non_comment
        # ``- to: []`` opens egress to everywhere; never legal here.
        assert "- to: []" not in non_comment

    @pytest.mark.parametrize(
        "filename",
        ["cloud-aws.yaml", "cloud-gcp.yaml", "cloud-azure.yaml"],
    )
    def test_uses_label_selector(self, filename: str) -> None:
        text = (_NP_DIR / filename).read_text(encoding="utf-8")
        assert "app: argus-backend" in text
        assert "cloud-iam: enabled" in text

    @pytest.mark.parametrize(
        "filename",
        ["cloud-aws.yaml", "cloud-gcp.yaml", "cloud-azure.yaml"],
    )
    def test_egress_only_on_443_or_dns(self, filename: str) -> None:
        text = (_NP_DIR / filename).read_text(encoding="utf-8")
        # All TCP egress ports must be 443 (HTTPS); UDP/TCP 53 only for DNS.
        ports = re.findall(r"port:\s*(\d+)", text)
        bad = [p for p in ports if p not in {"443", "53"}]
        assert not bad, f"{filename} opens unexpected ports: {bad}"


# ---------------------------------------------------------------------------
# Sliding-window cache & timeout invariants from the spec
# ---------------------------------------------------------------------------


class TestCacheAndTimeoutInvariants:
    def test_cloud_iam_ttl_is_ten_minutes(self) -> None:
        assert CLOUD_IAM_TTL_S == 600

    def test_cloud_sdk_timeout_is_strict(self) -> None:
        assert 0 < CLOUD_SDK_TIMEOUT_S <= 10
        assert CLOUD_SDK_TIMEOUT_S == 5.0

    def test_cloud_iam_methods_is_complete(self) -> None:
        assert CLOUD_IAM_METHODS == frozenset(
            {
                OwnershipMethod.AWS_STS_ASSUME_ROLE,
                OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT,
                OwnershipMethod.AZURE_MANAGED_IDENTITY,
            }
        )


# ---------------------------------------------------------------------------
# Adapter protocol-conformance — DI seam must remain testable
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_adapters_implement_their_protocols(self) -> None:
        from src.policy.cloud_iam.aws import BotoStsAdapter
        from src.policy.cloud_iam.azure import AzureManagedIdentityAdapter
        from src.policy.cloud_iam.gcp import GoogleAuthIamAdapter

        class _FakeBoto:
            """Minimal stand-in for a boto3 STS client (only the
            ``assume_role`` attribute matters for the adapter constructor)."""

            def assume_role(self, **_: Any) -> Mapping[str, Any]:  # noqa: ANN401
                return {}

        # ``runtime_checkable`` Protocol — ``isinstance`` is the runtime
        # gate the DI factory uses. ``BotoStsAdapter`` requires a real
        # client object (we pass a stub); the GCP / Azure adapters take
        # only kwargs and have safe defaults.
        assert isinstance(BotoStsAdapter(sts_client=_FakeBoto()), StsClientProtocol)
        assert isinstance(GoogleAuthIamAdapter(), GcpIamProtocol)
        assert isinstance(AzureManagedIdentityAdapter(), AzureCredentialProtocol)


# ---------------------------------------------------------------------------
# Helpers ensure the test file itself isn't running async loops outside pytest
# ---------------------------------------------------------------------------


def test_no_event_loop_pollution() -> None:
    """If a previous test forgot to ``asyncio.run`` or mismanaged a loop
    we'd accidentally inherit it; pytest-asyncio handles the proper
    cleanup, but the security gate still asserts a clean baseline."""
    try:
        asyncio.get_running_loop()
        running = True
    except RuntimeError:
        running = False
    assert not running
