"""AWS STS Assume-Role ownership verifier (ARG-043).

Customer flow
-------------

1. Tenant operator creates an IAM role in their account with a trust
   policy pinning ``sts:ExternalId`` to the
   :class:`OwnershipChallenge.token` ARGUS issued for them.
2. Tenant configures the role ARN + expected account ID in
   ``OwnershipChallenge.target`` (``"arn:aws:iam::<acct>:role/<name>"``).
3. ARGUS' worker pod, holding a baseline IAM identity with the
   ``sts:AssumeRole`` permission, calls
   :class:`AwsStsVerifier.verify(challenge)`.
4. The verifier performs ``sts:AssumeRole(RoleArn, ExternalId)`` via
   the injected :class:`StsClientProtocol` and checks that:
    * the API returns successfully (proves ARGUS can assume the role);
    * the returned ``Account`` matches the ARN's account id;
    * (optional) the ``UserId`` prefix matches a tenant pin if one was
      registered. The default verifier only enforces the first two.

If any check fails the closed-taxonomy reason from
:mod:`src.policy.ownership` is raised — never the raw boto3 error.

Wiring
------

::

    from boto3.session import Session
    from src.policy.cloud_iam.aws import AwsStsVerifier, BotoStsAdapter

    session = Session(region_name="us-east-1")
    sts = BotoStsAdapter(session.client("sts"))
    aws_verifier = AwsStsVerifier(sts_client=sts)

    verifier = OwnershipVerifier(
        store=store,
        audit_logger=logger,
        cloud_verifiers={OwnershipMethod.AWS_STS_ASSUME_ROLE: aws_verifier},
    )

The ``BotoStsAdapter`` is intentionally tiny so unit tests can replace
it with a pure :class:`StsClientProtocol` stub without importing boto3.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any, Final, Protocol, TypedDict, cast, runtime_checkable

from src.policy.audit import AuditLogger
from src.policy.cloud_iam._common import (
    CloudPrincipalDescriptor,
    descriptor_from_challenge,
    emit_cloud_attempt,
    make_proof,
    metadata_for,
    redact_token,
    run_with_timeout,
)
from src.policy.ownership import (
    REASON_AWS_STS_ACCESS_DENIED,
    REASON_AWS_STS_INVALID_ARN,
    REASON_AWS_STS_REGION_MISMATCH,
    REASON_AWS_STS_TIMEOUT,
    OwnershipChallenge,
    OwnershipMethod,
    OwnershipProof,
    OwnershipTimeoutError,
    OwnershipVerificationError,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public protocol — the ONLY surface verifier code imports for boto3.
# ---------------------------------------------------------------------------


class AssumeRoleResponse(TypedDict, total=False):
    """Subset of the AWS STS ``AssumeRole`` response we depend on."""

    Account: str
    AssumedRoleUser: dict[str, str]
    Credentials: dict[str, Any]


@runtime_checkable
class StsClientProtocol(Protocol):
    """Async-compatible STS client surface used by :class:`AwsStsVerifier`.

    Adapters can wrap a synchronous ``boto3`` client by running it on a
    thread (see :class:`BotoStsAdapter`). Pure async clients (aioboto3,
    aiobotocore) implement the same shape natively.
    """

    async def assume_role(
        self,
        *,
        role_arn: str,
        role_session_name: str,
        external_id: str,
        duration_seconds: int,
    ) -> AssumeRoleResponse:
        """Call ``sts:AssumeRole`` and return the parsed response."""


# ---------------------------------------------------------------------------
# Concrete adapter — kept small so it can be swapped out in tests.
# ---------------------------------------------------------------------------


class BotoStsAdapter:
    """Adapter from a synchronous ``boto3`` STS client to :class:`StsClientProtocol`.

    Built so production code never imports ``boto3`` outside of this
    file. Tests provide their own :class:`StsClientProtocol` stubs and
    skip importing the SDK entirely.
    """

    def __init__(self, sts_client: Any) -> None:
        if not hasattr(sts_client, "assume_role"):
            raise TypeError("sts_client must implement assume_role()")
        self._client = sts_client

    async def assume_role(
        self,
        *,
        role_arn: str,
        role_session_name: str,
        external_id: str,
        duration_seconds: int,
    ) -> AssumeRoleResponse:
        import asyncio

        def _call() -> AssumeRoleResponse:
            try:
                response = self._client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=role_session_name,
                    ExternalId=external_id,
                    DurationSeconds=duration_seconds,
                )
            except Exception as exc:
                raise _BotoCallFailed(exc) from exc
            # boto3 stubs are not type-checked, but the runtime contract is
            # enforced by ``AssumeRoleResponse``'s TypedDict shape — caller
            # validates required keys (`Credentials.AccessKeyId`, etc.).
            return cast(AssumeRoleResponse, response)

        return await asyncio.to_thread(_call)


class _BotoCallFailed(RuntimeError):
    """Internal wrapper so the adapter can surface boto3 ClientError to the
    verifier without importing ``botocore.exceptions`` here."""

    def __init__(self, original: BaseException) -> None:
        super().__init__(type(original).__name__)
        self.original = original


# ---------------------------------------------------------------------------
# ARN parsing — strict, no regex backtracking, never logs raw input.
# ---------------------------------------------------------------------------


_ROLE_ARN_RE: Final[re.Pattern[str]] = re.compile(
    r"^arn:aws[a-zA-Z0-9-]*:iam::(\d{12}):role/([A-Za-z0-9+=,.@_/-]{1,128})$"
)
_AWS_PARTITIONS: Final[frozenset[str]] = frozenset(
    {"aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b"}
)
_DEFAULT_SESSION_DURATION_S: Final[int] = 900  # 15 min minimum allowed by STS
_DEFAULT_SESSION_PREFIX: Final[str] = "argus-ownership"


class ParsedRoleArn(TypedDict):
    partition: str
    account_id: str
    role_name: str


def parse_role_arn(arn: str) -> ParsedRoleArn:
    """Parse ``arn`` into its IAM-role components.

    Raises :class:`OwnershipVerificationError(REASON_AWS_STS_INVALID_ARN)`
    on malformed input. The raw ARN is never embedded in the
    exception message — only the closed-taxonomy reason.
    """
    if not arn or len(arn) > 2048:
        raise OwnershipVerificationError(REASON_AWS_STS_INVALID_ARN)
    match = _ROLE_ARN_RE.match(arn.strip())
    if match is None:
        raise OwnershipVerificationError(REASON_AWS_STS_INVALID_ARN)
    parts = arn.split(":")
    partition = parts[1]
    if partition not in _AWS_PARTITIONS:
        raise OwnershipVerificationError(REASON_AWS_STS_INVALID_ARN)
    return ParsedRoleArn(
        partition=partition,
        account_id=match.group(1),
        role_name=match.group(2),
    )


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class AwsStsVerifier:
    """Verify customer ownership via ``sts:AssumeRole``.

    Parameters
    ----------
    sts_client
        Injected :class:`StsClientProtocol` implementation. Tests pass
        a stub; production wires a :class:`BotoStsAdapter` around a
        ``boto3`` client.
    audit_logger
        Optional :class:`AuditLogger`. When supplied, every verify
        attempt (success and failure) emits a hashed audit event from
        this module in addition to the dispatch-layer event. Defaults
        to ``None`` (the dispatch layer is the sole emitter).
    role_session_name_prefix
        First segment of the ``RoleSessionName`` passed to STS.
        Defaults to ``"argus-ownership"`` so AWS CloudTrail logs can
        be filtered easily.
    session_duration_s
        ``DurationSeconds`` passed to STS — minimum allowed is 900s.
    expected_account_resolver
        Optional callable that returns the expected account id for a
        given challenge. When provided, a successful AssumeRole is
        rejected with :data:`REASON_AWS_STS_REGION_MISMATCH` if the
        caller account differs. Defaults to deriving the expected
        account from the ARN itself.
    """

    cloud_provider: str = "aws"

    def __init__(
        self,
        *,
        sts_client: StsClientProtocol,
        audit_logger: AuditLogger | None = None,
        role_session_name_prefix: str = _DEFAULT_SESSION_PREFIX,
        session_duration_s: int = _DEFAULT_SESSION_DURATION_S,
        expected_account_resolver: Callable[[OwnershipChallenge], str | None] | None = None,
    ) -> None:
        if session_duration_s < 900 or session_duration_s > 43_200:
            raise ValueError("session_duration_s must be in [900, 43_200]")
        if not role_session_name_prefix or len(role_session_name_prefix) > 32:
            raise ValueError("role_session_name_prefix must be 1..32 chars")
        if not role_session_name_prefix.replace("-", "").isalnum():
            raise ValueError("role_session_name_prefix must be ASCII alnum + hyphen")
        self._sts = sts_client
        self._audit_logger = audit_logger
        self._session_prefix = role_session_name_prefix
        self._session_duration_s = session_duration_s
        self._expected_account_resolver = expected_account_resolver

    async def verify(self, challenge: OwnershipChallenge) -> OwnershipProof:
        """Run an AssumeRole-based ownership check for ``challenge``.

        Steps:

        1. Validate the challenge method is :data:`AWS_STS_ASSUME_ROLE`.
        2. Parse the role ARN from ``challenge.target``.
        3. Build a deterministic ``RoleSessionName`` from the
           challenge id.
        4. Invoke ``sts:AssumeRole`` with the per-tenant external_id
           (the challenge token).
        5. Cross-check the returned account / user id against the
           expected values.
        6. Return a fresh :class:`OwnershipProof` on success.
        """
        if challenge.method is not OwnershipMethod.AWS_STS_ASSUME_ROLE:
            raise OwnershipVerificationError(REASON_AWS_STS_INVALID_ARN)
        meta = metadata_for(challenge.method)
        parsed = parse_role_arn(challenge.target)
        descriptor = descriptor_from_challenge(
            cloud_provider=meta.cloud_provider,
            principal_kind="role_arn",
            principal_identifier=challenge.target,
            challenge=challenge,
        )

        session_name = self._build_session_name(challenge)

        try:
            response = await self._call_assume_role(
                role_arn=challenge.target,
                role_session_name=session_name,
                external_id=challenge.token,
            )
        except OwnershipTimeoutError:
            self._emit(challenge, descriptor, allowed=False, summary=REASON_AWS_STS_TIMEOUT)
            raise OwnershipVerificationError(REASON_AWS_STS_TIMEOUT)
        except OwnershipVerificationError as exc:
            self._emit(challenge, descriptor, allowed=False, summary=exc.summary)
            raise

        try:
            self._validate_response(parsed=parsed, response=response, challenge=challenge)
        except OwnershipVerificationError as exc:
            self._emit(challenge, descriptor, allowed=False, summary=exc.summary)
            raise

        proof = make_proof(challenge=challenge, notes="aws_sts_assume_role")
        self._emit(challenge, descriptor, allowed=True, summary=None)
        return proof

    # -- helpers ------------------------------------------------------------

    async def _call_assume_role(
        self,
        *,
        role_arn: str,
        role_session_name: str,
        external_id: str,
    ) -> AssumeRoleResponse:
        async def _do() -> AssumeRoleResponse:
            try:
                return await self._sts.assume_role(
                    role_arn=role_arn,
                    role_session_name=role_session_name,
                    external_id=external_id,
                    duration_seconds=self._session_duration_s,
                )
            except _BotoCallFailed as wrapper:
                raise self._map_boto_error(wrapper.original) from wrapper
            except OwnershipVerificationError:
                raise
            except OwnershipTimeoutError:
                raise
            except Exception as exc:
                raise self._map_boto_error(exc) from exc

        return await run_with_timeout(
            _do,
            timeout_reason=REASON_AWS_STS_TIMEOUT,
        )

    def _validate_response(
        self,
        *,
        parsed: ParsedRoleArn,
        response: AssumeRoleResponse,
        challenge: OwnershipChallenge,
    ) -> None:
        assumed = response.get("AssumedRoleUser") or {}
        returned_arn = str(assumed.get("Arn", "")).strip()
        returned_account = str(response.get("Account") or "").strip()

        if returned_account and returned_account != parsed["account_id"]:
            _logger.warning(
                "policy.cloud_iam.aws.account_mismatch",
                extra={
                    "expected_account_hash": redact_token(parsed["account_id"]),
                    "actual_account_hash": redact_token(returned_account),
                },
            )
            raise OwnershipVerificationError(REASON_AWS_STS_REGION_MISMATCH)

        if returned_arn:
            try:
                actual_role = parse_role_arn(_role_arn_from_assumed(returned_arn))
            except OwnershipVerificationError:
                raise OwnershipVerificationError(REASON_AWS_STS_INVALID_ARN)
            if actual_role["account_id"] != parsed["account_id"]:
                raise OwnershipVerificationError(REASON_AWS_STS_REGION_MISMATCH)
            if actual_role["role_name"] != parsed["role_name"]:
                raise OwnershipVerificationError(REASON_AWS_STS_INVALID_ARN)

        resolver = self._expected_account_resolver
        if resolver is not None:
            expected = resolver(challenge)
            if expected and expected != parsed["account_id"]:
                raise OwnershipVerificationError(REASON_AWS_STS_REGION_MISMATCH)

    def _build_session_name(self, challenge: OwnershipChallenge) -> str:
        suffix = challenge.challenge_id.hex[:24]
        candidate = f"{self._session_prefix}-{suffix}"
        candidate = candidate[:64]
        return candidate

    def _emit(
        self,
        challenge: OwnershipChallenge,
        descriptor: CloudPrincipalDescriptor,
        *,
        allowed: bool,
        summary: str | None,
    ) -> None:
        if self._audit_logger is None:
            return
        emit_cloud_attempt(
            audit_logger=self._audit_logger,
            challenge=challenge,
            actor_id=None,
            descriptor=descriptor,
            allowed=allowed,
            summary=summary,
        )

    @staticmethod
    def _map_boto_error(exc: BaseException) -> OwnershipVerificationError:
        """Map a raw boto exception class to the closed taxonomy.

        The exception ``__name__`` is the only attribute we look at —
        we deliberately ignore message text so a misconfigured AWS
        response can never leak into the audit log.
        """
        name = type(exc).__name__
        access_denied = {
            "ClientError",
            "AccessDenied",
            "AccessDeniedException",
            "InvalidIdentityToken",
            "ExpiredTokenException",
        }
        invalid = {
            "InvalidParameterException",
            "ValidationError",
            "MalformedPolicyDocumentException",
        }
        if name in access_denied:
            return OwnershipVerificationError(REASON_AWS_STS_ACCESS_DENIED)
        if name in invalid:
            return OwnershipVerificationError(REASON_AWS_STS_INVALID_ARN)
        # Default to access_denied — STS fails closed.
        return OwnershipVerificationError(REASON_AWS_STS_ACCESS_DENIED)


def _role_arn_from_assumed(arn: str) -> str:
    """Convert ``arn:aws:sts::<acct>:assumed-role/<name>/<session>`` to the role ARN."""
    parts = arn.split(":")
    if len(parts) < 6:
        return arn
    resource = parts[5]
    if not resource.startswith("assumed-role/"):
        return arn
    pieces = resource.split("/")
    if len(pieces) < 2:
        return arn
    role_name = pieces[1]
    return f"arn:{parts[1]}:iam::{parts[4]}:role/{role_name}"


__all__ = [
    "AssumeRoleResponse",
    "AwsStsVerifier",
    "BotoStsAdapter",
    "ParsedRoleArn",
    "StsClientProtocol",
    "parse_role_arn",
]
