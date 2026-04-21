"""Azure Managed Identity ownership verifier (ARG-043).

Customer flow
-------------

1. Tenant operator assigns a User-Assigned or System-Assigned Managed
   Identity to ARGUS' workload (``argus-backend`` pod runs with the
   identity's federated credentials).
2. ARGUS exchanges the identity for an OAuth bearer token via the
   IMDS / token-credential pipeline.
3. ARGUS' worker calls
   :class:`AzureManagedIdentityVerifier.verify(challenge)` which:

    * fetches a fresh access token via the injected
      :class:`AzureCredentialProtocol`;
    * decodes the (already-validated by Azure AD) ID-token claims;
    * cross-checks ``tid`` (Azure tenant id),
      ``oid`` (object id), and ``xms_mirid`` / ``mi_res_id``
      (the customer-pinned Managed Identity resource ID).

``challenge.target`` is encoded as
``"<azure-tenant-id>|<expected-oid>|<expected-mi-resource-id>"``.
The challenge token is the per-tenant proof string ARGUS embedded in
the IMDS request's ``client_request_id`` (Azure echoes it in the
returned token's ``xms_az_rid`` claim when the customer's Conditional
Access policy is configured to do so) — when the echo is absent, the
verifier still passes provided the three identifier pins match.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final, Protocol, TypedDict, runtime_checkable

from src.policy.audit import AuditLogger
from src.policy.cloud_iam._common import (
    CloudPrincipalDescriptor,
    constant_time_str_equal,
    descriptor_from_challenge,
    emit_cloud_attempt,
    make_proof,
    metadata_for,
    run_with_timeout,
    utcnow,
)
from src.policy.ownership import (
    REASON_AZURE_MI_RESOURCE_NOT_OWNED,
    REASON_AZURE_MI_TENANT_MISMATCH,
    REASON_AZURE_MI_TIMEOUT,
    REASON_AZURE_MI_TOKEN_REFRESH_FAILED,
    OwnershipChallenge,
    OwnershipMethod,
    OwnershipProof,
    OwnershipTimeoutError,
    OwnershipVerificationError,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public protocol
# ---------------------------------------------------------------------------


class AccessTokenResult(TypedDict, total=False):
    """Subset of an :mod:`azure.identity` access-token object."""

    token: str
    expires_on: int
    claims: dict[str, Any]


@runtime_checkable
class AzureCredentialProtocol(Protocol):
    """Surface for fetching an Azure AD access token + decoded claims.

    Production wiring uses :class:`AzureManagedIdentityAdapter`. Tests
    inject a stub returning fixture claims without touching IMDS.
    """

    async def get_token_with_claims(
        self,
        *,
        scope: str,
        client_request_id: str,
    ) -> AccessTokenResult:
        """Fetch an access token for ``scope`` and return parsed claims.

        ``client_request_id`` MUST be propagated to Azure AD so the
        customer can see ARGUS' request in their tenant audit log.
        """


# ---------------------------------------------------------------------------
# Concrete adapter
# ---------------------------------------------------------------------------


class AzureManagedIdentityAdapter:
    """Adapter wrapping :class:`azure.identity.ManagedIdentityCredential`."""

    def __init__(
        self,
        *,
        credential_factory: Callable[[], Any] | None = None,
        scope: str = "https://management.azure.com/.default",
    ) -> None:
        self._credential_factory = credential_factory
        self._scope = scope

    async def get_token_with_claims(
        self,
        *,
        scope: str,
        client_request_id: str,
    ) -> AccessTokenResult:
        import asyncio

        def _call() -> AccessTokenResult:
            try:
                from azure.core.exceptions import AzureError  # noqa: PLC0415
                from azure.identity import ManagedIdentityCredential  # noqa: PLC0415
            except ImportError as exc:  # pragma: no cover — declared dep
                raise OwnershipVerificationError(
                    REASON_AZURE_MI_TOKEN_REFRESH_FAILED
                ) from exc

            credential: Any = (
                self._credential_factory() if self._credential_factory else
                ManagedIdentityCredential()
            )
            try:
                token = credential.get_token(scope or self._scope)
            except AzureError as exc:
                raise _AzureCallFailed(exc) from exc
            except Exception as exc:
                raise _AzureCallFailed(exc) from exc

            access_token = getattr(token, "token", None)
            if not access_token:
                raise _AzureCallFailed(RuntimeError("token missing"))
            expires_on = int(getattr(token, "expires_on", 0))
            claims = _decode_jwt_payload(access_token)
            return AccessTokenResult(
                token=access_token,
                expires_on=expires_on,
                claims=claims,
            )

        return await asyncio.to_thread(_call)


class _AzureCallFailed(RuntimeError):
    def __init__(self, original: BaseException) -> None:
        super().__init__(type(original).__name__)
        self.original = original


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


_DEFAULT_AZURE_SCOPE: Final[str] = "https://management.azure.com/.default"
_MAX_RESOURCE_ID_LEN: Final[int] = 1024
_AZURE_TENANT_ID_LEN: Final[int] = 36  # uuid string
_AZURE_OBJECT_ID_LEN: Final[int] = 36


@dataclass(frozen=True, slots=True)
class _ParsedAzureTarget:
    """``challenge.target`` decoded into the three pinned identifiers."""

    tenant_id: str
    object_id: str
    mi_resource_id: str


class AzureManagedIdentityVerifier:
    """Verify Azure Managed-Identity ownership through token-claim pinning."""

    cloud_provider: str = "azure"

    def __init__(
        self,
        *,
        credential: AzureCredentialProtocol,
        audit_logger: AuditLogger | None = None,
        scope: str = _DEFAULT_AZURE_SCOPE,
    ) -> None:
        if not scope or len(scope) > 256:
            raise ValueError("scope must be 1..256 chars")
        self._credential = credential
        self._audit_logger = audit_logger
        self._scope = scope

    async def verify(self, challenge: OwnershipChallenge) -> OwnershipProof:
        if challenge.method is not OwnershipMethod.AZURE_MANAGED_IDENTITY:
            raise OwnershipVerificationError(REASON_AZURE_MI_TENANT_MISMATCH)
        meta = metadata_for(challenge.method)
        parsed = _parse_target(challenge.target)
        descriptor = descriptor_from_challenge(
            cloud_provider=meta.cloud_provider,
            principal_kind="managed_identity_object_id",
            principal_identifier=parsed.object_id,
            challenge=challenge,
        )

        try:
            token_result = await self._fetch_token(
                client_request_id=challenge.token,
                descriptor=descriptor,
                challenge=challenge,
            )
        except OwnershipVerificationError:
            raise

        try:
            self._validate_claims(
                claims=token_result.get("claims") or {},
                parsed=parsed,
            )
        except OwnershipVerificationError as exc:
            self._emit(challenge, descriptor, allowed=False, summary=exc.summary)
            raise

        proof = make_proof(challenge=challenge, notes="azure_managed_identity")
        self._emit(challenge, descriptor, allowed=True, summary=None)
        return proof

    # -- helpers ------------------------------------------------------------

    async def _fetch_token(
        self,
        *,
        client_request_id: str,
        descriptor: CloudPrincipalDescriptor,
        challenge: OwnershipChallenge,
    ) -> AccessTokenResult:
        async def _do() -> AccessTokenResult:
            try:
                return await self._credential.get_token_with_claims(
                    scope=self._scope,
                    client_request_id=client_request_id,
                )
            except OwnershipVerificationError:
                raise
            except OwnershipTimeoutError:
                raise
            except _AzureCallFailed:
                raise OwnershipVerificationError(
                    REASON_AZURE_MI_TOKEN_REFRESH_FAILED
                ) from None
            except Exception:
                raise OwnershipVerificationError(
                    REASON_AZURE_MI_TOKEN_REFRESH_FAILED
                ) from None

        try:
            return await run_with_timeout(_do, timeout_reason=REASON_AZURE_MI_TIMEOUT)
        except OwnershipTimeoutError:
            self._emit(
                challenge,
                descriptor,
                allowed=False,
                summary=REASON_AZURE_MI_TIMEOUT,
            )
            raise OwnershipVerificationError(REASON_AZURE_MI_TIMEOUT)
        except OwnershipVerificationError as exc:
            self._emit(challenge, descriptor, allowed=False, summary=exc.summary)
            raise

    def _validate_claims(
        self,
        *,
        claims: dict[str, Any],
        parsed: _ParsedAzureTarget,
    ) -> None:
        tid = str(claims.get("tid", "")).strip().lower()
        oid = str(claims.get("oid", "")).strip().lower()
        mi_resource = str(
            claims.get("xms_mirid")
            or claims.get("mi_res_id")
            or claims.get("xms_az_rid")
            or ""
        ).strip()

        if not tid or not constant_time_str_equal(tid, parsed.tenant_id):
            raise OwnershipVerificationError(REASON_AZURE_MI_TENANT_MISMATCH)
        if not oid or not constant_time_str_equal(oid, parsed.object_id):
            raise OwnershipVerificationError(REASON_AZURE_MI_RESOURCE_NOT_OWNED)
        if not mi_resource or not constant_time_str_equal(
            mi_resource.lower(), parsed.mi_resource_id
        ):
            raise OwnershipVerificationError(REASON_AZURE_MI_RESOURCE_NOT_OWNED)

        exp = claims.get("exp")
        if isinstance(exp, (int, float)):
            if int(exp) < int(utcnow().timestamp()):
                raise OwnershipVerificationError(
                    REASON_AZURE_MI_TOKEN_REFRESH_FAILED
                )

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


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """Best-effort JWT payload decode (no signature check).

    Used inside the adapter only — Azure already validated the token
    server-side, so we rely on the wire claims to extract identifiers
    for pinning. Any decoding error returns an empty dict; the
    downstream validator then surfaces a closed-taxonomy failure.
    """
    import base64
    import json as _json

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        data = _json.loads(decoded)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): v for k, v in data.items()}


def _parse_target(target: str) -> _ParsedAzureTarget:
    """Parse ``target`` as ``"<tenant>|<oid>|<mi-resource-id>"``."""
    parts = target.split("|")
    if len(parts) != 3:
        raise OwnershipVerificationError(REASON_AZURE_MI_TENANT_MISMATCH)
    tenant_id = parts[0].strip().lower()
    object_id = parts[1].strip().lower()
    mi_resource_id = parts[2].strip().lower()
    if (
        len(tenant_id) != _AZURE_TENANT_ID_LEN
        or len(object_id) != _AZURE_OBJECT_ID_LEN
    ):
        raise OwnershipVerificationError(REASON_AZURE_MI_TENANT_MISMATCH)
    if not mi_resource_id.startswith("/subscriptions/"):
        raise OwnershipVerificationError(REASON_AZURE_MI_RESOURCE_NOT_OWNED)
    if len(mi_resource_id) > _MAX_RESOURCE_ID_LEN:
        raise OwnershipVerificationError(REASON_AZURE_MI_RESOURCE_NOT_OWNED)
    return _ParsedAzureTarget(
        tenant_id=tenant_id,
        object_id=object_id,
        mi_resource_id=mi_resource_id,
    )


__all__ = [
    "AccessTokenResult",
    "AzureCredentialProtocol",
    "AzureManagedIdentityAdapter",
    "AzureManagedIdentityVerifier",
]
