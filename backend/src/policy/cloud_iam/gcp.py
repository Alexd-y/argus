"""GCP service-account JWT ownership verifier (ARG-043).

Customer flow
-------------

1. Tenant operator creates a Google Cloud service account
   (``svc-name@project.iam.gserviceaccount.com``).
2. Tenant grants ARGUS' ingest principal the
   ``roles/iam.serviceAccountTokenCreator`` role ON the SA so ARGUS can
   call ``iamcredentials.signJwt`` against it.
3. ARGUS dispatch routes
   :data:`OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT` challenges to
   :class:`GcpServiceAccountJwtVerifier.verify`, which:

    * asks the injected :class:`GcpIamProtocol` to sign + verify a JWT
      whose payload carries the per-challenge ``argus_token`` (the
      43-char secret from :class:`OwnershipChallenge`) and the
      pre-registered audience;
    * cross-checks ``aud`` / ``iss`` / ``sub`` / ``argus_token`` /
      time bounds in the returned claims;
    * returns a fresh :class:`OwnershipProof`.

The IAM client surface intentionally hides whether the JWT is fetched
from a customer-hosted URL or minted via ``iamcredentials.signJwt``;
production wiring (:class:`GoogleAuthIamAdapter`) does the latter.
"""

from __future__ import annotations

import logging
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
    REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID,
    REASON_GCP_SA_JWT_INVALID_AUDIENCE,
    REASON_GCP_SA_JWT_TIMEOUT,
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


class JwtClaims(TypedDict, total=False):
    """Subset of JWT claims the verifier checks."""

    iss: str
    sub: str
    aud: str
    iat: int
    exp: int
    nbf: int
    argus_token: str


@runtime_checkable
class GcpIamProtocol(Protocol):
    """Surface for proving service-account ownership.

    Production implementations call ``iamcredentials.signJwt`` against
    the customer's SA and then decode/verify the JWT against Google's
    JWKS; a stub that simply returns fixture claims is sufficient for
    unit tests.
    """

    async def verify_service_account_jwt(
        self,
        *,
        service_account_email: str,
        expected_audience: str,
        expected_argus_token: str,
    ) -> JwtClaims:
        """Return the validated claim set for ``service_account_email``.

        MUST raise on:
          * bad signature / unsigned tokens,
          * iss/aud/argus_token mismatch,
          * iat/exp outside the leeway window.
        """


# ---------------------------------------------------------------------------
# Concrete adapter
# ---------------------------------------------------------------------------


class GoogleAuthIamAdapter:
    """Adapter wrapping :mod:`google.auth` + ``iamcredentials.signJwt``."""

    def __init__(
        self,
        *,
        certs_url: str | None = None,
        signjwt_url_template: str = (
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:signJwt"
        ),
    ) -> None:
        self._certs_url = certs_url
        self._signjwt_url_template = signjwt_url_template

    async def verify_service_account_jwt(
        self,
        *,
        service_account_email: str,
        expected_audience: str,
        expected_argus_token: str,
    ) -> JwtClaims:
        import asyncio

        def _call() -> JwtClaims:
            try:
                from google.auth import default as google_default  # noqa: PLC0415
                from google.auth.transport import requests as google_requests  # noqa: PLC0415
                from google.oauth2 import id_token as google_id_token  # noqa: PLC0415
            except ImportError as exc:  # pragma: no cover — declared dep
                raise OwnershipVerificationError(
                    REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID
                ) from exc

            # google-auth has partial typing; treat the SDK surface as Any
            # so we don't pin a hard stub-completeness requirement.
            _default: Any = google_default
            _requests: Any = google_requests
            _id_token: Any = google_id_token

            credentials, _ = _default(
                scopes=["https://www.googleapis.com/auth/iam"]
            )
            request = _requests.Request()
            credentials.refresh(request)

            payload = {
                "aud": expected_audience,
                "argus_token": expected_argus_token,
                "sub": service_account_email,
                "iss": service_account_email,
            }
            try:
                signed_jwt = _request_signed_jwt(
                    request=request,
                    credentials=credentials,
                    sa_email=service_account_email,
                    payload=payload,
                    url_template=self._signjwt_url_template,
                )
            except Exception as exc:
                raise _GoogleAuthFailed(exc) from exc

            try:
                claims = _id_token.verify_token(
                    signed_jwt,
                    request,
                    audience=expected_audience,
                    certs_url=self._certs_url,
                )
            except Exception as exc:
                raise _GoogleAuthFailed(exc) from exc

            if not isinstance(claims, dict):
                raise _GoogleAuthFailed(TypeError("claims must be a dict"))
            casted: JwtClaims = {}
            for key in ("iss", "sub", "aud", "argus_token"):
                if key in claims:
                    casted[key] = str(claims[key])
            for key in ("iat", "exp", "nbf"):
                if key in claims:
                    try:
                        # mypy: TypedDict literal-key narrow via local Final
                        # tuple; runtime `key` is one of the four legal slots.
                        casted[key] = int(claims[key])  # type: ignore[literal-required]
                    except (TypeError, ValueError):
                        continue
            return casted

        return await asyncio.to_thread(_call)


def _request_signed_jwt(
    *,
    request: Any,
    credentials: Any,
    sa_email: str,
    payload: dict[str, Any],
    url_template: str,
) -> str:
    import json

    headers: dict[str, str] = {}
    credentials.apply(headers)
    headers["Content-Type"] = "application/json"
    body = json.dumps({"payload": json.dumps(payload)}).encode("utf-8")
    response = request(
        url=url_template.format(sa=sa_email),
        method="POST",
        headers=headers,
        body=body,
    )
    if getattr(response, "status", 200) >= 400:
        raise RuntimeError("signJwt failed")
    data = json.loads(getattr(response, "data", b"{}"))
    if not isinstance(data, dict) or "signedJwt" not in data:
        raise RuntimeError("signJwt returned no signedJwt")
    return str(data["signedJwt"])


class _GoogleAuthFailed(RuntimeError):
    def __init__(self, original: BaseException) -> None:
        super().__init__(type(original).__name__)
        self.original = original


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


_AUDIENCE_PREFIX: Final[str] = "https://ownership.argus.io/"
_DEFAULT_LEEWAY_S: Final[int] = 30
_VALID_ISSUER_SUFFIXES: Final[tuple[str, ...]] = (
    ".iam.gserviceaccount.com",
    ".gserviceaccount.com",
)


@dataclass(frozen=True, slots=True)
class _ParsedTarget:
    """``challenge.target`` interpreted as ``service-account|audience``."""

    service_account_email: str
    audience: str


class GcpServiceAccountJwtVerifier:
    """Verify customer ownership of a GCP service account.

    ``challenge.target`` MUST follow the format
    ``"<sa-email>|<audience>"`` where ``<sa-email>`` is the service
    account expected to sign the JWT and ``<audience>`` is the
    pre-registered audience claim. The audience MUST start with
    :data:`_AUDIENCE_PREFIX` so an adversarial customer cannot point
    us at an attacker-controlled URL.

    The 43-char :class:`OwnershipChallenge.token` is the per-challenge
    secret embedded into the JWT's ``argus_token`` claim by Google's
    ``iamcredentials.signJwt`` API.
    """

    cloud_provider: str = "gcp"

    def __init__(
        self,
        *,
        iam_client: GcpIamProtocol,
        audit_logger: AuditLogger | None = None,
        leeway_s: int = _DEFAULT_LEEWAY_S,
    ) -> None:
        if leeway_s < 0 or leeway_s > 300:
            raise ValueError("leeway_s must be in [0, 300]")
        self._iam = iam_client
        self._audit_logger = audit_logger
        self._leeway_s = leeway_s

    async def verify(self, challenge: OwnershipChallenge) -> OwnershipProof:
        if challenge.method is not OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT:
            raise OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)
        meta = metadata_for(challenge.method)
        parsed_target = _parse_target(challenge.target)
        descriptor = descriptor_from_challenge(
            cloud_provider=meta.cloud_provider,
            principal_kind="service_account",
            principal_identifier=parsed_target.service_account_email,
            challenge=challenge,
        )

        claims = await self._call_iam(
            sa_email=parsed_target.service_account_email,
            audience=parsed_target.audience,
            argus_token=challenge.token,
            descriptor=descriptor,
            challenge=challenge,
        )

        try:
            self._validate_claims(
                claims=claims,
                parsed_target=parsed_target,
                challenge=challenge,
            )
        except OwnershipVerificationError as exc:
            self._emit(challenge, descriptor, allowed=False, summary=exc.summary)
            raise

        proof = make_proof(challenge=challenge, notes="gcp_sa_jwt")
        self._emit(challenge, descriptor, allowed=True, summary=None)
        return proof

    # -- helpers ------------------------------------------------------------

    async def _call_iam(
        self,
        *,
        sa_email: str,
        audience: str,
        argus_token: str,
        descriptor: CloudPrincipalDescriptor,
        challenge: OwnershipChallenge,
    ) -> JwtClaims:
        async def _do() -> JwtClaims:
            try:
                return await self._iam.verify_service_account_jwt(
                    service_account_email=sa_email,
                    expected_audience=audience,
                    expected_argus_token=argus_token,
                )
            except OwnershipVerificationError:
                raise
            except OwnershipTimeoutError:
                raise
            except _GoogleAuthFailed:
                raise OwnershipVerificationError(
                    REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID
                ) from None
            except Exception:
                raise OwnershipVerificationError(
                    REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID
                ) from None

        try:
            return await run_with_timeout(_do, timeout_reason=REASON_GCP_SA_JWT_TIMEOUT)
        except OwnershipTimeoutError:
            self._emit(
                challenge,
                descriptor,
                allowed=False,
                summary=REASON_GCP_SA_JWT_TIMEOUT,
            )
            raise OwnershipVerificationError(REASON_GCP_SA_JWT_TIMEOUT)
        except OwnershipVerificationError as exc:
            self._emit(challenge, descriptor, allowed=False, summary=exc.summary)
            raise

    def _validate_claims(
        self,
        *,
        claims: JwtClaims,
        parsed_target: _ParsedTarget,
        challenge: OwnershipChallenge,
    ) -> None:
        aud = claims.get("aud", "")
        if not isinstance(aud, str) or not constant_time_str_equal(
            aud, parsed_target.audience
        ):
            raise OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)

        sub = claims.get("sub", "")
        iss = claims.get("iss", "")
        if not isinstance(sub, str) or not constant_time_str_equal(
            sub, parsed_target.service_account_email
        ):
            raise OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)
        if iss and iss != sub and not constant_time_str_equal(
            iss, parsed_target.service_account_email
        ):
            raise OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)

        if not (
            iss.endswith(_VALID_ISSUER_SUFFIXES) or sub.endswith(_VALID_ISSUER_SUFFIXES)
        ):
            raise OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)

        argus_token = claims.get("argus_token", "")
        if not isinstance(argus_token, str) or not constant_time_str_equal(
            argus_token, challenge.token
        ):
            raise OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)

        now = int(utcnow().timestamp())
        iat = _coerce_int(claims.get("iat"))
        exp = _coerce_int(claims.get("exp"))
        nbf = _coerce_int(claims.get("nbf"))

        if exp is None:
            raise OwnershipVerificationError(
                REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID
            )
        if exp + self._leeway_s < now:
            raise OwnershipVerificationError(
                REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID
            )
        if iat is not None and iat - self._leeway_s > now:
            raise OwnershipVerificationError(
                REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID
            )
        if nbf is not None and nbf - self._leeway_s > now:
            raise OwnershipVerificationError(
                REASON_GCP_SA_JWT_EXPIRED_OR_NOT_YET_VALID
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


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_target(target: str) -> _ParsedTarget:
    """Parse ``target`` as ``"<sa-email>|<audience>"``.

    Raises :class:`OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)`
    on malformed input or audience that does not start with the
    enforced prefix.
    """
    if "|" not in target:
        raise OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)
    head, _, tail = target.partition("|")
    sa_email = head.strip().lower()
    audience = tail.strip()
    if "@" not in sa_email or len(sa_email) > 256:
        raise OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)
    if not sa_email.endswith(_VALID_ISSUER_SUFFIXES):
        raise OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)
    if not audience.startswith(_AUDIENCE_PREFIX) or len(audience) > 1024:
        raise OwnershipVerificationError(REASON_GCP_SA_JWT_INVALID_AUDIENCE)
    return _ParsedTarget(service_account_email=sa_email, audience=audience)


__all__ = [
    "GcpIamProtocol",
    "GcpServiceAccountJwtVerifier",
    "GoogleAuthIamAdapter",
    "JwtClaims",
]
