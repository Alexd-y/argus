"""JWT auth — access token validation, optional API key."""

import hmac
import os
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt  # type: ignore[import-untyped]

from src.core.config import settings

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class AuthContext:
    """Authenticated context — user_id, tenant_id."""

    def __init__(self, user_id: str, tenant_id: str, is_api_key: bool = False):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.is_api_key = is_api_key


def _decode_jwt(token: str) -> dict | None:
    """Decode and validate JWT. Returns payload or None."""
    if not settings.jwt_secret:
        return None
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except JWTError:
        return None


def _configured_api_keys() -> list[str]:
    """Allowlisted service API keys — settings first, ``ARGUS_API_KEYS`` fallback."""
    keys = [k.strip() for k in settings.api_keys if k and k.strip()]
    if keys:
        return keys
    raw = os.environ.get("ARGUS_API_KEYS") or ""
    return [k.strip() for k in raw.split(",") if k.strip()]


def _match_api_key(candidate: str) -> AuthContext | None:
    """Resolve *candidate* against the configured API keys, comparing in constant time."""
    if not candidate:
        return None
    probe = candidate.encode("utf-8")

    for known in _configured_api_keys():
        if hmac.compare_digest(probe, known.encode("utf-8")):
            return AuthContext(
                user_id="api-key",
                tenant_id=settings.default_tenant_id,
                is_api_key=True,
            )

    admin_key = settings.admin_api_key
    if admin_key and hmac.compare_digest(probe, admin_key.encode("utf-8")):
        return AuthContext(
            user_id="admin",
            tenant_id=settings.default_tenant_id,
            is_api_key=True,
        )

    return None


async def get_optional_auth(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ],
    api_key: Annotated[str | None, Depends(api_key_header)],
) -> AuthContext | None:
    """
    Optional auth — returns AuthContext if valid token/API key, else None.
    Use for endpoints that work both with and without auth.
    """
    if credentials and credentials.scheme == "Bearer":
        token = credentials.credentials
        payload = _decode_jwt(token)
        if payload and payload.get("type") == "access":
            sub = payload.get("sub")
            tenant_id = payload.get("tenant_id")
            if sub and tenant_id:
                return AuthContext(user_id=sub, tenant_id=tenant_id, is_api_key=False)

        # Service clients (e2e harness, nginx gateway) are documented to send
        # their provisioned API key via Authorization: Bearer. The key must
        # still be in the configured allowlist to be accepted.
        bearer_key_auth = _match_api_key(token)
        if bearer_key_auth is not None:
            return bearer_key_auth

    if api_key:
        return _match_api_key(api_key)

    return None


async def get_required_auth(
    auth: Annotated[AuthContext | None, Depends(get_optional_auth)],
) -> AuthContext:
    """Required auth — 401 if not authenticated."""
    if auth is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return auth


def create_access_token(user_id: str, tenant_id: str) -> str:
    """Create JWT access token."""
    if not settings.jwt_secret:
        raise ValueError("JWT_SECRET not configured")
    now = int(datetime.now(UTC).timestamp())
    expiry_minutes = 15
    if settings.jwt_expiry.endswith("m"):
        expiry_minutes = int(settings.jwt_expiry[:-1])
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "iat": now,
        "exp": now + expiry_minutes * 60,
        "type": "access",
    }
    return jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
