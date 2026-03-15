"""Auth router — POST /auth/login (JWT), optional for admin-frontend."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from src.core.auth import create_access_token, get_required_auth
from src.core.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    """Login request — mail/password per pentagi reference."""

    mail: str
    password: str


@router.post("/login")
async def login(req: LoginRequest) -> dict:
    """
    Login — returns JWT access token when JWT_SECRET is set.
    Stub: accepts any credentials for dev. Production must validate against DB.
    """
    if not settings.jwt_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth not configured (JWT_SECRET missing)",
        )
    # Stub: no real user validation. Phase 3+ will validate against users table.
    user_id = "stub-user-id"
    tenant_id = "default-tenant-id"
    token = create_access_token(user_id=user_id, tenant_id=tenant_id)
    return {"status": "success", "access_token": token, "token_type": "bearer"}


@router.get("/me")
async def me(auth=Depends(get_required_auth)) -> dict:
    """Current user info — requires valid JWT or API key."""
    return {
        "user_id": auth.user_id,
        "tenant_id": auth.tenant_id,
        "is_api_key": auth.is_api_key,
    }
