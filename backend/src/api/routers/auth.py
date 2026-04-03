"""Auth router — POST /auth/login (JWT), GET /auth/me."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select

from src.core.auth import AuthContext, create_access_token, get_required_auth
from src.core.config import settings
from src.db.models import User
from src.db.session import async_session_factory

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginRequest(BaseModel):
    """Login request — mail/password per pentagi reference."""

    mail: str
    password: str


@router.post("/login")
async def login(req: LoginRequest) -> dict:
    """Login — validates credentials against users table, returns JWT."""
    if not settings.jwt_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT_SECRET missing",
        )

    async with async_session_factory() as session:
        result = await session.execute(
            select(User).where(User.email == req.mail, User.is_active == True)  # noqa: E712
        )
        user = result.scalar_one_or_none()

    if user:
        try:
            if _pwd_context.verify(req.password, user.password_hash):
                token = create_access_token(user_id=str(user.id), tenant_id=str(user.tenant_id))
                return {
                    "status": "success",
                    "access_token": token,
                    "token_type": "bearer",
                    "user_id": user.id,
                    "tenant_id": user.tenant_id,
                }
        except Exception:
            logger.exception(
                "password_verification_error",
                extra={"event": "argus.auth.password_verification_error"},
            )

    if settings.debug:
        logger.warning(
            "dev_login_bypass",
            extra={"event": "argus.auth.dev_login_bypass"},
        )
        token = create_access_token(user_id="dev-user", tenant_id=settings.default_tenant_id)
        return {
            "status": "success",
            "access_token": token,
            "token_type": "bearer",
            "dev_mode": True,
        }

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
    )


@router.get("/me")
async def me(auth: Annotated[AuthContext, Depends(get_required_auth)]) -> dict:
    """Current user info — requires valid JWT or API key."""
    return {
        "user_id": auth.user_id,
        "tenant_id": auth.tenant_id,
        "is_api_key": auth.is_api_key,
    }
