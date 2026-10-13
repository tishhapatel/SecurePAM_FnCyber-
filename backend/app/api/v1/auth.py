"""
Authentication endpoints — login, token management, and user info.

In DEV_MODE: Uses MockIdP with local JWT tokens.
In production: Redirects to Keycloak OIDC flow.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import get_current_active_user, get_db
from app.core.security import (
    create_dev_access_token,
    create_dev_refresh_token,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas.common import UserInfo

router = APIRouter(prefix="/auth", tags=["authentication"])


# --- Schemas ---

class LoginRequest(BaseModel):
    """Dev-mode login request."""
    username: str
    password: str


class TokenResponse(BaseModel):
    """Token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class AuthConfig(BaseModel):
    """Auth configuration for frontend."""
    dev_mode: bool
    auth_url: Optional[str] = None
    client_id: Optional[str] = None
    realm: Optional[str] = None


# --- Endpoints ---

@router.get("/config", response_model=AuthConfig)
async def get_auth_config():
    """
    Return auth configuration for the frontend.
    Frontend uses this to determine whether to use dev login or OIDC redirect.
    """
    if settings.DEV_MODE:
        return AuthConfig(dev_mode=True)
    else:
        return AuthConfig(
            dev_mode=False,
            auth_url=settings.KEYCLOAK_AUTH_URL,
            client_id=settings.KEYCLOAK_CLIENT_ID,
            realm=settings.KEYCLOAK_REALM,
        )


@router.post("/login", response_model=TokenResponse)
async def dev_login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Dev-mode login endpoint.
    Only available when DEV_MODE=true.
    In production, authentication goes through Keycloak OIDC.
    """
    if not settings.DEV_MODE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Direct login is disabled. Use Keycloak OIDC authentication.",
        )

    # Find user
    result = await db.execute(
        select(User).where(
            User.username == body.username,
            User.is_active == True,
            User.is_deleted == False,
        )
    )
    user = result.scalar_one_or_none()

    if not user or not user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not verify_password(body.password, user.hashed_password):
        # Track failed login
        await db.execute(
            update(User)
            .where(User.id == user.id)
            .values(failed_login_count=User.failed_login_count + 1)
        )
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Get user roles
    roles = [
        ur.role.name
        for ur in user.roles
        if ur.role and ur.role.is_active
    ]

    # Create tokens
    access_token = create_dev_access_token(
        subject=user.username,
        roles=roles,
        extra_claims={
            "email": user.email,
            "name": user.full_name,
        },
    )
    refresh_token = create_dev_refresh_token(subject=user.username)

    # Update last login
    client_ip = request.client.host if request.client else None
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(
            last_login=datetime.now(timezone.utc),
            last_login_ip=client_ip,
            failed_login_count=0,
        )
    )
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.TOKEN_EXPIRY_MINUTES * 60,
    )


@router.get("/me", response_model=UserInfo)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user),
):
    """Return the current authenticated user's info and permissions."""
    roles = [
        ur.role.name
        for ur in current_user.roles
        if ur.role and ur.role.is_active
    ]

    permissions = set()
    for ur in current_user.roles:
        if ur.role and ur.role.is_active:
            for perm in ur.role.permissions:
                permissions.add(f"{perm.resource}:{perm.action}")

    return UserInfo(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        roles=roles,
        permissions=sorted(permissions),
        mfa_enabled=current_user.mfa_enabled,
        is_active=current_user.is_active,
    )
