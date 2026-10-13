"""
FastAPI dependencies — database sessions, auth, and service providers.
"""
from app.auth.oidc_provider import OIDCProviderUnavailableError
from app.core.config import settings
from typing import AsyncGenerator, List, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import InvalidTokenError, get_token_validator
from app.core.audit import client_ip, write_audit_log
from app.database.session import async_session_factory
from app.models.user import User, UserRole
from app.models.role import Role


# --- Database Dependency ---

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


# --- Auth Dependencies ---

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Extract and validate the current user from the request.

    Identity (who is this?) is resolved by the configured TokenValidator
    (DevAuth today, Keycloak/OIDC later — see app.auth). Authorization
    (what can they do?) always comes from SecurePAM's own RBAC tables via
    the local User row looked up below, never from the token itself.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    validator = get_token_validator()
    try:
        identity = validator.validate(credentials.credentials)
    except OIDCProviderUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Identity provider temporarily unavailable",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    except NotImplementedError as e:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=str(e),
        )

    # Resolve the authenticated identity to a local SecurePAM user.
    # Dev tokens use the username; Keycloak tokens use the external subject ID.
    identity_column = User.username if settings.DEV_MODE else User.external_id

    result = await db.execute(
        select(User).where(
            identity_column == identity.subject,
            User.is_active == True,
            User.is_deleted == False,
        )
    )

    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure the current user is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )
    return current_user


class RoleChecker:
    """
    Dependency that checks if the current user has the required role(s).
    
    Usage:
        @router.get("/admin-only", dependencies=[Depends(RoleChecker(["ADMIN"]))])
    """

    def __init__(self, required_roles: List[str]):
        self.required_roles = required_roles

    async def __call__(
        self,
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        user_roles = [
            ur.role.name
            for ur in current_user.roles
            if ur.role and ur.role.is_active
        ]
        
        if not any(role in user_roles for role in self.required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {', '.join(self.required_roles)}",
            )
        return current_user

def user_has_permission(user: User, resource: str, action: str) -> bool:
    """ADMIN has all permissions only while the ADMIN role is active."""
    active_roles = [
        ur.role for ur in user.roles
        if ur.role and ur.role.is_active
    ]

    if any(role.name == "ADMIN" for role in active_roles):
        return True

    required = f"{resource}:{action}"
    return any(
        f"{perm.resource}:{perm.action}" == required
        for role in active_roles
        for perm in role.permissions
    )



class PermissionChecker:
    """
    Dependency that checks if the current user has the required permission(s).
    Writes (and commits) an ACCESS_DENIED audit event on denial — see the
    commit-before-raise note on app.core.audit.write_audit_log.

    Usage:
        @router.post("/assets", dependencies=[Depends(PermissionChecker("assets", "create"))])

    Extra actions are alternatives — any one of them suffices, e.g.
    PermissionChecker("sessions", "read", "read_own"). Object-level scoping
    (own vs. all) is then the route's job.
    """

    def __init__(self, resource: str, action: str, *alternatives: str):
        self.resource = resource
        self.action = action
        self.actions = (action, *alternatives)

    async def __call__(
        self,
        request: Request,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:

        required = " | ".join(f"{self.resource}:{a}" for a in self.actions)

        if not any(user_has_permission(current_user, self.resource, a) for a in self.actions):

            await write_audit_log(
                db,
                actor=current_user,
                action="ACCESS_DENIED",
                target_type=self.resource,
                source_ip=client_ip(request),
                result="DENIED",
                severity="MEDIUM",
                metadata={"required_permission": required},
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"You are not authorized to {self.action} {self.resource}.",
            )
        return current_user
