"""
RBAC foundation: RoleChecker / PermissionChecker dependency behavior.

Written in Phase 2, before any endpoint used these — kept because testing
the mechanism directly (bypassing FastAPI's DI) is still useful in its own
right. Since Phase 3, the real thing is also covered end-to-end at the
HTTP level: see test_assets.py / test_applications.py / test_policies.py,
which is what the Phase 3 spec asked for ("test actual HTTP endpoints").

PermissionChecker.__call__ now takes `request` and `db` (it writes an
ACCESS_DENIED audit event on denial — see app/core/deps.py), so calling it
directly here requires passing both explicitly.
"""

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import PermissionChecker, RoleChecker
from app.models.user import User


async def _get_user(db_session: AsyncSession, username: str) -> User:
    result = await db_session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    assert user is not None, f"seed user {username!r} missing"
    return user


async def test_role_checker_allows_matching_role(db_session: AsyncSession):
    admin = await _get_user(db_session, "admin")
    checker = RoleChecker(["ADMIN"])
    result = await checker(current_user=admin)
    assert result is admin


async def test_role_checker_rejects_non_matching_role(db_session: AsyncSession):
    operator = await _get_user(db_session, "operator")
    checker = RoleChecker(["ADMIN", "APPROVER"])
    with pytest.raises(HTTPException) as exc_info:
        await checker(current_user=operator)
    assert exc_info.value.status_code == 403


async def test_permission_checker_allows_held_permission(db_session: AsyncSession):
    approver = await _get_user(db_session, "approver")
    checker = PermissionChecker("approvals", "approve")
    result = await checker(request=None, current_user=approver, db=db_session)
    assert result is approver


async def test_permission_checker_rejects_missing_permission(db_session: AsyncSession):
    operator = await _get_user(db_session, "operator")
    # Operators can create access requests but cannot approve them.
    checker = PermissionChecker("approvals", "approve")
    with pytest.raises(HTTPException) as exc_info:
        await checker(request=None, current_user=operator, db=db_session)
    assert exc_info.value.status_code == 403


async def test_admin_bypasses_explicit_permission_grants(db_session: AsyncSession):
    """ADMIN is granted every permission at seed time (see app/main.py), so
    this also covers the explicit 'ADMIN has all permissions' short-circuit
    in PermissionChecker."""
    admin = await _get_user(db_session, "admin")
    checker = PermissionChecker("vault", "manage")
    result = await checker(request=None, current_user=admin, db=db_session)
    assert result is admin


async def test_auditor_cannot_approve(db_session: AsyncSession):
    auditor = await _get_user(db_session, "auditor")
    checker = PermissionChecker("approvals", "approve")
    with pytest.raises(HTTPException) as exc_info:
        await checker(request=None, current_user=auditor, db=db_session)
    assert exc_info.value.status_code == 403

async def test_role_checker_rejects_inactive_role(db_session: AsyncSession):
    admin = await _get_user(db_session, "admin")
    admin_role = next(
        ur.role for ur in admin.roles
        if ur.role and ur.role.name == "ADMIN"
    )
    original_active = admin_role.is_active

    try:
        admin_role.is_active = False
        await db_session.flush()

        checker = RoleChecker(["ADMIN"])

        with pytest.raises(HTTPException) as exc_info:
            await checker(current_user=admin)

        assert exc_info.value.status_code == 403
    finally:
        admin_role.is_active = original_active
        await db_session.flush()


async def test_permission_checker_rejects_inactive_admin_role(
    db_session: AsyncSession,
):
    admin = await _get_user(db_session, "admin")
    admin_role = next(
        ur.role for ur in admin.roles
        if ur.role and ur.role.name == "ADMIN"
    )
    original_active = admin_role.is_active

    try:
        admin_role.is_active = False
        await db_session.flush()

        checker = PermissionChecker("vault", "manage")

        with pytest.raises(HTTPException) as exc_info:
            await checker(request=None, current_user=admin, db=db_session)

        assert exc_info.value.status_code == 403
    finally:
        admin_role.is_active = original_active
        await db_session.flush()
