"""
Application management endpoints.

SECURITY: there is no /proxy?url=<...> here, and never will be — see
app/schemas/applications.py's module docstring. `target_url` is always
computed server-side from a validated hostname/port/protocol
(app/core/ssrf.py), both on create and whenever those fields change on
update, so an admin can't register (even by mistake) a target that fails
SSRF validation.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.gateway import (
    remove_app_upstream_config,
    trigger_nginx_reload,
    write_app_upstream_config,
)
from app.core.audit import client_ip, write_audit_log
from app.core.deps import PermissionChecker, get_db
from app.core.pagination import apply_sorting, paginate
from app.core.ssrf import SSRFValidationError, validate_application_target
from app.models.application import Application
from app.models.session import Session as SessionModel
from app.models.user import User
from app.schemas.applications import ApplicationCreate, ApplicationOut, ApplicationUpdate
from app.schemas.common import PaginatedResponse, PaginationParams

router = APIRouter(prefix="/applications", tags=["applications"])

_SORTABLE_COLUMNS = {
    "name", "hostname", "environment", "criticality", "access_mode",
    "created_at", "updated_at",
}
_ACTIVE_SESSION_STATUSES = ("CREATED", "STARTING", "ACTIVE", "TERMINATING")


def _build_target_url(hostname: str, port: int, protocol: str) -> str:
    return f"{protocol.lower()}://{hostname}:{port}"


def _validate_or_422(hostname: str, port: int, protocol: str) -> None:
    try:
        validate_application_target(hostname, port, protocol)
    except SSRFValidationError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))


async def _get_application_or_404(db: AsyncSession, application_id: UUID) -> Application:
    result = await db.execute(
        select(Application).where(Application.id == application_id, Application.is_deleted == False)
    )
    application = result.scalar_one_or_none()
    if not application:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application not found")
    return application


@router.get("", response_model=PaginatedResponse[ApplicationOut])
async def list_applications(
    pagination: PaginationParams = Depends(),
    environment: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    access_mode: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    search: Optional[str] = Query(None, max_length=255, description="Matches name or hostname"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("applications", "read")),
):
    query = select(Application).where(Application.is_deleted == False)

    if environment:
        query = query.where(Application.environment == environment)
    if criticality:
        query = query.where(Application.criticality == criticality)
    if access_mode:
        query = query.where(Application.access_mode == access_mode)
    if enabled is not None:
        query = query.where(Application.enabled == enabled)
    if search:
        like = f"%{search}%"
        query = query.where(or_(Application.name.ilike(like), Application.hostname.ilike(like)))

    query = apply_sorting(query, Application, pagination.sort_by, pagination.sort_order, _SORTABLE_COLUMNS)
    return await paginate(db, query, pagination, schema=ApplicationOut)


@router.post("", response_model=ApplicationOut, status_code=status.HTTP_201_CREATED)
async def create_application(
    body: ApplicationCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("applications", "create")),
):
    _validate_or_422(body.hostname, body.port, body.protocol)

    application = Application(
        **body.model_dump(),
        target_url=_build_target_url(body.hostname, body.port, body.protocol),
        created_by=current_user.id,
        updated_by=current_user.id,
    )
    db.add(application)
    await db.flush()

    await write_audit_log(
        db,
        actor=current_user,
        action="APPLICATION_CREATED",
        target_type="application",
        target_id=str(application.id),
        source_ip=client_ip(request),
        metadata={"name": application.name, "hostname": application.hostname},
    )
    await db.commit()
    await db.refresh(application)

    # Gateway upstream configuration synchronization
    if application.enabled and application.status == "ACTIVE" and application.access_mode == "STANDARD_PROXY":
        await write_app_upstream_config(application)
        await trigger_nginx_reload()

    return application


@router.get("/{application_id}", response_model=ApplicationOut)
async def get_application(
    application_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("applications", "read")),
):
    return await _get_application_or_404(db, application_id)


@router.patch("/{application_id}", response_model=ApplicationOut)
async def update_application(
    application_id: UUID,
    body: ApplicationUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("applications", "update")),
):
    application = await _get_application_or_404(db, application_id)

    changes = body.model_dump(exclude_unset=True)

    # Re-resolve the effective hostname/port/protocol (existing value for
    # anything not in this PATCH) and re-validate + re-derive target_url
    # whenever any of the three actually changed.
    if {"hostname", "port", "protocol"} & changes.keys():
        hostname = changes.get("hostname", application.hostname)
        port = changes.get("port", application.port)
        protocol = changes.get("protocol", application.protocol)
        _validate_or_422(hostname, port, protocol)
        changes["target_url"] = _build_target_url(hostname, port, protocol)

    for field, value in changes.items():
        setattr(application, field, value)
    application.updated_by = current_user.id
    await db.flush()

    await write_audit_log(
        db,
        actor=current_user,
        action="APPLICATION_UPDATED",
        target_type="application",
        target_id=str(application.id),
        source_ip=client_ip(request),
        metadata={"changed_fields": sorted(changes.keys())},
    )
    await db.commit()
    await db.refresh(application)

    # Gateway upstream configuration synchronization
    target_affecting = {"hostname", "port", "protocol", "enabled", "status", "access_mode", "is_deleted"}
    if target_affecting & changes.keys():
        if (
            application.enabled
            and application.status == "ACTIVE"
            and not application.is_deleted
            and application.access_mode == "STANDARD_PROXY"
        ):
            await write_app_upstream_config(application)
            await trigger_nginx_reload()
        else:
            await remove_app_upstream_config(application.id)
            await trigger_nginx_reload()

    return application


@router.delete("/{application_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_application(
    application_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("applications", "delete")),
):
    application = await _get_application_or_404(db, application_id)

    active_sessions = await db.scalar(
        select(func.count()).select_from(SessionModel).where(
            SessionModel.application_id == application.id,
            SessionModel.status.in_(_ACTIVE_SESSION_STATUSES),
        )
    )
    if active_sessions:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot delete this application: {active_sessions} active session(s) still reference it.",
        )

    application.is_deleted = True
    application.enabled = False
    application.updated_by = current_user.id
    await db.flush()

    await write_audit_log(
        db,
        actor=current_user,
        action="APPLICATION_DELETED",
        target_type="application",
        target_id=str(application.id),
        source_ip=client_ip(request),
        metadata={"name": application.name},
    )
    await db.commit()

    # Gateway upstream configuration synchronization
    await remove_app_upstream_config(application.id)
    await trigger_nginx_reload()
