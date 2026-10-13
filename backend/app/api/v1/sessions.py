"""
Sessions API Router — M9 RDP Gateway & Session Orchestration.

Authorization:
- list/detail: sessions:read sees every session; sessions:read_own sees
  only the caller's. Someone else's session is 404 (not 403) for an
  own-scope caller, matching access_requests.py, so its existence isn't
  confirmed.
- terminate: sessions:terminate may end any session; an owner may end
  their own. Anyone else is refused.
- RDP launch: sessions:create, then the caller's own ACTIVE access request
  for that RDP asset, a live JIT grant from JITService.validate() bound to
  that request, and a CredentialService checkout bound to the new session.
  Any failure marks the session FAILED; nothing is reported as started.
  The response never contains a credential or a filesystem path.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import apply_sorting, paginate
from app.schemas.common import PaginatedResponse, PaginationParams
from app.core.audit import client_ip, write_audit_log
from app.core.config import settings
from app.core.deps import PermissionChecker, get_db, user_has_permission
from app.core.security import generate_session_number
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.recording import Recording
from app.models.session import Session, SessionEvent
from app.models.user import User
from app.services.credential_service import (
    CheckoutRequest,
    CredentialAccessDenied,
    CredentialService,
    CredentialUnavailable,
)
from app.services.jit_service import JITService
from app.services.rdp_gateway import GatewayError, RDPGateway, get_rdp_gateway

router = APIRouter(prefix="/sessions", tags=["Sessions"])

LIVE_STATUSES = {"CREATED", "STARTING", "ACTIVE"}
_SESSION_STATUSES = {"CREATED", "STARTING", "ACTIVE", "TERMINATING", "COMPLETED", "FAILED", "EXPIRED"}
_SORTABLE_COLUMNS = {"created_at", "start_time", "end_time", "status", "protocol", "session_number"}
_jit = JITService()


def get_credential_service() -> CredentialService:
    return CredentialService()


class CreateRDPSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: uuid.UUID
    asset_id: uuid.UUID


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_number: str
    user_id: uuid.UUID
    asset_id: Optional[uuid.UUID]
    request_id: uuid.UUID
    protocol: str
    status: str
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    recording_id: Optional[uuid.UUID]


def _can_view_all(user: User) -> bool:
    return user_has_permission(user, "sessions", "read")


async def _get_visible_session_or_404(db: AsyncSession, session_id: uuid.UUID, user: User) -> Session:
    session = await db.get(Session, session_id)
    if session is None or (not _can_view_all(user) and session.user_id != user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    return session



@router.get("/", response_model=PaginatedResponse[SessionResponse])
async def list_sessions(
    pagination: PaginationParams = Depends(),
    status_filter: Optional[str] = Query(None, alias="status", max_length=20),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(
        PermissionChecker("sessions", "read", "read_own")
    ),
):
    """List sessions visible to the caller, with optional status filtering and pagination."""
    query = select(Session)

    # Preserve the existing ownership restriction.
    if not _can_view_all(current_user):
        query = query.where(Session.user_id == current_user.id)

    # Preserve existing status validation.
    if status_filter:
        normalized_status = status_filter.upper()
        if normalized_status not in _SESSION_STATUSES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Unknown session status",
            )
        query = query.where(Session.status == normalized_status)

    query = apply_sorting(
        query,
        Session,
        pagination.sort_by,
        pagination.sort_order,
        _SORTABLE_COLUMNS,
    )

    # Preserve newest-first ordering when sorting isn't allowlisted.
    if not pagination.sort_by or pagination.sort_by not in _SORTABLE_COLUMNS:
        query = query.order_by(Session.created_at.desc())

    return await paginate(
        db, query, pagination, schema=SessionResponse
    )



@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("sessions", "read", "read_own")),
):
    """Retrieve details for a single session."""
    return await _get_visible_session_or_404(db, session_id, current_user)


async def _fail_launch(
    db: AsyncSession, *, session: Session, recording: Optional[Recording], actor: User,
    reason: str, source_ip: Optional[str],
) -> None:
    now = datetime.now(timezone.utc)
    session.status = "FAILED"
    session.end_time = now
    if recording:
        recording.status = "FAILED"
    db.add(SessionEvent(session_id=session.id, event_type="SESSION_FAILED", timestamp=now, details={"reason": reason}))
    await write_audit_log(
        db, actor=actor, action="SESSION_LAUNCH_FAILED", target_type="asset", target_id=str(session.asset_id),
        request_id=session.request_id, session_id=session.id, source_ip=source_ip,
        result="FAILURE", severity="HIGH", metadata={"reason": reason, "protocol": session.protocol},
    )
    await db.commit()


@router.post("/rdp/launch", status_code=status.HTTP_201_CREATED)
async def launch_rdp_session(
    payload: CreateRDPSessionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("sessions", "create")),
    credentials: CredentialService = Depends(get_credential_service),
    gateway: RDPGateway = Depends(get_rdp_gateway),
):
    """
    Launch an RDP session via the gateway. The credential is checked out
    server-side and handed only to the gateway; the client receives the
    session identifiers and non-secret connection details.
    """
    source_ip = client_ip(request)

    asset = (await db.execute(
        select(Asset).where(Asset.id == payload.asset_id, Asset.is_deleted == False)
    )).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target asset not found")

    access_request = await db.get(AccessRequest, payload.request_id)
    if access_request is None or access_request.user_id != current_user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Access request not found")
    if access_request.asset_id != asset.id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Access request is for a different target")
    if asset.protocol != "RDP" or access_request.protocol != "RDP":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Target and request must both be RDP")

    async def deny(reason: str, detail: str):
        await write_audit_log(
            db, actor=current_user, action="SESSION_LAUNCH_DENIED", target_type="asset", target_id=str(asset.id),
            request_id=access_request.id, source_ip=source_ip, result="DENIED", severity="MEDIUM",
            metadata={"reason": reason, "protocol": "RDP"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail)

    if not asset.enabled or asset.status != "ACTIVE":
        await deny("ASSET_DISABLED", "This target is not available.")
    if access_request.status != "ACTIVE":
        await deny("ACCESS_REQUEST_NOT_ACTIVE", "This access request is not active.")

    grant = await _jit.validate(db, user_id=current_user.id, target_id=asset.id, protocol="RDP")
    if grant is None or grant.request_id != access_request.id:
        await deny("NO_VALID_JIT_GRANT", "No valid just-in-time grant for this request.")

    session = Session(
        session_number=generate_session_number(), user_id=current_user.id, asset_id=asset.id,
        request_id=access_request.id, jit_grant_id=grant.id, protocol="RDP", status="STARTING",
        source_ip=source_ip, risk_score=access_request.risk_score,
    )
    db.add(session)
    await db.flush()

    recording: Optional[Recording] = None
    if asset.recording_required or access_request.recording_required:
        recording = Recording(
            session_id=session.id, recording_type="VIDEO", status="PENDING",
            file_path=f"{settings.RECORDING_STORAGE_PATH}/session_{session.id}",
        )
        db.add(recording)
        await db.flush()
        session.recording_id = recording.id

    db.add(SessionEvent(session_id=session.id, event_type="SESSION_CREATED",
                        timestamp=datetime.now(timezone.utc), details={"protocol": "RDP"}))
    await db.commit()

    checkout = CheckoutRequest(
        user_id=current_user.id, access_request_id=access_request.id, jit_grant_id=grant.id,
        asset_id=asset.id, session_id=session.id, source_ip=source_ip,
    )
    try:
        async with credentials.checkout(db, checkout) as credential:
            connection = await gateway.prepare(session=session, asset=asset, credential=credential)
    except CredentialAccessDenied as exc:
        await _fail_launch(db, session=session, recording=recording, actor=current_user,
                           reason=exc.reason, source_ip=source_ip)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Credential access was denied for this session.")
    except CredentialUnavailable as exc:
        await _fail_launch(db, session=session, recording=recording, actor=current_user,
                           reason=exc.reason, source_ip=source_ip)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Credential provider unavailable; session not started.")
    except GatewayError:
        await _fail_launch(db, session=session, recording=recording, actor=current_user,
                           reason="GATEWAY_ERROR", source_ip=source_ip)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Session gateway could not start the session.")

    now = datetime.now(timezone.utc)
    session.status = "ACTIVE"
    session.start_time = now
    session.gateway_session_id = connection.gateway_session_id
    if recording:
        recording.status = "RECORDING"
    db.add(SessionEvent(session_id=session.id, event_type="SESSION_STARTED", timestamp=now,
                        details={"protocol": "RDP", "recording": recording is not None}))
    await write_audit_log(
        db, actor=current_user, action="SESSION_STARTED", target_type="asset", target_id=str(asset.id),
        request_id=access_request.id, session_id=session.id, source_ip=source_ip,
        result="SUCCESS", severity="INFO",
        metadata={"protocol": "RDP", "session_number": session.session_number,
                  "jit_grant_id": str(grant.id), "recording": recording is not None},
    )
    await db.commit()

    return {
        "session_id": str(session.id),
        "session_number": session.session_number,
        "status": session.status,
        "recording_id": str(recording.id) if recording else None,
        "connection": {"protocol": connection.protocol, "hostname": connection.hostname, "port": connection.port},
    }


@router.post("/{session_id}/terminate")
async def terminate_session(
    session_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("sessions", "terminate", "read", "read_own")),
):
    """Terminate a live session and finalize its recording and audit records."""
    session = await _get_visible_session_or_404(db, session_id, current_user)

    is_owner = session.user_id == current_user.id
    if not is_owner and not user_has_permission(current_user, "sessions", "terminate"):
        await write_audit_log(
            db, actor=current_user, action="ACCESS_DENIED", target_type="session", target_id=str(session.id),
            session_id=session.id, source_ip=client_ip(request), result="DENIED", severity="MEDIUM",
            metadata={"required_permission": "sessions:terminate"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not authorized to terminate this session.")

    if session.status not in LIVE_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Session is already {session.status}")

    now = datetime.now(timezone.utc)
    session.status = "COMPLETED"
    session.end_time = now

    if session.recording_id:
        recording = await db.get(Recording, session.recording_id)
        if recording and recording.status in ("PENDING", "RECORDING"):
            recording.status = "COMPLETED"

    db.add(SessionEvent(session_id=session.id, event_type="SESSION_TERMINATED", timestamp=now,
                        details={"by_owner": is_owner}))
    await write_audit_log(
        db, actor=current_user, action="SESSION_TERMINATED", target_type="session", target_id=str(session.id),
        request_id=session.request_id, session_id=session.id, source_ip=client_ip(request),
        result="SUCCESS", severity="INFO", metadata={"by_owner": is_owner},
    )
    await db.commit()

    return {"message": "Session terminated successfully", "session_id": str(session_id)}
