"""
Dashboard endpoints — real data from the database.

All statistics are computed server-side.
No hard-coded numbers.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_active_user, get_db
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.recording import Recording
from app.models.audit import AuditLog
from app.models.jit_grant import JITGrant
from app.models.session import Session
from app.models.user import User
from app.schemas.common import DashboardActivity, DashboardSummary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get dashboard summary statistics from real data."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Active sessions
    active_sessions = await db.scalar(
        select(func.count()).select_from(Session).where(
            Session.status.in_(["ACTIVE", "STARTING"])
        )
    ) or 0

    # Requests awaiting human approval
    pending_requests = await db.scalar(
        select(func.count()).select_from(AccessRequest).where(
            AccessRequest.status == "APPROVAL_REQUIRED"
        )
    ) or 0

    # High risk sessions (risk_score >= 60)
    high_risk_sessions = await db.scalar(
        select(func.count()).select_from(Session).where(
            and_(
                Session.status == "ACTIVE",
                Session.risk_score >= 60,
            )
        )
    ) or 0

    # Today's sessions
    today_sessions = await db.scalar(
        select(func.count()).select_from(Session).where(
            Session.created_at >= today_start
        )
    ) or 0

    # Failed MFA attempts (from audit log)
    failed_mfa = await db.scalar(
        select(func.count()).select_from(AuditLog).where(
            and_(
                AuditLog.action == "MFA_FAILURE",
                AuditLog.timestamp >= today_start,
            )
        )
    ) or 0

    # Active JIT grants
    jit_active = await db.scalar(
        select(func.count()).select_from(JITGrant).where(
            and_(
                JITGrant.status == "ACTIVE",
                JITGrant.expires_at > now,
            )
        )
    ) or 0

    # Registered assets
    registered_assets = await db.scalar(
        select(func.count()).select_from(Asset).where(
            Asset.is_deleted == False
        )
    ) or 0

    # Recording storage (exclude deleted recordings)
    recording_bytes = await db.scalar(
        select(func.coalesce(func.sum(Recording.file_size), 0)).where(
            Recording.status != "DELETED",
            Recording.file_size.is_not(None),
        )
    ) or 0

    recording_storage_mb = recording_bytes / (1024 * 1024)

    return DashboardSummary(
        active_sessions=active_sessions,
        pending_requests=pending_requests,
        high_risk_sessions=high_risk_sessions,
        today_sessions=today_sessions,
        failed_mfa_attempts=failed_mfa,
        jit_grants_active=jit_active,
        registered_assets=registered_assets,
        recording_storage_mb=recording_storage_mb,
    )


@router.get("/activity", response_model=list[DashboardActivity])
async def get_recent_activity(
    limit: int = Query(default=20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get recent security activity from audit logs."""
    result = await db.execute(
        select(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
    )
    events = result.scalars().all()

    return [
        DashboardActivity(
            event_id=event.event_id,
            timestamp=event.timestamp,
            severity=event.severity,
            action=event.action,
            actor=event.actor_username,
            target=event.target_id,
            details=event.details.get("message") if event.details else None,
        )
        for event in events
    ]
