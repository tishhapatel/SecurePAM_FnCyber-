"""
Audit API Router — M12 Structured Audit Logs & SIEM Export.

Read-only, and only for holders of audit:read (AUDITOR, ADMIN). Audit
rows describe every user's activity, so there is no "own rows" scope —
a user without audit:read gets 403 (and that denial is itself audited by
PermissionChecker).
"""

import uuid
from datetime import datetime

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, ConfigDict

from app.core.pagination import apply_sorting, paginate
from app.schemas.common import PaginatedResponse, PaginationParams
from app.core.deps import PermissionChecker, get_db
from app.models.audit import AuditLog
from app.models.user import User

router = APIRouter(prefix="/audit", tags=["Audit"])
_SORTABLE_COLUMNS = {
    "timestamp",
    "action",
    "severity",
    "result",
    "actor_username",
    "target_type",
}

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    event_id: str
    timestamp: datetime
    actor_username: str
    action: str
    target_type: Optional[str]
    target_id: Optional[str]
    result: str
    severity: str
    details: Optional[dict]



@router.get("/", response_model=PaginatedResponse[AuditLogResponse])
async def get_audit_logs(
    pagination: PaginationParams = Depends(),
    action: Optional[str] = Query(None, max_length=50),
    severity: Optional[str] = Query(None, max_length=10),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(PermissionChecker("audit", "read")),
):
    """Retrieve paginated audit logs with optional action and severity filters."""
    query = select(AuditLog)

    if action:
        query = query.where(AuditLog.action == action.upper())
    if severity:
        query = query.where(AuditLog.severity == severity.upper())

    query = apply_sorting(
        query,
        AuditLog,
        pagination.sort_by,
        pagination.sort_order,
        _SORTABLE_COLUMNS,
    )

    # Preserve newest-first ordering by default.
    if not pagination.sort_by or pagination.sort_by not in _SORTABLE_COLUMNS:
        query = query.order_by(AuditLog.timestamp.desc())

    return await paginate(
        db, query, pagination, schema=AuditLogResponse
    )
