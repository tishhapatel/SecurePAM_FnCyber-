"""
Recordings API Router — M12 Session Recording & Evidence Access.

Recordings are evidence of other users' privileged sessions, so access is
limited to holders of recordings:read (AUDITOR, ADMIN); there is no
per-owner scope. Every playback is audited (RECORDING_VIEWED), and the
file served must resolve inside RECORDING_STORAGE_PATH — a tampered
file_path (absolute elsewhere, "..", or a symlink out) is treated as not
found rather than served.
"""

import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, ConfigDict

from app.core.pagination import apply_sorting, paginate
from app.schemas.common import PaginatedResponse, PaginationParams
from app.core.audit import client_ip, write_audit_log
from app.core.config import settings
from app.core.deps import PermissionChecker, get_db
from app.models.recording import Recording
from app.models.user import User

router = APIRouter(prefix="/recordings", tags=["Recordings"])
_SORTABLE_COLUMNS = {
    "created_at",
    "file_size",
    "duration_seconds",
    "status",
    "recording_type",
}
_PLAYABLE_SUFFIXES = ("", ".m4v", ".mp4")


class RecordingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_id: uuid.UUID
    recording_type: str
    status: str
    file_size: Optional[int]
    duration_seconds: Optional[int]
    created_at: datetime


def _resolve_inside_storage(file_path: str) -> Optional[Path]:
    """The first existing playable variant of file_path that resolves inside
    the storage root, or None."""
    root = Path(settings.RECORDING_STORAGE_PATH).resolve()
    for suffix in _PLAYABLE_SUFFIXES:
        candidate = Path(f"{file_path}{suffix}").resolve()
        if candidate.is_relative_to(root) and candidate.is_file():
            return candidate
    return None



@router.get("/", response_model=PaginatedResponse[RecordingResponse])
async def list_recordings(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(PermissionChecker("recordings", "read")),
):
    """List recordings with pagination and allowlisted sorting."""
    query = select(Recording)

    query = apply_sorting(
        query,
        Recording,
        pagination.sort_by,
        pagination.sort_order,
        _SORTABLE_COLUMNS,
    )

    # Preserve newest-first ordering by default.
    if not pagination.sort_by or pagination.sort_by not in _SORTABLE_COLUMNS:
        query = query.order_by(Recording.created_at.desc())

    return await paginate(
        db, query, pagination, schema=RecordingResponse
    )



@router.get("/{recording_id}/stream")
async def stream_recording(
    recording_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(PermissionChecker("recordings", "read")),
):
    """Stream a session recording file for browser playback."""
    recording = await db.get(Recording, recording_id)
    if not recording or not recording.file_path or recording.status == "DELETED":
        raise HTTPException(status_code=404, detail="Recording not found")

    valid_path = _resolve_inside_storage(recording.file_path)
    if not valid_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recording video file not yet processed or not found on disk",
        )

    await write_audit_log(
        db, actor=current_user, action="RECORDING_VIEWED", target_type="recording",
        target_id=str(recording.id), session_id=recording.session_id,
        source_ip=client_ip(request), result="SUCCESS", severity="INFO",
    )
    await db.commit()
    return FileResponse(valid_path, media_type="video/mp4")
