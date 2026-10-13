"""
Session model — unified session abstraction across all protocols.

All session types (RDP, SSH, Web) use the same model.
This ensures consistent lifecycle management, audit, and recording.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDMixin


class Session(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sessions"

    # Human-readable identifier
    session_number: Mapped[str] = mapped_column(
        String(20), unique=True, nullable=False, index=True,
        comment="Human-readable ID like SES-A1B2C"
    )

    # User
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )

    # Target — either asset OR application
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    application_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Protocol
    protocol: Mapped[str] = mapped_column(
        String(10), nullable=False, index=True,
        comment="RDP, SSH, HTTP, HTTPS"
    )

    # Status
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="CREATED", index=True,
        comment="CREATED, STARTING, ACTIVE, TERMINATING, COMPLETED, FAILED, EXPIRED"
    )

    # Time tracking
    start_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    end_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Context
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # References
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("access_requests.id"), nullable=False, index=True
    )
    jit_grant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jit_grants.id", ondelete="SET NULL"), nullable=True
    )
    # use_alter: recordings.session_id also references sessions.id, so this
    # FK is applied via ALTER TABLE after both tables exist, breaking the cycle.
    recording_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("recordings.id", ondelete="SET NULL", use_alter=True, name="fk_sessions_recording_id"),
        nullable=True,
    )

    # External gateway reference
    gateway_session_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True,
        comment="Guacamole connection ID or similar"
    )

    # Additional metadata
    metadata_: Mapped[Optional[dict]] = mapped_column(
        "metadata", JSON, nullable=True
    )

    def __repr__(self) -> str:
        return f"<Session {self.session_number} ({self.protocol}, {self.status})>"


class SessionEvent(Base, UUIDMixin):
    """Individual events within a session timeline."""
    __tablename__ = "session_events"

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="SESSION_CREATED, RECORDING_STARTED, etc."
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<SessionEvent {self.event_type} @ {self.timestamp}>"
