"""SQLAlchemy 2.0 policy store: versioned, append-only history, audited writes.

Requires the optional `db` extra (SQLAlchemy). Authorization of WHO may publish policies is the
backend's job (pass the authenticated actor); every write calls `audit_sink` BEFORE commit, so a
failed audit write rolls the change back (no unaudited policy change).
"""
from __future__ import annotations
from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable, Optional
from sqlalchemy import JSON, Boolean, DateTime, Integer, String, UniqueConstraint, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from .models import Policy, PolicyConfigurationError
from .repository import PolicyRepository, policy_from_record, policy_to_record
from .validation import validate_policy


class Base(DeclarativeBase):
    pass


class PolicyRow(Base):
    """One row per policy VERSION. Rows are never updated except `is_current`."""
    # Not "policies": the backend's Alembic schema already owns that table.
    __tablename__ = "policy_engine_policies"
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_engine_policy_version"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    definition: Mapped[dict] = mapped_column(JSON)
    changed_by: Mapped[str] = mapped_column(String(128))
    change_note: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


AuditSink = Callable[[dict], None]


class SqlAlchemyPolicyRepository(PolicyRepository):
    def __init__(self, session_factory: Callable[[], Session], audit_sink: Optional[AuditSink] = None):
        self._sf = session_factory
        self._audit = audit_sink

    def list_active(self) -> list[Policy]:
        with self._sf() as s:
            rows = s.scalars(select(PolicyRow).where(PolicyRow.is_current.is_(True), PolicyRow.enabled.is_(True))
                             .order_by(PolicyRow.policy_id)).all()
            return [policy_from_record(r.definition) for r in rows]

    def list_current(self) -> list[Policy]:
        """Current version of every policy, including disabled ones (for admin views)."""
        with self._sf() as s:
            rows = s.scalars(select(PolicyRow).where(PolicyRow.is_current.is_(True))
                             .order_by(PolicyRow.policy_id)).all()
            return [policy_from_record(r.definition) for r in rows]

    def history(self, policy_id: str) -> list[dict]:
        with self._sf() as s:
            rows = s.scalars(select(PolicyRow).where(PolicyRow.policy_id == policy_id)
                             .order_by(PolicyRow.version)).all()
            return [{"version": r.version, "enabled": r.enabled, "changed_by": r.changed_by,
                     "change_note": r.change_note, "created_at": r.created_at.isoformat()} for r in rows]

    def publish(self, policy: Policy, actor: str, change_note: str = "") -> Policy:
        """Store `policy` as the next version (version number is assigned here, not by the caller)."""
        if not actor or not isinstance(actor, str):
            raise PolicyConfigurationError("An authenticated actor is required to change policies")
        return self._write_version(policy, actor, change_note, "policy.published")

    def disable(self, policy_id: str, actor: str, change_note: str = "") -> Policy:
        """Disable by writing a new, disabled version (history is preserved)."""
        if not actor or not isinstance(actor, str):
            raise PolicyConfigurationError("An authenticated actor is required to change policies")
        with self._sf() as s:
            current = s.scalars(select(PolicyRow).where(PolicyRow.policy_id == policy_id,
                                                        PolicyRow.is_current.is_(True))).first()
            if current is None:
                raise KeyError(policy_id)
            base = policy_from_record(current.definition)
        return self._write_version(replace(base, enabled=False), actor, change_note, "policy.disabled")

    def _write_version(self, policy: Policy, actor: str, note: str, event: str) -> Policy:
        with self._sf() as s:
            try:
                latest = s.scalars(select(PolicyRow).where(PolicyRow.policy_id == policy.policy_id)
                                   .order_by(PolicyRow.version.desc())).first()
                new = replace(policy, version=(latest.version + 1) if latest else 1)
                validate_policy(new)
                now = datetime.now(timezone.utc)
                if latest is not None:
                    latest.is_current = False
                s.add(PolicyRow(policy_id=new.policy_id, version=new.version, name=new.name,
                                enabled=new.enabled, is_current=True, definition=policy_to_record(new),
                                changed_by=actor, change_note=note[:500], created_at=now))
                if self._audit:  # before commit: if auditing fails the change is rolled back
                    self._audit({"event": event, "actor": actor, "policy_id": new.policy_id,
                                 "version": new.version, "enabled": new.enabled, "timestamp": now.isoformat()})
                s.commit()
                return new
            except Exception:
                s.rollback()
                raise
