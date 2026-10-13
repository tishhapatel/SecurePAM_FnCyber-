"""
JITService — the single authoritative source of truth for "is this
just-in-time grant currently valid?"

This is explicitly NOT a UI countdown. Every future gateway integration
(Guacamole/RDP, SSH, Web) must call `validate()` before establishing a
session; none of them — and no frontend timer — gets to decide for
itself whether access is still live. `grant()` is the only place an
expiry is ever computed, and it always clamps to the policy/decision
maximum — a caller cannot hand it an arbitrary duration and expect it
honored past that ceiling (see app/services/access_decision.py, which is
the only caller of `grant()`).
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session, SessionEvent

# Session states that still represent live access (see app/models/session.py).
LIVE_SESSION_STATUSES = ("CREATED", "STARTING", "ACTIVE", "TERMINATING")


class JITService:
    async def grant(
        self,
        db: AsyncSession,
        *,
        request_id: UUID,
        user_id: UUID,
        asset_id: Optional[UUID],
        application_id: Optional[UUID],
        protocol: str,
        duration_minutes: int,
        created_by: Optional[UUID],
    ) -> JITGrant:
        """Create a JIT grant bounded by its originating access request."""
        from app.models.access_request import AccessRequest

        if isinstance(duration_minutes, bool) or not isinstance(duration_minutes, int):
            raise ValueError("JIT duration must be an integer number of minutes.")

        if duration_minutes <= 0:
            raise ValueError("JIT duration must be greater than zero.")

        result = await db.execute(
            select(AccessRequest).where(AccessRequest.id == request_id)
        )
        access_request = result.scalar_one_or_none()

        if access_request is None:
            raise ValueError("Cannot grant JIT access without an existing request.")

        if (
            access_request.user_id != user_id
            or access_request.asset_id != asset_id
            or access_request.application_id != application_id
            or access_request.protocol != protocol
        ):
            raise ValueError("JIT grant details must match the originating access request.")

        requested_duration = access_request.requested_duration
        if requested_duration <= 0:
            raise ValueError("The access request has an invalid duration.")

        # Never grant more time than the request originally asked for.
        effective_duration = min(duration_minutes, requested_duration)

        # Enforce the policy decision snapshot when a maximum was recorded.
        decision = access_request.policy_decision or {}
        max_duration = decision.get("max_duration")

        if max_duration is not None:
            if (
                isinstance(max_duration, bool)
                or not isinstance(max_duration, int)
                or max_duration <= 0
            ):
                raise ValueError("The policy decision contains an invalid maximum duration.")

            effective_duration = min(effective_duration, max_duration)

        now = datetime.now(timezone.utc)
        grant = JITGrant(
            request_id=request_id,
            user_id=user_id,
            asset_id=asset_id,
            application_id=application_id,
            protocol=protocol,
            granted_at=now,
            expires_at=now + timedelta(minutes=effective_duration),
            status="ACTIVE",
            created_by=created_by,
        )
        db.add(grant)
        await db.flush()
        return grant


    def is_active(self, grant: JITGrant) -> bool:
        """Pure check against an already-loaded grant — no DB access, no
        side effects. Use `validate()` instead when you need the
        authoritative, up-to-date answer (it also flips a stale ACTIVE
        row to EXPIRED)."""
        return grant.status == "ACTIVE" and grant.expires_at > datetime.now(timezone.utc)

    async def validate(
        self, db: AsyncSession, *, user_id: UUID, target_id: UUID, protocol: str
    ) -> Optional[JITGrant]:
        """
        Returns the live JITGrant if `user_id` currently holds valid JIT
        access to `target_id` over `protocol`, else None. `target_id` is
        matched against whichever of asset_id/application_id is set on
        the grant — callers don't need to know which kind of target it is.

        Opportunistically flips a found-but-expired ACTIVE row to EXPIRED
        (and writes nothing further — JIT_EXPIRED auditing is the caller's
        job, since only it knows the request context) so stale grants
        don't linger as ACTIVE purely because nothing looked at them
        since they lapsed.
        """
        result = await db.execute(
            select(JITGrant)
            .where(
                JITGrant.user_id == user_id,
                JITGrant.protocol == protocol,
                or_(JITGrant.asset_id == target_id, JITGrant.application_id == target_id),
                JITGrant.status == "ACTIVE",
            )
            .order_by(JITGrant.granted_at.desc())
        )
        grant = result.scalars().first()
        if grant is None:
            return None

        if grant.expires_at <= datetime.now(timezone.utc):
            grant.status = "EXPIRED"
            await self._end_bound_sessions(db, grant, "JIT_EXPIRED")
            await db.flush()
            return None

        return grant

    async def revoke(self, db: AsyncSession, grant: JITGrant) -> JITGrant:
        if grant.status == "ACTIVE":
            grant.status = "REVOKED"
            grant.revoked_at = datetime.now(timezone.utc)
            await self._end_bound_sessions(db, grant, "JIT_REVOKED")
            await db.flush()
        return grant

    async def expire(self, db: AsyncSession, grant: JITGrant) -> JITGrant:
        if grant.status == "ACTIVE":
            grant.status = "EXPIRED"
            await self._end_bound_sessions(db, grant, "JIT_EXPIRED")
            await db.flush()
        return grant

    async def _end_bound_sessions(self, db: AsyncSession, grant: JITGrant, reason: str) -> int:
        """A grant that stops being live takes every live session it
        authorized with it — a session must never outlast its JIT access.
        Marks them EXPIRED, finalizes in-progress recordings, and records a
        SessionEvent. The gateway (once integrated) must also tear down the
        actual connection; this is the authoritative state it reads."""
        result = await db.execute(
            select(Session).where(Session.jit_grant_id == grant.id, Session.status.in_(LIVE_SESSION_STATUSES))
        )
        sessions = result.scalars().all()
        now = datetime.now(timezone.utc)
        for session in sessions:
            session.status = "EXPIRED"
            session.end_time = now
            db.add(SessionEvent(session_id=session.id, event_type="SESSION_ENDED_BY_GRANT", timestamp=now,
                                details={"reason": reason, "jit_grant_id": str(grant.id)}))
            if session.recording_id:
                recording = await db.get(Recording, session.recording_id)
                if recording and recording.status == "RECORDING":
                    recording.status = "COMPLETED"
        return len(sessions)
