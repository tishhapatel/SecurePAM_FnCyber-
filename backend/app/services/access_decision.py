"""
AccessDecisionService — the one place the full access-request workflow
runs:

  1. Authenticate (done by the caller, before this service is invoked)
  2. Load + validate the target (exists, enabled, exactly one of
     asset_id/application_id, protocol matches the target's own protocol)
  3. Load the target's policy (if any)
  4. Evaluate policy (app/policies/evaluator.py)
  5. Evaluate risk (app/risk/engine.py) — kept separate from policy on
     purpose; this service is what combines them
  6. Apply the decision matrix (policy denies -> DENIED, always; CRITICAL
     risk -> DENIED without a policy, else elevated APPROVAL_REQUIRED;
     HIGH -> always APPROVAL_REQUIRED; LOW/MEDIUM -> whatever the policy
     says)
  7. Persist the AccessRequest (+ RiskEvent, + Approval if one is needed)
  8. Write every audit event the decision implies

None of this is duplicated in app/api/v1/access_requests.py — the route
only translates HTTP <-> this service's calls and exceptions.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Set, Union
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import write_audit_log
from app.core.config import settings
from app.core.security import generate_request_number
from app.models.access_request import AccessRequest
from app.models.application import Application
from app.models.approval import Approval
from app.models.asset import Asset
from app.models.audit import RiskEvent
from app.models.policy import Policy
from app.models.user import User
from app.policies import PolicyDecision, PolicyEvaluator
from app.risk import RiskConfiguration, RiskContext, RiskResult, evaluate_risk
from app.services.jit_service import JITService

# How long a request sits in the approval queue before it lapses on its
# own if nobody acts on it. Project-specific constant, not derived from
# anything external.
APPROVAL_EXPIRY_HOURS = 24

ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    "PENDING": {"APPROVAL_REQUIRED", "APPROVED", "DENIED", "CANCELLED", "EXPIRED"},
    "APPROVAL_REQUIRED": {"APPROVED", "REJECTED", "EXPIRED", "CANCELLED"},
    "APPROVED": {"ACTIVE", "EXPIRED"},
    "ACTIVE": {"EXPIRED"},
    "REJECTED": set(),
    "DENIED": set(),
    "CANCELLED": set(),
    "EXPIRED": set(),
}


class InvalidTargetError(ValueError):
    """Structurally invalid request (bad target/protocol/XOR) — route maps this to 422."""


class InvalidTransitionError(Exception):
    """Disallowed status transition — route maps this to 409."""

    def __init__(self, current: str, attempted: str):
        self.current = current
        self.attempted = attempted
        super().__init__(f"Cannot transition from {current} to {attempted}")


class SelfApprovalError(Exception):
    """A requester tried to approve/reject their own request — route maps this to 403."""


def check_transition(current_status: str, new_status: str) -> None:
    if new_status not in ALLOWED_TRANSITIONS.get(current_status, set()):
        raise InvalidTransitionError(current_status, new_status)


def _target_type(asset_id: Optional[UUID]) -> str:
    return "asset" if asset_id else "application"


class AccessDecisionService:
    def __init__(self, risk_configuration: Optional[RiskConfiguration] = None):
        self._policy_evaluator = PolicyEvaluator()
        self._jit = JITService()
        self._risk_configuration = risk_configuration or RiskConfiguration.from_settings(settings)

    # --- target loading / validation ---

    async def _load_target(
        self, db: AsyncSession, asset_id: Optional[UUID], application_id: Optional[UUID]
    ) -> Union[Asset, Application]:
        if bool(asset_id) == bool(application_id):
            raise InvalidTargetError("Exactly one of asset_id or application_id must be provided.")

        if asset_id:
            result = await db.execute(select(Asset).where(Asset.id == asset_id, Asset.is_deleted == False))
            target: Optional[Union[Asset, Application]] = result.scalar_one_or_none()
            if target is None:
                raise InvalidTargetError("Asset not found.")
        else:
            result = await db.execute(
                select(Application).where(Application.id == application_id, Application.is_deleted == False)
            )
            target = result.scalar_one_or_none()
            if target is None:
                raise InvalidTargetError("Application not found.")

        if not target.enabled:
            raise InvalidTargetError("This target is disabled and cannot be requested.")

        return target

    async def _load_policy(self, db: AsyncSession, policy_id: Optional[UUID]) -> Optional[Policy]:
        if not policy_id:
            return None
        result = await db.execute(select(Policy).where(Policy.id == policy_id, Policy.is_deleted == False))
        return result.scalar_one_or_none()

    # --- the decision matrix (Phase 4 spec, section 6) ---

    def _decide(self, policy_decision: PolicyDecision, risk_result: RiskResult) -> tuple[str, list[str]]:
        """Returns (final_status, decision_reasons). Policy is authoritative
        for an explicit deny; risk can only ESCALATE scrutiny, never
        silently grant access a policy didn't already permit."""
        if not policy_decision.allowed:
            return "DENIED", ["Policy denies this request"]

        if risk_result.level == "CRITICAL":
            if policy_decision.policy_id is None:
                return "DENIED", ["Risk level CRITICAL and no policy is assigned to vouch for this target"]
            return "APPROVAL_REQUIRED", ["Risk level CRITICAL requires elevated (human) approval"]

        if risk_result.level == "HIGH":
            return "APPROVAL_REQUIRED", ["Risk level HIGH always requires approval, regardless of policy"]

        # LOW / MEDIUM: fully policy-dependent.
        if policy_decision.approval_required or not policy_decision.auto_approve:
            return "APPROVAL_REQUIRED", [f"Risk level {risk_result.level}; policy requires human approval"]
        return "APPROVED", [f"Risk level {risk_result.level} and policy permits automatic approval"]

    # --- create ---

    async def create_request(
        self,
        db: AsyncSession,
        *,
        requester: User,
        asset_id: Optional[UUID],
        application_id: Optional[UUID],
        protocol: str,
        reason: str,
        requested_duration: int,
        source_ip: Optional[str],
        user_agent: Optional[str],
        now: Optional[datetime] = None,
    ) -> AccessRequest:
        """`now` is injectable (tests only — the API route never passes it)
        so time-dependent factors (business hours) can be tested
        deterministically instead of depending on wall-clock time at
        test-run time. Defaults to the real current time in production."""
        target = await self._load_target(db, asset_id, application_id)

        if protocol != target.protocol:
            raise InvalidTargetError(
                f"Protocol '{protocol}' does not match this target's configured protocol ('{target.protocol}')."
            )

        policy = await self._load_policy(db, target.policy_id)
        now = now or datetime.now(timezone.utc)

        policy_decision = self._policy_evaluator.evaluate_access(
            user=requester, target=target, policy=policy, protocol=protocol,
            requested_duration=requested_duration, now=now,
        )

        prior_count = await db.scalar(
            select(func.count()).select_from(AccessRequest).where(AccessRequest.user_id == requester.id)
        )
        risk_result = evaluate_risk(
            user=requester, target=target, requested_duration=requested_duration,
            context=RiskContext(now=now, source_ip=source_ip, prior_request_count=prior_count),
            configuration=self._risk_configuration,
        )

        final_status, decision_reasons = self._decide(policy_decision, risk_result)

        access_request = AccessRequest(
            request_number=generate_request_number(),
            user_id=requester.id,
            asset_id=asset_id,
            application_id=application_id,
            protocol=protocol,
            reason=reason,
            requested_duration=requested_duration,
            status=final_status,
            risk_score=risk_result.score,
            risk_level=risk_result.level,
            risk_factors=risk_result.to_dict()["factors"],
            policy_decision=policy_decision.to_dict(),
            policy_id=policy_decision.policy_id,
            approval_required=(final_status == "APPROVAL_REQUIRED"),
            jit_required=policy_decision.jit_required,
            mfa_required=policy_decision.mfa_required,
            recording_required=policy_decision.recording_required,
            source_ip=source_ip,
            user_agent=user_agent,
        )

        if final_status == "APPROVAL_REQUIRED":
            access_request.expires_at = now + timedelta(hours=APPROVAL_EXPIRY_HOURS)
        else:
            access_request.decided_at = now  # automatic decision — decided_by stays null

        db.add(access_request)
        await db.flush()

        db.add(RiskEvent(
            request_id=access_request.id,
            user_id=requester.id,
            risk_score=risk_result.score,
            risk_level=risk_result.level,
            risk_factors=risk_result.to_dict()["factors"],
            evaluated_at=now,
        ))

        audit_kwargs = dict(
            target_type=_target_type(asset_id),
            target_id=str(asset_id or application_id),
            request_id=access_request.id,
            source_ip=source_ip,
        )
        await write_audit_log(
            db, actor=requester, action="ACCESS_REQUEST_CREATED", result="SUCCESS", severity="INFO",
            metadata={"protocol": protocol, "requested_duration": requested_duration}, **audit_kwargs,
        )
        await write_audit_log(
            db, actor=requester, action="POLICY_EVALUATED",
            result="SUCCESS" if policy_decision.allowed else "DENIED", severity="INFO",
            metadata={"policy_id": policy_decision.to_dict()["policy_id"], "reasons": policy_decision.reasons},
            **audit_kwargs,
        )
        await write_audit_log(
            db, actor=requester, action="RISK_EVALUATED", result="SUCCESS", severity="INFO",
            metadata={"score": risk_result.score, "level": risk_result.level}, **audit_kwargs,
        )

        if final_status == "DENIED":
            await write_audit_log(
                db, actor=requester, action="ACCESS_DENIED", result="DENIED", severity="HIGH",
                metadata={"reasons": decision_reasons}, **audit_kwargs,
            )
        elif final_status == "APPROVAL_REQUIRED":
            db.add(Approval(request_id=access_request.id, status="PENDING"))
            await write_audit_log(
                db, actor=requester, action="APPROVAL_REQUESTED", result="SUCCESS", severity="MEDIUM",
                metadata={"reasons": decision_reasons}, **audit_kwargs,
            )
        elif final_status == "APPROVED":
            await write_audit_log(
                db, actor=requester, action="ACCESS_ALLOWED", result="SUCCESS", severity="INFO",
                metadata={"reasons": decision_reasons}, **audit_kwargs,
            )
            jit = await self._jit.grant(
                db, request_id=access_request.id, user_id=requester.id, asset_id=asset_id,
                application_id=application_id, protocol=protocol,
                duration_minutes=policy_decision.max_duration, created_by=None,
            )
            access_request.status = "ACTIVE"
            await write_audit_log(
                db, actor=requester, action="JIT_GRANTED", result="SUCCESS", severity="INFO",
                metadata={"expires_at": jit.expires_at.isoformat(), "duration_minutes": policy_decision.max_duration},
                **audit_kwargs,
            )

        await db.commit()
        await db.refresh(access_request)
        return access_request

    # --- cancel ---

    async def cancel_request(self, db: AsyncSession, access_request: AccessRequest, actor: User) -> AccessRequest:
        check_transition(access_request.status, "CANCELLED")
        access_request.status = "CANCELLED"
        await write_audit_log(
            db, actor=actor, action="ACCESS_REQUEST_CANCELLED",
            target_type=_target_type(access_request.asset_id), target_id=str(access_request.asset_id or access_request.application_id),
            request_id=access_request.id, result="SUCCESS", severity="INFO",
        )
        await db.commit()
        await db.refresh(access_request)
        return access_request

    # --- approve / reject ---

    async def approve(
        self, db: AsyncSession, *, approval: Approval, access_request: AccessRequest,
        approver: User, comment: Optional[str], source_ip: Optional[str],
    ) -> AccessRequest:
        if approval.status != "PENDING":
            raise InvalidTransitionError(approval.status, "APPROVED")

        now = datetime.now(timezone.utc)

        # A request cannot be approved after its approval deadline.
        if access_request.expires_at is not None:
            deadline = access_request.expires_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
            if deadline <= now:
                raise InvalidTransitionError(
                    access_request.status, "EXPIRED"
                )

        if approver.id == access_request.user_id:
            raise SelfApprovalError(
                "A requester cannot approve their own access request."
            )

        check_transition(access_request.status, "APPROVED")

        approval.status = "APPROVED"
        approval.approver_id = approver.id
        approval.comment = comment
        approval.decided_at = now
        approval.source_ip = source_ip

        access_request.status = "APPROVED"
        access_request.decided_at = now
        access_request.decided_by = approver.id
        await db.flush()

        audit_kwargs = dict(
            target_type=_target_type(access_request.asset_id),
            target_id=str(
                access_request.asset_id or access_request.application_id
            ),
            request_id=access_request.id,
            source_ip=source_ip,
        )
        await write_audit_log(
            db, actor=approver, action="APPROVAL_GRANTED",
            result="SUCCESS", severity="INFO",
            metadata={"comment": comment}, **audit_kwargs,
        )

        duration = access_request.requested_duration
        if (
            access_request.policy_decision
            and access_request.policy_decision.get("max_duration") is not None
        ):
            duration = min(
                duration,
                access_request.policy_decision["max_duration"],
            )

        jit = await self._jit.grant(
            db,
            request_id=access_request.id,
            user_id=access_request.user_id,
            asset_id=access_request.asset_id,
            application_id=access_request.application_id,
            protocol=access_request.protocol,
            duration_minutes=duration,
            created_by=approver.id,
        )

        access_request.status = "ACTIVE"
        await write_audit_log(
            db, actor=approver, action="JIT_GRANTED",
            result="SUCCESS", severity="INFO",
            metadata={
                "expires_at": jit.expires_at.isoformat(),
                "duration_minutes": duration,
            },
            **audit_kwargs,
        )

        await db.commit()
        await db.refresh(access_request)
        return access_request


    async def reject(
        self, db: AsyncSession, *, approval: Approval, access_request: AccessRequest,
        approver: User, comment: str, source_ip: Optional[str],
    ) -> AccessRequest:
        if approval.status != "PENDING":
            raise InvalidTransitionError(approval.status, "REJECTED")

        now = datetime.now(timezone.utc)

        # An expired request cannot receive a new approval decision.
        if access_request.expires_at is not None:
            deadline = access_request.expires_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
            if deadline <= now:
                raise InvalidTransitionError(
                    access_request.status, "EXPIRED"
                )

        if approver.id == access_request.user_id:
            raise SelfApprovalError(
                "A requester cannot reject their own access request."
            )

        check_transition(access_request.status, "REJECTED")

        approval.status = "REJECTED"
        approval.approver_id = approver.id
        approval.comment = comment
        approval.decided_at = now
        approval.source_ip = source_ip

        access_request.status = "REJECTED"
        access_request.decided_at = now
        access_request.decided_by = approver.id

        await write_audit_log(
            db, actor=approver, action="APPROVAL_REJECTED",
            target_type=_target_type(access_request.asset_id),
            target_id=str(
                access_request.asset_id or access_request.application_id
            ),
            request_id=access_request.id,
            source_ip=source_ip,
            result="DENIED",
            severity="MEDIUM",
            metadata={"comment": comment},
        )

        await db.commit()
        await db.refresh(access_request)
        return access_request
