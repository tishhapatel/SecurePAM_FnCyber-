"""Thin FastAPI adapter (optional `api` extra). Wrap this into the backend's existing app/auth.

- The evaluation endpoint takes NO request body: the client cannot supply role, risk, MFA,
  target registration, approval, JIT or expiry. `context_provider` (backend code) builds the
  AccessContext from trusted sources.
- Every route requires authentication: `auth_dependency` (the backend's auth dependency,
  returning the authenticated actor) is mandatory, and the router cannot be built without it.
  The actor is passed to `context_provider(request_id, request, actor)`, which must refuse
  (raise HTTPException 403/404) when that actor may not evaluate that access request.
- Admin routes are mounted only if BOTH a policy repository with publish/disable and an
  `admin_dependency` (returning the authenticated admin's id) are supplied.
"""
from __future__ import annotations
from typing import Callable, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from .evaluator import PolicyEvaluator
from .models import AccessContext, Policy, PolicyConfigurationError
from .repository import policy_to_record


class PolicySchema(BaseModel):
    """Admin input for a policy. `version` is assigned by the server."""
    model_config = ConfigDict(extra="forbid")
    policy_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    enabled: bool = True
    priority: int = 100
    effect: Literal["ALLOW", "DENY"] = "ALLOW"
    allowed_roles: list[str] = []
    environments: list[str] = []
    protocols: list[str] = []
    target_ids: list[str] = []
    criticalities: list[str] = []
    requires_assignment: bool = False
    allowed_weekdays: Optional[list[int]] = None
    timezone_name: str = "UTC"
    business_hours_start: Optional[str] = None
    business_hours_end: Optional[str] = None
    deny_outside_time_window: bool = False
    max_duration_minutes: int = 30
    approval_required: bool = False
    mfa_required: bool = True
    recording_required: bool = True
    jit_required: bool = True
    isolated_browser_required: bool = False
    allow_file_transfer: bool = False
    session_timeout_minutes: Optional[int] = None
    idle_timeout_minutes: Optional[int] = None
    max_risk_score: Optional[int] = None
    deny_min_risk: Optional[int] = None
    approval_min_risk: Optional[int] = None
    mfa_min_risk: Optional[int] = None
    isolated_browser_min_risk: Optional[int] = None
    change_note: str = Field(default="", max_length=500)

    def to_policy(self) -> Policy:
        data = self.model_dump(exclude={"change_note"})
        for k in ("allowed_roles", "environments", "protocols", "target_ids", "criticalities"):
            data[k] = frozenset(data[k])
        if data["allowed_weekdays"] is not None:
            data["allowed_weekdays"] = frozenset(data["allowed_weekdays"])
        return Policy(version=1, **data)


def create_policy_router(evaluator: PolicyEvaluator,
                         context_provider: Callable[[str, Request, object], AccessContext],
                         audit_sink: Optional[Callable[[dict], None]] = None,
                         repository=None,
                         admin_dependency: Optional[Callable] = None,
                         *,
                         auth_dependency: Callable) -> APIRouter:
    if auth_dependency is None:
        raise ValueError("auth_dependency is required: the evaluation route must not be unauthenticated")
    router = APIRouter(tags=["policy-engine"])

    @router.post("/access-requests/{request_id}/policy-evaluation")
    def evaluate(request_id: str, request: Request, actor=Depends(auth_dependency)):
        # Trusted, server-side; must check that `actor` may evaluate this request (IDOR).
        context = context_provider(request_id, request, actor)
        decision = evaluator.evaluate(context)
        if audit_sink is not None:  # every decision, including DENY, is audited
            audit_sink({"event": "policy.evaluated", "user_id": context.user_id,
                        "target_id": context.target_id, **decision.to_dict()})
        return decision.to_dict()

    if repository is not None and admin_dependency is not None:
        @router.get("/policies")
        def list_policies(actor: str = Depends(admin_dependency)):
            return [policy_to_record(p) for p in repository.list_current()]

        @router.post("/policies", status_code=201)
        def publish_policy(body: PolicySchema, actor: str = Depends(admin_dependency)):
            try:
                stored = repository.publish(body.to_policy(), actor=actor, change_note=body.change_note)
            except PolicyConfigurationError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
            return policy_to_record(stored)

        @router.post("/policies/{policy_id}/disable")
        def disable_policy(policy_id: str, actor: str = Depends(admin_dependency)):
            try:
                return policy_to_record(repository.disable(policy_id, actor=actor))
            except KeyError:
                raise HTTPException(status_code=404, detail="Unknown policy")

    return router
