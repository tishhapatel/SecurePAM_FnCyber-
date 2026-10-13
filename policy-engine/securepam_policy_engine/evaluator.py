"""Deterministic SecurePAM policy evaluator. No network, DB, or session side effects."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Iterable
from zoneinfo import ZoneInfo
from .models import (AccessContext, Decision, Policy, PolicyConfigurationError, PolicyDecision,
                     ReasonCode as RC, WEB_PROTOCOLS)
from .validation import parse_hhmm, validate_policy

_RISK_FIELDS = ("max_risk_score", "deny_min_risk", "approval_min_risk", "mfa_min_risk",
                "isolated_browser_min_risk")


def _fold(values) -> frozenset:
    return frozenset(v.strip().casefold() for v in values)


def _ref(p: Policy) -> dict:
    return {"policy_id": p.policy_id, "version": p.version}


def _refs(policies) -> tuple:
    return tuple(_ref(p) for p in sorted(policies, key=lambda x: (x.priority, x.policy_id)))


def _build(context, decision, codes, reasons, matched=(), **kw) -> PolicyDecision:
    try:
        now_iso = context.now.astimezone(timezone.utc).isoformat()
    except Exception:
        now_iso = datetime.now(timezone.utc).isoformat()
    risk = getattr(context, "risk_score", None)
    return PolicyDecision(
        request_id=(getattr(context, "request_id", "") or "unknown"),
        decision=decision,
        reason_codes=tuple(c.value for c in codes),
        matched_policies=tuple(matched),
        reasons=tuple(reasons),
        approval_required=kw.get("approval", False),
        mfa_required=kw.get("mfa", True),
        mfa_satisfied=bool(getattr(context, "mfa_satisfied", False)),
        recording_required=kw.get("recording", False),
        jit_required=kw.get("jit", False),
        max_duration_minutes=kw.get("max_duration"),
        evaluated_at=now_iso,
        web_access_mode=kw.get("web_mode"),
        recording_mode=kw.get("recording_mode"),
        session_timeout_minutes=kw.get("session_timeout"),
        idle_timeout_minutes=kw.get("idle_timeout"),
        file_transfer_allowed=kw.get("file_transfer", False),
        risk_score=risk if isinstance(risk, int) and not isinstance(risk, bool) else None,
    )


def deny(context, code: RC, reason: str, matched=()) -> PolicyDecision:
    """Build a fail-closed DENY decision (also used by PolicyEvaluator for store errors)."""
    return _build(context, Decision.DENY, [code], [reason], matched)


class _Norm:
    """Case/whitespace-normalised view of the trusted context used for matching."""
    def __init__(self, c: AccessContext):
        self.roles = _fold({c.role} | set(c.extra_roles))
        self.environment = c.environment.strip().casefold()
        self.protocol = c.protocol.strip().upper()
        self.criticality = c.criticality.strip().casefold() if c.criticality else None


def _base_selectors_match(p: Policy, c: AccessContext, n: _Norm) -> bool:
    if p.allowed_roles and not (_fold(p.allowed_roles) & n.roles):
        return False
    if p.environments and n.environment not in _fold(p.environments):
        return False
    if p.protocols and n.protocol not in {x.strip().upper() for x in p.protocols}:
        return False
    if p.target_ids and c.target_id not in p.target_ids:
        return False
    if p.criticalities:
        if n.criticality is None:
            return p.effect == "DENY"  # unknown criticality: DENY rules apply conservatively
        if n.criticality not in _fold(p.criticalities):
            return False
    if p.requires_assignment and p.policy_id not in c.assigned_policy_ids:
        return False
    return True


def _time_window_matches(p: Policy, now: datetime) -> bool:
    has_days = p.allowed_weekdays is not None
    has_hours = p.business_hours_start is not None
    if not has_days and not has_hours:
        return True
    local = now.astimezone(ZoneInfo(p.timezone_name))
    if not has_hours:
        return local.weekday() in p.allowed_weekdays
    start = parse_hhmm(p.business_hours_start)
    end = parse_hhmm(p.business_hours_end, allow_24=True)
    cur = local.hour * 60 + local.minute
    if start < end:                      # same-day window
        if not (start <= cur < end):
            return False
        day = local.weekday()
    elif cur >= start:                   # overnight window, evening part
        day = local.weekday()
    elif cur < end:                      # overnight window, after midnight belongs to previous day
        day = (local.weekday() - 1) % 7
    else:
        return False
    return not has_days or day in p.allowed_weekdays


def _needs_risk(p: Policy) -> bool:
    return any(getattr(p, f) is not None for f in _RISK_FIELDS)


def _recording_mode(protocol: str, isolated: bool):
    if protocol == "RDP":
        return "VIDEO"
    if protocol == "SSH":
        return "TERMINAL_AND_COMMANDS"
    if protocol in WEB_PROTOCOLS:
        return "VIDEO_AND_HTTP_AUDIT" if isolated else "HTTP_AUDIT"
    return "VIDEO"


def evaluate_policies(context: AccessContext, policies: Iterable[Policy]) -> PolicyDecision:
    """Evaluate policies using deny-overrides, accumulating mandatory controls.

    Fail-closed means DENY for missing/invalid context, no active/matching policy,
    malformed policy, missing risk required by a policy, or evaluator errors.
    REQUIRE_MFA / REQUIRE_APPROVAL are orchestration states, never evidence that MFA
    or approval happened. Only `can_proceed` (ALLOW) means the policy gate is open.
    """
    if not isinstance(context, AccessContext):
        return deny(context, RC.INVALID_CONTEXT, "Invalid access context")
    try:
        if not all(isinstance(v, str) and v.strip() for v in
                   (context.request_id, context.user_id, context.role, context.target_id,
                    context.environment, context.protocol)):
            return deny(context, RC.INVALID_CONTEXT, "Missing required trusted request context")
        if not isinstance(context.now, datetime) or context.now.tzinfo is None or context.now.utcoffset() is None:
            return deny(context, RC.INVALID_CONTEXT, "Evaluation timestamp must be timezone-aware")
        if not isinstance(context.extra_roles, (frozenset, set)) or not all(isinstance(r, str) for r in context.extra_roles):
            return deny(context, RC.INVALID_CONTEXT, "extra_roles must be a set of strings")
        if context.criticality is not None and not isinstance(context.criticality, str):
            return deny(context, RC.INVALID_CONTEXT, "criticality must be a string or null")
        if context.target_registered is not True:
            return deny(context, RC.TARGET_NOT_REGISTERED, "Target is not registered or registration is unverified")
        d = context.requested_duration_minutes
        if not isinstance(d, int) or isinstance(d, bool) or d <= 0:
            return deny(context, RC.INVALID_CONTEXT, "Requested duration must be a positive integer")
        r = context.risk_score
        if r is not None and (not isinstance(r, int) or isinstance(r, bool) or not 0 <= r <= 100):
            return deny(context, RC.INVALID_CONTEXT, "Risk score must be an integer from 0 to 100")
        return _decide(context, policies)
    except PolicyConfigurationError as exc:
        return deny(context, RC.POLICY_INVALID, f"Invalid policy configuration: {exc}")
    except Exception as exc:  # never leak internals, never fail open
        return deny(context, RC.EVALUATION_ERROR, f"Policy evaluation failed closed ({type(exc).__name__})")


def _decide(context: AccessContext, policies: Iterable[Policy]) -> PolicyDecision:
    all_policies = list(policies)
    for p in all_policies:
        if not isinstance(p, Policy):
            raise PolicyConfigurationError("Invalid policy object in policy set")
    active = [p for p in all_policies if p.enabled]
    if not active:
        return deny(context, RC.NO_ACTIVE_POLICY, "No active policy is available")
    for p in active:
        validate_policy(p)  # also validates time config for policies whose selectors don't match
    n = _Norm(context)

    guards = [p for p in active if p.effect == "ALLOW" and p.deny_outside_time_window
              and _base_selectors_match(p, context, n) and not _time_window_matches(p, context.now)]
    if guards:
        return deny(context, RC.OUTSIDE_TIME_WINDOW, "Access is outside a mandatory policy time window", _refs(guards))

    matching = [p for p in active if _base_selectors_match(p, context, n) and _time_window_matches(p, context.now)]
    if not matching:
        return deny(context, RC.NO_MATCHING_POLICY, "No policy matched this request")
    denies = [p for p in matching if p.effect == "DENY"]
    if denies:
        return deny(context, RC.EXPLICIT_DENY, "A matching DENY policy overrides all ALLOW policies", _refs(denies))

    refs = _refs(matching)
    risk = context.risk_score
    for p in matching:
        if _needs_risk(p) and risk is None:
            return deny(context, RC.RISK_UNAVAILABLE, f"Risk score unavailable for policy {p.policy_id}", refs)
        if p.max_risk_score is not None and risk > p.max_risk_score:
            return deny(context, RC.RISK_TOO_HIGH, f"Risk score exceeds configured threshold in {p.policy_id}", refs)
        if p.deny_min_risk is not None and risk >= p.deny_min_risk:
            return deny(context, RC.RISK_TOO_HIGH, f"Risk score {risk} is at or above the deny tier ({p.deny_min_risk}) in {p.policy_id}", refs)

    effective_max = min(p.max_duration_minutes for p in matching)
    if context.requested_duration_minutes > effective_max:
        return deny(context, RC.DURATION_EXCEEDED, f"Requested duration exceeds effective maximum of {effective_max} minutes", refs)

    def at_or_above(p, field):
        v = getattr(p, field)
        return v is not None and risk is not None and risk >= v

    risk_approval = [p for p in matching if at_or_above(p, "approval_min_risk")]
    approval = any(p.approval_required for p in matching) or bool(risk_approval)
    mfa = any(p.mfa_required for p in matching) or any(at_or_above(p, "mfa_min_risk") for p in matching)
    recording = any(p.recording_required for p in matching)
    jit = any(p.jit_required for p in matching)
    is_web = n.protocol in WEB_PROTOCOLS
    isolated = is_web and (any(p.isolated_browser_required for p in matching)
                           or any(at_or_above(p, "isolated_browser_min_risk") for p in matching))
    web_mode = ("ISOLATED_BROWSER" if isolated else "STANDARD_PROXY") if is_web else None
    timeouts = [p.session_timeout_minutes for p in matching if p.session_timeout_minutes is not None]
    idles = [p.idle_timeout_minutes for p in matching if p.idle_timeout_minutes is not None]
    file_transfer = all(p.allow_file_transfer for p in matching) and not isolated

    reasons = [f"Matched {len(matching)} active policy/policies",
               f"Effective maximum duration is {effective_max} minutes"]
    if approval:
        reasons.append("Approval is required" + (f" (risk score {risk} reached an approval tier)" if risk_approval else " by a matching policy"))
    if mfa:
        reasons.append("MFA is required by a matching policy or risk tier")
    if recording:
        reasons.append("Session recording is required by at least one matching policy")
    if jit:
        reasons.append("Just-in-time access is required by at least one matching policy")
    if isolated:
        reasons.append("Isolated browser is required for this web session")

    if mfa and not context.mfa_satisfied:
        decision, codes = Decision.REQUIRE_MFA, [RC.MFA_REQUIRED]
        reasons.append("MFA is required but not verified; run step-up MFA, then re-evaluate")
    elif approval:
        decision, codes = Decision.REQUIRE_APPROVAL, [RC.APPROVAL_REQUIRED]
    else:
        decision, codes = Decision.ALLOW, [RC.ALLOWED]
    return _build(context, decision, codes, reasons, refs, approval=approval, mfa=mfa,
                  recording=recording, jit=jit, max_duration=effective_max, web_mode=web_mode,
                  recording_mode=_recording_mode(n.protocol, isolated) if recording else None,
                  session_timeout=min(timeouts) if timeouts else None,
                  idle_timeout=min(idles) if idles else None, file_transfer=file_transfer)


class PolicyEvaluator:
    """Small injectable façade for backend integration."""
    def __init__(self, repository):
        self.repository = repository

    def evaluate(self, context: AccessContext) -> PolicyDecision:
        try:
            policies = self.repository.list_active()
        except PolicyConfigurationError as exc:
            return deny(context, RC.POLICY_INVALID, f"Invalid policy configuration: {exc}")
        except Exception:
            # A policy-store outage must never turn into implicit permission.
            return deny(context, RC.POLICY_STORE_UNAVAILABLE, "Policy store is unavailable")
        return evaluate_policies(context, policies)
