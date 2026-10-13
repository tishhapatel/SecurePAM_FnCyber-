"""Typed, side-effect-free data contracts for SecurePAM policy evaluation."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import FrozenSet, Optional

ENGINE_VERSION = "2.0.0"
WEB_PROTOCOLS = frozenset({"HTTP", "HTTPS"})


class PolicyConfigurationError(Exception):
    """A policy (or policy record) is malformed. Always handled as fail-closed DENY."""


class Decision(str, Enum):
    DENY = "DENY"
    REQUIRE_MFA = "REQUIRE_MFA"            # step-up authentication needed before anything else
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"  # approval workflow needed (NOT an approval)
    ALLOW = "ALLOW"                        # policy-wise allowed; coordinator still enforces signals


class ReasonCode(str, Enum):
    """Stable machine-readable codes for audit/SIEM; reasons[] stays human-readable."""
    ALLOWED = "ALLOWED"
    INVALID_CONTEXT = "INVALID_CONTEXT"
    TARGET_NOT_REGISTERED = "TARGET_NOT_REGISTERED"
    POLICY_STORE_UNAVAILABLE = "POLICY_STORE_UNAVAILABLE"
    POLICY_INVALID = "POLICY_INVALID"
    NO_ACTIVE_POLICY = "NO_ACTIVE_POLICY"
    NO_MATCHING_POLICY = "NO_MATCHING_POLICY"
    EXPLICIT_DENY = "EXPLICIT_DENY"
    OUTSIDE_TIME_WINDOW = "OUTSIDE_TIME_WINDOW"
    RISK_UNAVAILABLE = "RISK_UNAVAILABLE"
    RISK_TOO_HIGH = "RISK_TOO_HIGH"
    DURATION_EXCEEDED = "DURATION_EXCEEDED"
    MFA_REQUIRED = "MFA_REQUIRED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    EVALUATION_ERROR = "EVALUATION_ERROR"


@dataclass(frozen=True)
class AccessContext:
    """Context supplied by trusted backend services, never trusted from the browser.

    `now` must be timezone-aware. Everything here must be resolved server-side
    (RBAC, asset registry, risk engine, MFA verifier, server clock).
    `role` is the primary role; `extra_roles` carries any additional roles.
    `criticality` / `assigned_policy_ids` come from the asset/application registry (Member 4).
    """
    request_id: str
    user_id: str
    role: str
    target_id: str
    target_registered: bool
    environment: str
    protocol: str
    requested_duration_minutes: int
    mfa_satisfied: bool = False
    risk_score: Optional[int] = None
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    extra_roles: FrozenSet[str] = frozenset()
    criticality: Optional[str] = None
    assigned_policy_ids: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class Policy:
    policy_id: str
    version: int
    name: str
    enabled: bool = True
    priority: int = 100
    effect: str = "ALLOW"  # ALLOW or DENY
    # --- selectors (ALLOW policies must list roles, environments and protocols) ---
    allowed_roles: FrozenSet[str] = frozenset()
    environments: FrozenSet[str] = frozenset()
    protocols: FrozenSet[str] = frozenset()
    target_ids: FrozenSet[str] = frozenset()
    criticalities: FrozenSet[str] = frozenset()
    requires_assignment: bool = False  # only applies when listed in context.assigned_policy_ids
    allowed_weekdays: Optional[FrozenSet[int]] = None  # Monday=0 ... Sunday=6
    timezone_name: str = "UTC"
    business_hours_start: Optional[str] = None  # HH:MM inclusive
    business_hours_end: Optional[str] = None    # HH:MM exclusive; "24:00" allowed; start>end = overnight
    deny_outside_time_window: bool = False  # guard: deny when other selectors match but time does not
    # --- mandatory controls (OR-accumulated across matching policies) ---
    max_duration_minutes: int = 30
    approval_required: bool = False
    mfa_required: bool = True
    recording_required: bool = True
    jit_required: bool = True
    isolated_browser_required: bool = False
    allow_file_transfer: bool = False  # AND-accumulated: any matching policy can forbid it
    session_timeout_minutes: Optional[int] = None  # strictest (minimum) wins
    idle_timeout_minutes: Optional[int] = None     # strictest (minimum) wins
    # --- risk-adaptive tiers (score comes from the trusted risk engine) ---
    max_risk_score: Optional[int] = None         # DENY if score > value (legacy ceiling)
    deny_min_risk: Optional[int] = None          # DENY if score >= value (CRITICAL tier)
    approval_min_risk: Optional[int] = None      # approval required if score >= value
    mfa_min_risk: Optional[int] = None           # MFA required if score >= value
    isolated_browser_min_risk: Optional[int] = None  # web: isolated browser if score >= value


@dataclass(frozen=True)
class PolicyDecision:
    request_id: str
    decision: Decision
    reason_codes: tuple[str, ...]
    matched_policies: tuple[dict, ...]
    reasons: tuple[str, ...]
    approval_required: bool
    mfa_required: bool
    mfa_satisfied: bool
    recording_required: bool
    jit_required: bool
    max_duration_minutes: Optional[int]
    evaluated_at: str
    web_access_mode: Optional[str] = None       # STANDARD_PROXY | ISOLATED_BROWSER (web only)
    recording_mode: Optional[str] = None        # VIDEO | TERMINAL_AND_COMMANDS | HTTP_AUDIT | VIDEO_AND_HTTP_AUDIT
    session_timeout_minutes: Optional[int] = None
    idle_timeout_minutes: Optional[int] = None
    file_transfer_allowed: bool = False
    risk_score: Optional[int] = None
    policy_engine_version: str = ENGINE_VERSION

    @property
    def can_proceed(self) -> bool:
        """True only for ALLOW. REQUIRE_MFA / REQUIRE_APPROVAL / DENY are all 'not yet'."""
        return self.decision is Decision.ALLOW

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "decision": self.decision.value,
            "can_proceed": self.can_proceed,
            "reason_codes": list(self.reason_codes),
            "reasons": list(self.reasons),
            "matched_policies": list(self.matched_policies),
            "approval_required": self.approval_required,
            "mfa_required": self.mfa_required,
            "mfa_satisfied": self.mfa_satisfied,
            "recording_required": self.recording_required,
            "recording_mode": self.recording_mode,
            "jit_required": self.jit_required,
            "max_duration_minutes": self.max_duration_minutes,
            "session_timeout_minutes": self.session_timeout_minutes,
            "idle_timeout_minutes": self.idle_timeout_minutes,
            "web_access_mode": self.web_access_mode,
            "file_transfer_allowed": self.file_transfer_allowed,
            "risk_score": self.risk_score,
            "evaluated_at": self.evaluated_at,
            "policy_engine_version": self.policy_engine_version,
        }
