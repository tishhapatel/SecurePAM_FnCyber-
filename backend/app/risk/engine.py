"""
Explainable, deterministic risk engine.

NOT machine learning, NOT an external model — every factor is a plain
rule over data already in the request/target/user. With the same context
and configuration, the same inputs always produce the same score. This
is deliberate: a risk score that can't be explained to the person it was
applied to isn't acceptable for a PAM decision.

IMPORTANT: the default weights below are THIS PROJECT'S choices, not an
industry standard, not derived from any external framework, and not
validated against real incident data. They demonstrate an adjustable
decision flow; operators can override them with RISK_* environment
settings for their own deployment.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, List, Mapping, Optional, Union

from app.core.business_hours import is_business_hours
from app.models.application import Application
from app.models.asset import Asset
from app.models.user import User

# --- Weights: project-specific, see module docstring ---
RISK_WEIGHTS = {
    "PRODUCTION_ASSET": 30,
    "CRITICAL_ASSET": 25,
    "HIGH_CRITICALITY": 15,
    "SENSITIVE_APPLICATION": 20,
    "HIGH_PRIVILEGE_ROLE": 20,
    "OUTSIDE_BUSINESS_HOURS": 20,
    "UNKNOWN_CONTEXT": 20,
    "REPEATED_AUTH_FAILURE": 20,
    "UNUSUAL_ACCESS_PATTERN": 20,
    "LONG_DURATION": 10,
}

RISK_FACTOR_CODES = (
    "PRODUCTION_ASSET",
    "CRITICAL_ASSET",
    "HIGH_CRITICALITY",
    "SENSITIVE_APPLICATION",
    "HIGH_PRIVILEGE_ROLE",
    "OUTSIDE_BUSINESS_HOURS",
    "UNKNOWN_CONTEXT",
    "REPEATED_AUTH_FAILURE",
    "UNUSUAL_ACCESS_PATTERN",
    "LONG_DURATION",
)

# Defaults retained as named constants for callers that used the original
# engine API. Runtime configuration is captured in RiskConfiguration.
HIGH_PRIVILEGE_ROLES = {"ADMIN"}
LONG_DURATION_THRESHOLD_MINUTES = 60
RISK_LEVEL_THRESHOLDS = ((80, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (0, "LOW"))


@dataclass(frozen=True)
class RiskConfiguration:
    """Validated, immutable inputs that control the risk scoring rules."""

    weights: Mapping[str, int] = field(default_factory=lambda: dict(RISK_WEIGHTS))
    enabled_factors: frozenset[str] = frozenset(RISK_FACTOR_CODES)
    high_privilege_roles: frozenset[str] = frozenset(HIGH_PRIVILEGE_ROLES)
    long_duration_threshold_minutes: int = LONG_DURATION_THRESHOLD_MINUTES
    medium_threshold: int = 30
    high_threshold: int = 60
    critical_threshold: int = 80

    def __post_init__(self) -> None:
        if not isinstance(self.weights, Mapping):
            raise ValueError("Risk weights must be a mapping of factor codes to integer points")
        unknown_weights = set(self.weights) - set(RISK_FACTOR_CODES)
        missing_weights = set(RISK_FACTOR_CODES) - set(self.weights)
        if unknown_weights or missing_weights:
            raise ValueError(
                "Risk weights must define each known factor exactly; "
                f"unknown={sorted(unknown_weights)}, missing={sorted(missing_weights)}"
            )
        for code, points in self.weights.items():
            if type(points) is not int or points < 0:
                raise ValueError(f"Risk weight for {code} must be a non-negative integer")

        enabled_factors = frozenset(self.enabled_factors)
        unknown_enabled = enabled_factors - set(RISK_FACTOR_CODES)
        if unknown_enabled:
            raise ValueError(f"Unknown enabled risk factors: {sorted(unknown_enabled)}")
        integer_settings = {
            "long-duration threshold": self.long_duration_threshold_minutes,
            "medium threshold": self.medium_threshold,
            "high threshold": self.high_threshold,
            "critical threshold": self.critical_threshold,
        }
        if any(type(value) is not int for value in integer_settings.values()):
            raise ValueError("Risk duration and level thresholds must be integers")
        if self.long_duration_threshold_minutes < 0:
            raise ValueError("Long-duration threshold must be non-negative")
        if not (0 < self.medium_threshold < self.high_threshold < self.critical_threshold):
            raise ValueError("Risk thresholds must satisfy 0 < medium < high < critical")

        if any(not isinstance(role, str) for role in self.high_privilege_roles):
            raise ValueError("High-privilege role names must be strings")
        normalized_roles = frozenset(
            role.strip().upper() for role in self.high_privilege_roles if role.strip()
        )
        object.__setattr__(self, "weights", MappingProxyType(dict(self.weights)))
        object.__setattr__(self, "enabled_factors", enabled_factors)
        object.__setattr__(self, "high_privilege_roles", normalized_roles)

    @classmethod
    def from_settings(cls, settings: Any) -> "RiskConfiguration":
        """Build a risk configuration from the application's validated settings."""
        weights = {
            code: getattr(settings, f"RISK_WEIGHT_{code}", RISK_WEIGHTS[code])
            for code in RISK_FACTOR_CODES
        }
        enabled = frozenset(
            code for code in RISK_FACTOR_CODES
            if getattr(settings, f"RISK_ENABLE_{code}", True)
        )
        return cls(
            weights=weights,
            enabled_factors=enabled,
            high_privilege_roles=frozenset(
                getattr(settings, "RISK_HIGH_PRIVILEGE_ROLES", HIGH_PRIVILEGE_ROLES)
            ),
            long_duration_threshold_minutes=getattr(
                settings, "RISK_LONG_DURATION_THRESHOLD_MINUTES", LONG_DURATION_THRESHOLD_MINUTES
            ),
            medium_threshold=getattr(settings, "RISK_MEDIUM_THRESHOLD", 30),
            high_threshold=getattr(settings, "RISK_HIGH_THRESHOLD", 60),
            critical_threshold=getattr(settings, "RISK_CRITICAL_THRESHOLD", 80),
        )


@dataclass(frozen=True)
class RiskFactor:
    code: str
    points: int
    reason: str


@dataclass(frozen=True)
class RiskResult:
    score: int
    level: str
    factors: List[RiskFactor]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "factors": [{"code": f.code, "points": f.points, "reason": f.reason} for f in self.factors],
        }


@dataclass
class RiskContext:
    """
    Inputs the engine cannot derive from the target/user rows alone.
    `now` is injectable so time-dependent factors (business hours) are
    actually testable/reproducible rather than depending on wall-clock
    time at test-run time.
    """
    now: Optional[datetime] = None
    source_ip: Optional[str] = None
    # Number of PRIOR access requests this user has made (any target),
    # not counting the one currently being evaluated. None means "not
    # computed" — callers that can cheaply query it should; it's never
    # inferred to be either 0 or nonzero when omitted.
    prior_request_count: Optional[int] = None


def _level_for(score: int, configuration: RiskConfiguration) -> str:
    if score >= configuration.critical_threshold:
        return "CRITICAL"
    if score >= configuration.high_threshold:
        return "HIGH"
    if score >= configuration.medium_threshold:
        return "MEDIUM"
    return "LOW"


def evaluate_risk(
    *,
    user: User,
    target: Union[Asset, Application],
    requested_duration: int,
    context: Optional[RiskContext] = None,
    configuration: Optional[RiskConfiguration] = None,
) -> RiskResult:
    """
    Pure function: same user/target/duration/context/configuration always
    produces the same RiskResult. Does not touch the database or mutable
    global state — callers gather `context.prior_request_count` and pass
    the active configuration beforehand.
    """
    context = context or RiskContext()
    configuration = configuration or RiskConfiguration()
    now = context.now or datetime.now(timezone.utc)
    factors: List[RiskFactor] = []
    is_application = isinstance(target, Application)

    def add_factor(code: str, reason: str) -> None:
        if code in configuration.enabled_factors:
            factors.append(RiskFactor(code, configuration.weights[code], reason))

    if target.environment == "PRODUCTION":
        add_factor("PRODUCTION_ASSET", "Target environment is PRODUCTION")

    # Asset and Application criticality are scored under distinct codes —
    # "sensitive application" reads more naturally than "critical asset"
    # for a web app, and keeps the two target kinds from silently double
    # counting if a future change adds both an asset_id and application_id
    # concept to one request.
    if is_application:
        if target.criticality in ("HIGH", "CRITICAL"):
            add_factor("SENSITIVE_APPLICATION", f"Application criticality is {target.criticality}")
    else:
        if target.criticality == "CRITICAL":
            add_factor("CRITICAL_ASSET", "Target asset criticality is CRITICAL")
        elif target.criticality == "HIGH":
            add_factor("HIGH_CRITICALITY", "Target asset criticality is HIGH")

    user_role_names = {ur.role.name for ur in user.roles if ur.role}
    high_priv_held = user_role_names & configuration.high_privilege_roles
    if high_priv_held:
        add_factor(
            "HIGH_PRIVILEGE_ROLE",
            f"Requester holds a high-privilege role ({', '.join(sorted(high_priv_held))})",
        )

    if not is_business_hours(now):
        add_factor("OUTSIDE_BUSINESS_HOURS", "Request made outside business hours (09:00-17:00 UTC, Mon-Fri)")

    if not context.source_ip:
        add_factor("UNKNOWN_CONTEXT", "Request source IP could not be determined")

    if user.failed_login_count and user.failed_login_count > 0:
        add_factor(
            "REPEATED_AUTH_FAILURE",
            f"{user.failed_login_count} recent failed login attempt(s) on this account",
        )

    if context.prior_request_count == 0:
        add_factor(
            "UNUSUAL_ACCESS_PATTERN",
            "This is the requester's first-ever access request — no established pattern to compare against",
        )

    if requested_duration > configuration.long_duration_threshold_minutes:
        add_factor(
            "LONG_DURATION",
            f"Requested duration ({requested_duration}m) exceeds "
            f"{configuration.long_duration_threshold_minutes}m",
        )

    score = sum(f.points for f in factors)
    return RiskResult(score=score, level=_level_for(score, configuration), factors=factors)
