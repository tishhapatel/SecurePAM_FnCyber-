"""Policy configuration validation shared by the evaluator, repositories and admin API."""
from __future__ import annotations
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from .models import Policy, PolicyConfigurationError

_SET_FIELDS = ("allowed_roles", "environments", "protocols", "target_ids", "criticalities")
_RISK_FIELDS = ("max_risk_score", "deny_min_risk", "approval_min_risk", "mfa_min_risk",
                "isolated_browser_min_risk")


def parse_hhmm(value, *, allow_24: bool = False) -> int:
    """Return minutes since midnight. '24:00' is accepted only as an end boundary."""
    try:
        hour, minute = value.split(":", 1)
        h, m = int(hour), int(minute)
    except (ValueError, AttributeError):
        raise PolicyConfigurationError(f"Invalid HH:MM time: {value!r}")
    if allow_24 and h == 24 and m == 0:
        return 1440
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise PolicyConfigurationError(f"Invalid HH:MM time: {value!r}")
    return h * 60 + m


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def validate_policy(p: Policy) -> None:
    """Raise PolicyConfigurationError if the policy is unsafe or malformed."""
    if not isinstance(p, Policy):
        raise PolicyConfigurationError("Not a Policy object")
    pid = p.policy_id
    if not isinstance(pid, str) or not pid.strip():
        raise PolicyConfigurationError("Policy has no policy_id")
    if not _is_int(p.version) or p.version < 1:
        raise PolicyConfigurationError(f"{pid}: version must be an integer >= 1")
    if p.effect not in {"ALLOW", "DENY"}:
        raise PolicyConfigurationError(f"{pid}: effect must be ALLOW or DENY")
    for name in _SET_FIELDS:
        value = getattr(p, name)
        if not isinstance(value, (frozenset, set)) or not all(isinstance(x, str) and x.strip() for x in value):
            raise PolicyConfigurationError(f"{pid}: {name} must be a set of non-empty strings")
    if p.effect == "ALLOW" and not (p.allowed_roles and p.environments and p.protocols):
        # An ALLOW policy with an empty selector would match everyone/everything.
        raise PolicyConfigurationError(
            f"{pid}: ALLOW policies must list allowed_roles, environments and protocols")
    if not _is_int(p.max_duration_minutes) or p.max_duration_minutes <= 0:
        raise PolicyConfigurationError(f"{pid}: max_duration_minutes must be a positive integer")
    for name in ("session_timeout_minutes", "idle_timeout_minutes"):
        v = getattr(p, name)
        if v is not None and (not _is_int(v) or v <= 0):
            raise PolicyConfigurationError(f"{pid}: {name} must be a positive integer or null")
    for name in _RISK_FIELDS:
        v = getattr(p, name)
        if v is not None and (not _is_int(v) or not 0 <= v <= 100):
            raise PolicyConfigurationError(f"{pid}: {name} must be an integer 0-100 or null")
    if p.deny_min_risk is not None and p.approval_min_risk is not None and p.approval_min_risk >= p.deny_min_risk:
        raise PolicyConfigurationError(f"{pid}: approval_min_risk must be below deny_min_risk")
    if p.allowed_weekdays is not None and not all(_is_int(d) and 0 <= d <= 6 for d in p.allowed_weekdays):
        raise PolicyConfigurationError(f"{pid}: allowed_weekdays must contain integers 0-6")
    if (p.business_hours_start is None) != (p.business_hours_end is None):
        raise PolicyConfigurationError(f"{pid}: set both business-hours boundaries or neither")
    if p.business_hours_start is not None:
        start = parse_hhmm(p.business_hours_start)
        end = parse_hhmm(p.business_hours_end, allow_24=True)
        if start == end:
            raise PolicyConfigurationError(f"{pid}: business-hours start and end must differ")
    try:
        ZoneInfo(p.timezone_name)
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        raise PolicyConfigurationError(f"{pid}: unknown timezone {p.timezone_name!r}")
    if p.deny_outside_time_window and p.effect != "ALLOW":
        raise PolicyConfigurationError(f"{pid}: deny_outside_time_window is only for ALLOW policies")
