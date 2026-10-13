"""Illustrative SecurePAM baseline policies using the project's role model.

Roles follow the project docs: Administrator / Operator may operate targets; Approver and
Auditor never receive target access. Risk tiers follow the documented model
(LOW 0-29, MEDIUM 30-59, HIGH 60-79, CRITICAL 80+). Review and adjust with the team.
policies.json is generated from this list (see tools/export_policies.py); do not hand-edit both.
"""
from .models import Policy

OPERATING_ROLES = frozenset({"Administrator", "Operator"})
ALL_ENVS = frozenset({"development", "staging", "production"})
ALL_PROTOCOLS = frozenset({"SSH", "RDP", "HTTP", "HTTPS"})
WEEKDAYS_MON_SAT = frozenset({0, 1, 2, 3, 4, 5})

DEFAULT_POLICIES = [
    Policy(policy_id="POL-001", version=1, name="Deny restricted production targets",
           effect="DENY", priority=1, environments=frozenset({"production"}),
           target_ids=frozenset({"prod-unknown", "prod-restricted"})),
    Policy(policy_id="POL-002", version=1, name="Auditors never operate targets",
           effect="DENY", priority=2, allowed_roles=frozenset({"Auditor"})),
    Policy(policy_id="POL-003", version=1, name="Baseline privileged access (risk-adaptive)",
           priority=10, allowed_roles=OPERATING_ROLES, environments=ALL_ENVS, protocols=ALL_PROTOCOLS,
           max_duration_minutes=60, mfa_required=True, recording_required=True, jit_required=True,
           session_timeout_minutes=60, idle_timeout_minutes=15,
           approval_min_risk=60, deny_min_risk=80),
    Policy(policy_id="POL-004", version=1, name="Production access requires approval",
           priority=20, allowed_roles=OPERATING_ROLES, environments=frozenset({"production"}),
           protocols=ALL_PROTOCOLS, max_duration_minutes=30, approval_required=True,
           mfa_required=True, recording_required=True, jit_required=True),
    Policy(policy_id="POL-005", version=1, name="Web access: isolated browser at HIGH risk",
           priority=30, allowed_roles=OPERATING_ROLES, environments=ALL_ENVS,
           protocols=frozenset({"HTTP", "HTTPS"}), max_duration_minutes=60,
           isolated_browser_min_risk=60),
    Policy(policy_id="POL-006", version=1, name="Non-production business hours only (IST, Mon-Sat)",
           priority=40, allowed_roles=OPERATING_ROLES, environments=frozenset({"development", "staging"}),
           protocols=ALL_PROTOCOLS, allowed_weekdays=WEEKDAYS_MON_SAT, timezone_name="Asia/Kolkata",
           business_hours_start="09:00", business_hours_end="19:00", max_duration_minutes=60,
           deny_outside_time_window=True),
]
