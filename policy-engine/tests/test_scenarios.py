"""End-to-end scenarios against the shipped baseline policies (default_policies.py)."""
from dataclasses import replace
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import pytest
from securepam_policy_engine import AccessContext, Decision, PolicyEvaluator
from securepam_policy_engine.default_policies import DEFAULT_POLICIES
from securepam_policy_engine.repository import InMemoryPolicyRepository

EVAL = PolicyEvaluator(InMemoryPolicyRepository(DEFAULT_POLICIES))
IST = ZoneInfo("Asia/Kolkata")


def ctx(**kw):
    base = dict(request_id="REQ-1", user_id="u1", role="Operator", target_id="win-prod-01",
                target_registered=True, environment="production", protocol="RDP",
                requested_duration_minutes=30, mfa_satisfied=True, risk_score=65,
                now=datetime(2026, 10, 12, 11, 0, tzinfo=IST))
    base.update(kw)
    return AccessContext(**base)


def test_project_demo_operator_production_rdp_high_risk():
    """Plan section 11: operator requests production RDP -> HIGH risk -> approval + JIT + recording."""
    d = EVAL.evaluate(ctx())
    assert d.decision is Decision.REQUIRE_APPROVAL and not d.can_proceed
    assert d.approval_required and d.mfa_required and d.jit_required and d.recording_required
    assert d.recording_mode == "VIDEO" and d.max_duration_minutes == 30
    assert {m["policy_id"] for m in d.matched_policies} == {"POL-003", "POL-004"}


def test_demo_step_up_mfa_comes_first():
    assert EVAL.evaluate(ctx(mfa_satisfied=False)).decision is Decision.REQUIRE_MFA


def test_demo_duration_over_production_limit_denied():
    assert EVAL.evaluate(ctx(requested_duration_minutes=45)).reason_codes == ("DURATION_EXCEEDED",)


@pytest.mark.parametrize("role", ["Administrator", "Operator"])
def test_project_roles_are_accepted(role):
    assert EVAL.evaluate(ctx(role=role, environment="staging", risk_score=10)).decision is Decision.ALLOW


@pytest.mark.parametrize("role", ["Approver", "Auditor", "Intern"])
def test_non_operating_roles_denied(role):
    assert EVAL.evaluate(ctx(role=role, environment="staging", risk_score=10)).decision is Decision.DENY


def test_auditor_as_secondary_role_is_denied():
    d = EVAL.evaluate(ctx(environment="staging", risk_score=10, extra_roles=frozenset({"Auditor"})))
    assert d.reason_codes == ("EXPLICIT_DENY",)


def test_critical_risk_denied_everywhere():
    for env in ("development", "staging", "production"):
        assert EVAL.evaluate(ctx(environment=env, risk_score=80)).decision is Decision.DENY


def test_medium_risk_staging_allowed_with_controls():
    d = EVAL.evaluate(ctx(environment="staging", protocol="SSH", risk_score=45))
    assert d.decision is Decision.ALLOW and d.recording_mode == "TERMINAL_AND_COMMANDS"
    assert d.session_timeout_minutes == 60 and d.idle_timeout_minutes == 15


def test_web_low_risk_standard_proxy_and_high_risk_isolated():
    low = EVAL.evaluate(ctx(environment="staging", protocol="HTTPS", risk_score=20))
    high = EVAL.evaluate(ctx(environment="staging", protocol="HTTPS", risk_score=65))
    assert low.decision is Decision.ALLOW and low.web_access_mode == "STANDARD_PROXY"
    assert high.decision is Decision.REQUIRE_APPROVAL and high.web_access_mode == "ISOLATED_BROWSER"
    assert not high.file_transfer_allowed


def test_restricted_production_target_always_denied():
    assert EVAL.evaluate(ctx(target_id="prod-restricted", risk_score=5)).reason_codes == ("EXPLICIT_DENY",)


def test_non_prod_outside_business_hours_denied_but_prod_not_time_gated():
    night = datetime(2026, 10, 12, 22, 0, tzinfo=IST)
    assert EVAL.evaluate(ctx(environment="staging", risk_score=10, now=night)).reason_codes == ("OUTSIDE_TIME_WINDOW",)
    assert EVAL.evaluate(ctx(environment="production", risk_score=10, now=night)).decision is Decision.REQUIRE_APPROVAL


def test_sunday_non_prod_denied():
    sunday = datetime(2026, 10, 18, 11, 0, tzinfo=IST)
    assert EVAL.evaluate(ctx(environment="staging", risk_score=10, now=sunday)).decision is Decision.DENY


def test_risk_engine_down_denies():
    assert EVAL.evaluate(ctx(risk_score=None)).reason_codes == ("RISK_UNAVAILABLE",)


def test_decision_is_deterministic():
    a, b = EVAL.evaluate(ctx()), EVAL.evaluate(ctx())
    assert a == b
