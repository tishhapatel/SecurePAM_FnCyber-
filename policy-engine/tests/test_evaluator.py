from dataclasses import replace
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from securepam_policy_engine import Decision, Policy, ReasonCode as RC, evaluate_policies
from conftest import make_policy


def codes(d):
    return list(d.reason_codes)


def test_allow_and_required_controls(context, policy):
    out = evaluate_policies(context, [policy])
    assert out.decision is Decision.ALLOW and out.can_proceed
    assert out.mfa_required and out.recording_required and out.jit_required
    assert out.max_duration_minutes == 30 and out.recording_mode == "TERMINAL_AND_COMMANDS"
    assert out.to_dict()["decision"] == "ALLOW" and codes(out) == ["ALLOWED"]


def test_role_mismatch_fails_closed(context, policy):
    out = evaluate_policies(replace(context, role="Auditor"), [policy])
    assert out.decision is Decision.DENY and codes(out) == ["NO_MATCHING_POLICY"]


def test_unregistered_target_denied(context, policy):
    out = evaluate_policies(replace(context, target_registered=False), [policy])
    assert out.decision is Decision.DENY and codes(out) == ["TARGET_NOT_REGISTERED"]


def test_no_policies_denied(context):
    assert codes(evaluate_policies(context, [])) == ["NO_ACTIVE_POLICY"]


def test_explicit_deny_overrides_allow(context, policy):
    deny = Policy(policy_id="POL-DENY", version=1, name="No staging", effect="DENY",
                  environments=frozenset({"staging"}))
    out = evaluate_policies(context, [policy, deny])
    assert out.decision is Decision.DENY and codes(out) == ["EXPLICIT_DENY"]
    assert out.matched_policies[0]["policy_id"] == "POL-DENY"


def test_approval_requirement(context, policy):
    p2 = make_policy(policy_id="POL-APPROVAL", approval_required=True)
    out = evaluate_policies(context, [policy, p2])
    assert out.decision is Decision.REQUIRE_APPROVAL and out.approval_required and not out.can_proceed


def test_strictest_duration_wins(context, policy):
    out = evaluate_policies(context, [policy, make_policy(policy_id="POL-SHORT", max_duration_minutes=10)])
    assert out.decision is Decision.DENY and codes(out) == ["DURATION_EXCEEDED"] and "10 minutes" in out.reasons[0]


def test_duration_boundary_is_inclusive(context, policy):
    assert evaluate_policies(replace(context, requested_duration_minutes=30), [policy]).decision is Decision.ALLOW
    assert evaluate_policies(replace(context, requested_duration_minutes=31), [policy]).decision is Decision.DENY


# ---------- MFA is an explicit decision state ----------
def test_unverified_mfa_is_require_mfa_not_allow(context, policy):
    out = evaluate_policies(replace(context, mfa_satisfied=False), [policy])
    assert out.decision is Decision.REQUIRE_MFA and not out.can_proceed
    assert out.mfa_required and not out.mfa_satisfied and codes(out) == ["MFA_REQUIRED"]


def test_mfa_takes_priority_over_approval(context, policy):
    p2 = make_policy(policy_id="POL-A", approval_required=True)
    out = evaluate_policies(replace(context, mfa_satisfied=False), [policy, p2])
    assert out.decision is Decision.REQUIRE_MFA and out.approval_required


# ---------- risk-adaptive tiers ----------
def tiers():
    return make_policy(approval_min_risk=60, deny_min_risk=80, mfa_min_risk=30)


def test_risk_tier_boundaries(context):
    p = tiers()
    r = lambda s, **k: evaluate_policies(replace(context, risk_score=s, **k), [p])
    assert r(29).decision is Decision.ALLOW
    assert r(59).decision is Decision.ALLOW
    assert r(60).decision is Decision.REQUIRE_APPROVAL
    assert r(79).decision is Decision.REQUIRE_APPROVAL
    d = r(80)
    assert d.decision is Decision.DENY and codes(d) == ["RISK_TOO_HIGH"]


def test_mfa_min_risk_forces_mfa(context):
    p = make_policy(mfa_required=False, mfa_min_risk=30)
    assert evaluate_policies(replace(context, risk_score=29, mfa_satisfied=False), [p]).decision is Decision.ALLOW
    assert evaluate_policies(replace(context, risk_score=30, mfa_satisfied=False), [p]).decision is Decision.REQUIRE_MFA


def test_critical_risk_denied_in_staging_too(context):
    assert evaluate_policies(replace(context, risk_score=95), [tiers()]).decision is Decision.DENY


def test_missing_risk_denies_when_tier_configured(context):
    out = evaluate_policies(replace(context, risk_score=None), [tiers()])
    assert out.decision is Decision.DENY and codes(out) == ["RISK_UNAVAILABLE"]


def test_legacy_max_risk_ceiling(context, policy):
    p2 = make_policy(policy_id="POL-RISK", max_risk_score=30)
    assert evaluate_policies(replace(context, risk_score=30), [policy, p2]).decision is Decision.ALLOW
    assert evaluate_policies(replace(context, risk_score=31), [policy, p2]).decision is Decision.DENY


def test_invalid_risk_score_denied(context, policy):
    for bad in (-1, 101, True, 5.5):
        assert evaluate_policies(replace(context, risk_score=bad), [policy]).decision is Decision.DENY


# ---------- web mode, timeouts, file transfer ----------
def web_policy(**kw):
    base = dict(policy_id="POL-WEB", protocols=frozenset({"HTTP", "HTTPS"}), isolated_browser_min_risk=60)
    base.update(kw)
    return make_policy(**base)


def test_web_standard_vs_isolated_by_risk(context):
    low = evaluate_policies(replace(context, protocol="HTTPS", risk_score=59), [web_policy()])
    high = evaluate_policies(replace(context, protocol="https", risk_score=60), [web_policy()])
    assert low.web_access_mode == "STANDARD_PROXY" and low.recording_mode == "HTTP_AUDIT"
    assert high.web_access_mode == "ISOLATED_BROWSER" and high.recording_mode == "VIDEO_AND_HTTP_AUDIT"


def test_non_web_has_no_web_mode(context, policy):
    assert evaluate_policies(context, [policy]).web_access_mode is None


def test_file_transfer_blocked_when_isolated_or_any_policy_forbids(context):
    ok = evaluate_policies(replace(context, protocol="HTTPS", risk_score=10),
                           [web_policy(allow_file_transfer=True)])
    assert ok.file_transfer_allowed
    isolated = evaluate_policies(replace(context, protocol="HTTPS", risk_score=70),
                                 [web_policy(allow_file_transfer=True)])
    assert not isolated.file_transfer_allowed
    mixed = evaluate_policies(replace(context, protocol="HTTPS", risk_score=10),
                              [web_policy(allow_file_transfer=True), web_policy(policy_id="X")])
    assert not mixed.file_transfer_allowed


def test_strictest_timeouts_win(context, policy):
    a = make_policy(policy_id="A", session_timeout_minutes=60, idle_timeout_minutes=15)
    b = make_policy(policy_id="B", session_timeout_minutes=30, idle_timeout_minutes=20)
    out = evaluate_policies(context, [policy, a, b])
    assert out.session_timeout_minutes == 30 and out.idle_timeout_minutes == 15


# ---------- time windows ----------
BH = dict(timezone_name="Asia/Kolkata", allowed_weekdays=frozenset({0, 1, 2, 3, 4}),
          business_hours_start="09:00", business_hours_end="19:00")


def ist(h, m=0, day=12):
    return datetime(2026, 10, day, h, m, tzinfo=ZoneInfo("Asia/Kolkata"))


def test_business_hours_boundaries(context):
    p = make_policy(**BH)
    ok = lambda t: evaluate_policies(replace(context, now=t), [p]).decision is Decision.ALLOW
    assert ok(ist(9, 0)) and ok(ist(18, 59))
    assert not ok(ist(8, 59)) and not ok(ist(19, 0))


def test_weekday_restriction(context):
    p = make_policy(allowed_weekdays=frozenset({1}))  # Tuesday only; context is Monday
    assert evaluate_policies(context, [p]).decision is Decision.DENY


def test_time_guard_denies_even_if_general_allow_matches(context, policy):
    guard = make_policy(policy_id="POL-GUARD", deny_outside_time_window=True,
                        timezone_name="UTC", allowed_weekdays=frozenset({0, 1, 2, 3, 4}),
                        business_hours_start="09:00", business_hours_end="17:00")
    out = evaluate_policies(replace(context, now=datetime(2026, 10, 12, 20, 0, tzinfo=timezone.utc)), [policy, guard])
    assert out.decision is Decision.DENY and codes(out) == ["OUTSIDE_TIME_WINDOW"]


def test_overnight_window_and_weekday_belongs_to_start_day(context):
    # Mon-Fri night shift 22:00-06:00 IST; Saturday 02:00 is the tail of Friday's shift.
    p = make_policy(timezone_name="Asia/Kolkata", allowed_weekdays=frozenset({0, 1, 2, 3, 4}),
                    business_hours_start="22:00", business_hours_end="06:00")
    ok = lambda t: evaluate_policies(replace(context, now=t), [p]).decision is Decision.ALLOW
    assert ok(ist(23, 0, day=12))            # Mon 23:00
    assert ok(ist(2, 0, day=13))             # Tue 02:00 (Mon's shift)
    assert ok(ist(2, 0, day=17))             # Sat 02:00 (Fri's shift)
    assert not ok(ist(23, 0, day=17))        # Sat 23:00 (Saturday not allowed)
    assert not ok(ist(2, 0, day=18))         # Sun 02:00 (Sat's shift, not allowed)
    assert not ok(ist(12, 0, day=12))        # midday


def test_end_of_day_24_00(context):
    p = make_policy(business_hours_start="09:00", business_hours_end="24:00")
    late = replace(context, now=datetime(2026, 10, 12, 23, 59, tzinfo=timezone.utc))
    assert evaluate_policies(late, [p]).decision is Decision.ALLOW


def test_dst_transition_uses_local_wall_clock(context):
    # US DST starts 2026-03-08. 14:00 UTC = 10:00 EDT (after) but 09:00 EST (before).
    p = make_policy(timezone_name="America/New_York", business_hours_start="09:30", business_hours_end="17:00")
    before = replace(context, now=datetime(2026, 3, 7, 14, 0, tzinfo=timezone.utc))   # 09:00 EST -> outside
    after = replace(context, now=datetime(2026, 3, 8, 14, 0, tzinfo=timezone.utc))    # 10:00 EDT -> inside
    assert evaluate_policies(before, [p]).decision is Decision.DENY
    assert evaluate_policies(after, [p]).decision is Decision.ALLOW


# ---------- selectors ----------
def test_target_restriction(context):
    p = make_policy(target_ids=frozenset({"different-target"}))
    assert evaluate_policies(context, [p]).decision is Decision.DENY


def test_case_and_whitespace_normalisation(context, policy):
    c = replace(context, role=" operator ", environment="Staging", protocol="ssh")
    assert evaluate_policies(c, [policy]).decision is Decision.ALLOW


def test_multiple_roles(context, policy):
    c = replace(context, role="Viewer", extra_roles=frozenset({"Operator"}))
    assert evaluate_policies(c, [policy]).decision is Decision.ALLOW


def test_deny_on_secondary_role(context, policy):
    deny = Policy(policy_id="D", version=1, name="no auditors", effect="DENY", allowed_roles=frozenset({"Auditor"}))
    c = replace(context, extra_roles=frozenset({"Auditor"}))
    assert evaluate_policies(c, [policy, deny]).decision is Decision.DENY


def test_criticality_selector(context):
    p = make_policy(criticalities=frozenset({"low", "medium"}))
    assert evaluate_policies(replace(context, criticality="Low"), [p]).decision is Decision.ALLOW
    assert evaluate_policies(replace(context, criticality="critical"), [p]).decision is Decision.DENY
    assert evaluate_policies(replace(context, criticality=None), [p]).decision is Decision.DENY


def test_unknown_criticality_still_triggers_deny_rules(context, policy):
    deny = Policy(policy_id="D", version=1, name="no critical", effect="DENY", criticalities=frozenset({"critical"}))
    assert evaluate_policies(replace(context, criticality=None), [policy, deny]).decision is Decision.DENY


def test_requires_assignment(context):
    p = make_policy(requires_assignment=True)
    assert evaluate_policies(context, [p]).decision is Decision.DENY
    assert evaluate_policies(replace(context, assigned_policy_ids=frozenset({"POL-TEST"})), [p]).decision is Decision.ALLOW


# ---------- fail-closed validation ----------
def test_invalid_context_time_denied(context, policy):
    out = evaluate_policies(replace(context, now=datetime(2026, 10, 12, 10, 0)), [policy])
    assert out.decision is Decision.DENY and codes(out) == ["INVALID_CONTEXT"]


def test_blank_context_fields_denied(context, policy):
    for field in ("role", "environment", "protocol", "target_id", "user_id"):
        assert evaluate_policies(replace(context, **{field: "  "}), [policy]).decision is Decision.DENY


def test_non_context_object_denied(policy):
    assert evaluate_policies(None, [policy]).decision is Decision.DENY


def test_invalid_policy_fails_closed_with_code(context):
    p = make_policy(business_hours_start="25:00", business_hours_end="26:00")
    out = evaluate_policies(context, [p])
    assert out.decision is Decision.DENY and codes(out) == ["POLICY_INVALID"]


def test_invalid_policy_denies_even_when_its_selectors_do_not_match(context, policy):
    bad = make_policy(policy_id="BAD", environments=frozenset({"production"}), timezone_name="Mars/Base")
    assert evaluate_policies(context, [policy, bad]).decision is Decision.DENY


def test_allow_policy_with_empty_selectors_is_rejected(context):
    wildcard = Policy(policy_id="X", version=1, name="oops", max_duration_minutes=60)
    out = evaluate_policies(replace(context, role="Intern", environment="production", protocol="RDP"), [wildcard])
    assert out.decision is Decision.DENY and codes(out) == ["POLICY_INVALID"]


def test_global_deny_policy_may_be_wildcard(context, policy):
    deny = Policy(policy_id="D", version=1, name="freeze", effect="DENY")
    assert evaluate_policies(context, [policy, deny]).decision is Decision.DENY


def test_non_policy_objects_denied(context):
    assert evaluate_policies(context, [object()]).decision is Decision.DENY
