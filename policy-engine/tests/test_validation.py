import pytest
from securepam_policy_engine import PolicyConfigurationError, validate_policy
from conftest import make_policy


@pytest.mark.parametrize("kw", [
    dict(effect="MAYBE"), dict(version=0), dict(max_duration_minutes=0), dict(max_duration_minutes=True),
    dict(deny_min_risk=101), dict(approval_min_risk=-1), dict(approval_min_risk=80, deny_min_risk=60),
    dict(allowed_weekdays=frozenset({7})), dict(business_hours_start="09:00"),
    dict(business_hours_start="09:00", business_hours_end="09:00"),
    dict(timezone_name="Nope/Zone"), dict(session_timeout_minutes=0),
    dict(allowed_roles=frozenset()), dict(protocols=frozenset()), dict(environments=frozenset()),
    dict(policy_id=""), dict(allowed_roles=frozenset({""})),
])
def test_bad_policies_rejected(kw):
    with pytest.raises(PolicyConfigurationError):
        validate_policy(make_policy(**kw))


def test_good_policy_accepted():
    validate_policy(make_policy(approval_min_risk=60, deny_min_risk=80,
                                business_hours_start="22:00", business_hours_end="06:00"))
