from datetime import datetime, timezone
import pytest
from securepam_policy_engine.models import AccessContext, Policy


@pytest.fixture
def context():
    # Monday 2026-10-12 10:00 UTC (15:30 IST)
    return AccessContext(
        request_id="req-100", user_id="user-10", role="Operator",
        target_id="srv-01", target_registered=True, environment="staging",
        protocol="SSH", requested_duration_minutes=20, mfa_satisfied=True,
        risk_score=20, now=datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc),
    )


def make_policy(**kw):
    base = dict(policy_id="POL-TEST", version=1, name="Test allow",
                allowed_roles=frozenset({"Operator"}), environments=frozenset({"staging"}),
                protocols=frozenset({"SSH"}), max_duration_minutes=30)
    base.update(kw)
    return Policy(**base)


@pytest.fixture
def policy():
    return make_policy()
