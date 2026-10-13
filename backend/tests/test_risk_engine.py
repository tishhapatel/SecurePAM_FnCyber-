"""
Risk engine: each factor individually, score/level boundaries, and
explainability. `now` is always injected via RiskContext so
OUTSIDE_BUSINESS_HOURS is deterministic — never dependent on wall-clock
time at test-run time.
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.application import Application
from app.models.asset import Asset
from app.models.user import User
from app.risk.engine import RISK_WEIGHTS, RiskConfiguration, RiskContext, evaluate_risk

# Wednesday 12:00 UTC — inside business hours (09:00-17:00 UTC, Mon-Fri).
BUSINESS_HOURS_NOW = datetime(2025, 1, 8, 12, 0, tzinfo=timezone.utc)
# Saturday 12:00 UTC — outside business hours (weekend).
OFF_HOURS_NOW = datetime(2025, 1, 11, 12, 0, tzinfo=timezone.utc)


async def _get(db_session: AsyncSession, model, **filters):
    conditions = [getattr(model, k) == v for k, v in filters.items()]
    result = await db_session.execute(select(model).where(*conditions))
    obj = result.scalar_one()
    return obj


async def test_production_asset_factor(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    prod_asset = await _get(db_session, Asset, name="WIN-PROD-01")  # PRODUCTION, HIGH

    result = evaluate_risk(
        user=operator, target=prod_asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    codes = {f.code for f in result.factors}
    assert "PRODUCTION_ASSET" in codes
    assert "HIGH_CRITICALITY" in codes


async def test_critical_asset_factor_uses_critical_not_high(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="WIN-PROD-01")
    asset.criticality = "CRITICAL"  # in-memory only, not persisted

    result = evaluate_risk(
        user=operator, target=asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    codes = {f.code for f in result.factors}
    assert "CRITICAL_ASSET" in codes
    assert "HIGH_CRITICALITY" not in codes  # mutually exclusive, not additive


async def test_sensitive_application_factor(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    app = await _get(db_session, Application, name="Admin Portal")  # criticality HIGH

    result = evaluate_risk(
        user=operator, target=app, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    codes = {f.code for f in result.factors}
    assert "SENSITIVE_APPLICATION" in codes
    # Application targets never trigger the asset-worded factors.
    assert "CRITICAL_ASSET" not in codes
    assert "HIGH_CRITICALITY" not in codes


async def test_high_privilege_role_factor(db_session: AsyncSession):
    admin = await _get(db_session, User, username="admin")
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")  # DEVELOPMENT, MEDIUM — avoid other factors

    admin_result = evaluate_risk(
        user=admin, target=asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    operator_result = evaluate_risk(
        user=operator, target=asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    assert "HIGH_PRIVILEGE_ROLE" in {f.code for f in admin_result.factors}
    assert "HIGH_PRIVILEGE_ROLE" not in {f.code for f in operator_result.factors}


async def test_outside_business_hours_factor(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")

    in_hours = evaluate_risk(
        user=operator, target=asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    off_hours = evaluate_risk(
        user=operator, target=asset, requested_duration=15,
        context=RiskContext(now=OFF_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    assert "OUTSIDE_BUSINESS_HOURS" not in {f.code for f in in_hours.factors}
    assert "OUTSIDE_BUSINESS_HOURS" in {f.code for f in off_hours.factors}


async def test_unknown_context_factor(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")

    known = evaluate_risk(
        user=operator, target=asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    unknown = evaluate_risk(
        user=operator, target=asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip=None, prior_request_count=5),
    )
    assert "UNKNOWN_CONTEXT" not in {f.code for f in known.factors}
    assert "UNKNOWN_CONTEXT" in {f.code for f in unknown.factors}


async def test_repeated_auth_failure_factor(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")

    operator.failed_login_count = 3  # in-memory only
    result = evaluate_risk(
        user=operator, target=asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    assert "REPEATED_AUTH_FAILURE" in {f.code for f in result.factors}


async def test_unusual_access_pattern_factor(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")

    first_ever = evaluate_risk(
        user=operator, target=asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=0),
    )
    established = evaluate_risk(
        user=operator, target=asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=10),
    )
    assert "UNUSUAL_ACCESS_PATTERN" in {f.code for f in first_ever.factors}
    assert "UNUSUAL_ACCESS_PATTERN" not in {f.code for f in established.factors}


async def test_long_duration_factor(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")

    short = evaluate_risk(
        user=operator, target=asset, requested_duration=30,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    long = evaluate_risk(
        user=operator, target=asset, requested_duration=120,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    assert "LONG_DURATION" not in {f.code for f in short.factors}
    assert "LONG_DURATION" in {f.code for f in long.factors}


async def test_risk_level_boundaries(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")

    # Zero factors -> score 0 -> LOW.
    none_result = evaluate_risk(
        user=operator, target=asset, requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    assert none_result.score == 0
    assert none_result.level == "LOW"

    # PRODUCTION(30) + HIGH_CRITICALITY(15) + OUTSIDE_BUSINESS_HOURS(20) = 65 -> HIGH.
    prod_asset = await _get(db_session, Asset, name="WIN-PROD-01")
    high_result = evaluate_risk(
        user=operator, target=prod_asset, requested_duration=15,
        context=RiskContext(now=OFF_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
    )
    assert high_result.score == 65
    assert high_result.level == "HIGH"

    # Stack everything applicable to cross into CRITICAL (80+).
    prod_asset.criticality = "CRITICAL"  # 30 + 25 + 20 (hours) + 20 (unknown ctx) + 20 (first-ever) = 115
    critical_result = evaluate_risk(
        user=operator, target=prod_asset, requested_duration=15,
        context=RiskContext(now=OFF_HOURS_NOW, source_ip=None, prior_request_count=0),
    )
    assert critical_result.score == 115
    assert critical_result.level == "CRITICAL"


async def test_explainability_factors_sum_to_score(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    prod_asset = await _get(db_session, Asset, name="WIN-PROD-01")

    result = evaluate_risk(
        user=operator, target=prod_asset, requested_duration=90,
        context=RiskContext(now=OFF_HOURS_NOW, source_ip=None, prior_request_count=0),
    )
    assert result.score == sum(f.points for f in result.factors)
    for factor in result.factors:
        assert factor.code
        assert factor.points > 0
        assert factor.reason  # every factor must be able to explain itself


async def test_configured_weights_factor_switches_and_thresholds(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    prod_asset = await _get(db_session, Asset, name="WIN-PROD-01")
    configured_settings = Settings.model_construct(
        RISK_WEIGHT_PRODUCTION_ASSET=12,
        RISK_ENABLE_HIGH_CRITICALITY=False,
        RISK_HIGH_PRIVILEGE_ROLES=["SECURITY_ADMIN"],
        RISK_MEDIUM_THRESHOLD=10,
        RISK_HIGH_THRESHOLD=25,
        RISK_CRITICAL_THRESHOLD=40,
    )
    configuration = RiskConfiguration.from_settings(configured_settings)
    assert RiskConfiguration.from_settings(Settings.model_construct()).weights == RISK_WEIGHTS

    result = evaluate_risk(
        user=operator,
        target=prod_asset,
        requested_duration=15,
        context=RiskContext(now=BUSINESS_HOURS_NOW, source_ip="10.0.0.1", prior_request_count=5),
        configuration=configuration,
    )

    assert [(factor.code, factor.points) for factor in result.factors] == [("PRODUCTION_ASSET", 12)]
    assert result.score == 12
    assert result.level == "MEDIUM"
    assert configuration.high_privilege_roles == frozenset({"SECURITY_ADMIN"})
    assert result.to_dict()["factors"][0]["reason"] == "Target environment is PRODUCTION"


@pytest.mark.parametrize("overrides", [
    {"RISK_MEDIUM_THRESHOLD": 70, "RISK_HIGH_THRESHOLD": 60},
    {"RISK_MEDIUM_THRESHOLD": 0},
    {"RISK_WEIGHT_PRODUCTION_ASSET": -5},
])
def test_invalid_risk_settings_fail_closed(overrides):
    with pytest.raises(ValueError):
        RiskConfiguration.from_settings(Settings.model_construct(**overrides))
