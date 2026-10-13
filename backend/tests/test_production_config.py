"""
Tests for Production Configuration Hardening (Task D).

Verifies:
- Rejection of default/placeholder GATEWAY_AUTH_TOKEN in production.
- Rejection of short (< 32 char) GATEWAY_AUTH_TOKEN in production.
- Acceptance of strong GATEWAY_AUTH_TOKEN in production.
- Usable defaults in development and test environments.
- Fail-closed behavior for internal authentication.
"""

import pytest
from app.core.config import Settings, SettingsError

STRONG_SECRET = "x" * 48
STRONG_TOKEN = "a" * 32
DEFAULT_TOKEN = "dev-insecure-change-me-in-production"


def make_settings(**kw) -> Settings:
    return Settings(_env_file=None, **kw)


def test_production_rejects_placeholder_gateway_auth_token():
    """Production mode must reject default dev gateway token."""
    with pytest.raises(SettingsError, match="GATEWAY_AUTH_TOKEN must be changed"):
        make_settings(
            ENVIRONMENT="production",
            DEV_MODE=False,
            SECRET_KEY=STRONG_SECRET,
            SECRET_PROVIDER="openbao",
            OPENBAO_ADDR="https://bao:8200",
            OPENBAO_TOKEN="t",
            GATEWAY_AUTH_TOKEN=DEFAULT_TOKEN,
        )


def test_production_rejects_short_gateway_auth_token():
    """Production mode must reject gateway auth tokens shorter than 32 characters."""
    with pytest.raises(SettingsError, match="at least 32 characters"):
        make_settings(
            ENVIRONMENT="production",
            DEV_MODE=False,
            SECRET_KEY=STRONG_SECRET,
            SECRET_PROVIDER="openbao",
            OPENBAO_ADDR="https://bao:8200",
            OPENBAO_TOKEN="t",
            GATEWAY_AUTH_TOKEN="short-weak-token",
        )


def test_production_accepts_strong_gateway_auth_token():
    """Production mode accepts strong gateway auth token >= 32 characters."""
    s = make_settings(
        ENVIRONMENT="production",
        DEV_MODE=False,
        SECRET_KEY=STRONG_SECRET,
        SECRET_PROVIDER="openbao",
        OPENBAO_ADDR="https://bao:8200",
        OPENBAO_TOKEN="t",
        GATEWAY_AUTH_TOKEN=STRONG_TOKEN,
    )
    assert s.GATEWAY_AUTH_TOKEN.get_secret_value() == STRONG_TOKEN
    assert s.DEV_MODE is False


def test_development_allows_default_gateway_auth_token():
    """Settings load in development; the auth hook itself still refuses the
    placeholder (see test_gateway_security)."""
    s = make_settings(
        ENVIRONMENT="development",
        DEV_MODE=True,
        GATEWAY_AUTH_TOKEN=DEFAULT_TOKEN,
    )
    assert s.GATEWAY_AUTH_TOKEN.get_secret_value() == DEFAULT_TOKEN


def test_production_allows_unset_gateway_token():
    """No gateway deployed: startup succeeds and the auth hook rejects everything."""
    s = make_settings(
        ENVIRONMENT="production",
        DEV_MODE=False,
        SECRET_KEY=STRONG_SECRET,
        SECRET_PROVIDER="openbao",
        OPENBAO_ADDR="https://bao:8200",
        OPENBAO_TOKEN="t",
    )
    assert s.GATEWAY_AUTH_TOKEN.get_secret_value() == ""
