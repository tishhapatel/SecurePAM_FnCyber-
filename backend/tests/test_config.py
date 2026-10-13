import pytest
from app.core.config import Settings, SettingsError


def test_development_settings_allow_dev_mode():
    settings = Settings(
        ENVIRONMENT="development",
        DEV_MODE=True,
    )

    assert settings.DEV_MODE is True


def test_production_rejects_dev_mode():
    with pytest.raises(SettingsError):
        Settings(
            ENVIRONMENT="production",
            DEV_MODE=True,
            SECRET_KEY="a-strong-test-secret-key",
        )


def test_production_rejects_placeholder_secret():
    with pytest.raises(SettingsError):
        Settings(
            ENVIRONMENT="production",
            DEV_MODE=False,
            SECRET_KEY=(
                "change-this-to-a-secure-random-string-in-production"
            ),
        )


def test_production_accepts_secure_configuration():
    settings = Settings(
        ENVIRONMENT="production",
        DEV_MODE=False,
        SECRET_KEY="a-strong-test-secret-key-for-testing-only",
        SECRET_PROVIDER="openbao",
        OPENBAO_ADDR="https://openbao.example.test:8200",
        OPENBAO_TOKEN="synthetic-test-token",
    )

    assert settings.DEV_MODE is False
    assert settings.ENVIRONMENT == "production"


@pytest.mark.parametrize("environment", ["production", "staging"])
@pytest.mark.parametrize("secret", ["", "   "])
def test_protected_environments_reject_blank_secret(
    environment, secret
):
    with pytest.raises(SettingsError):
        Settings(
            ENVIRONMENT=environment,
            DEV_MODE=False,
            SECRET_KEY=secret,
        )


def test_staging_rejects_dev_mode():
    with pytest.raises(SettingsError):
        Settings(
            ENVIRONMENT="staging",
            DEV_MODE=True,
            SECRET_KEY="a-strong-test-secret-key",
        )


def test_staging_accepts_secure_configuration():
    settings = Settings(
        ENVIRONMENT="staging",
        DEV_MODE=False,
        SECRET_KEY="a-strong-test-secret-key",
    )

    assert settings.DEV_MODE is False
    assert settings.ENVIRONMENT == "staging"
