"""
SECRET_PROVIDER / OPENBAO_* settings: defaults, fail-safe validation, and
that no validation path ever echoes the token. Builds Settings directly
with _env_file=None so a developer's backend/.env can't influence results.
"""

import pytest

from app.core.config import BACKEND_DIR, Settings, SettingsError
from app.secret_providers import MockSecretProvider, OpenBaoSecretProvider, build_secret_provider

CANARY = "s.TOKENCANARY0123456789"
VALID = dict(SECRET_PROVIDER="openbao", OPENBAO_ADDR="http://127.0.0.1:8200", OPENBAO_TOKEN=CANARY)


def make(**kw) -> Settings:
    return Settings(_env_file=None, **kw)


def test_default_provider_is_mock():
    s = make()
    assert s.SECRET_PROVIDER == "mock"
    assert isinstance(build_secret_provider(s), MockSecretProvider)


def test_env_file_is_anchored_to_backend_dir():
    assert Settings.model_config["env_file"] == str(BACKEND_DIR / ".env")
    assert (BACKEND_DIR / "app").is_dir()


def test_valid_openbao_settings_build_openbao_provider():
    s = make(**VALID)
    assert s.SECRET_PROVIDER == "openbao"
    assert s.OPENBAO_MOUNT_POINT == "secret"
    assert isinstance(build_secret_provider(s), OpenBaoSecretProvider)


def test_provider_name_is_case_insensitive():
    assert make(**{**VALID, "SECRET_PROVIDER": " OpenBao "}).SECRET_PROVIDER == "openbao"


def test_unknown_provider_rejected():
    with pytest.raises(Exception):
        make(SECRET_PROVIDER="hashicorp")


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"OPENBAO_TOKEN": ""}, "OPENBAO_TOKEN is required"),
        ({"OPENBAO_TOKEN": "   "}, "OPENBAO_TOKEN is required"),
        ({"OPENBAO_TOKEN": "s.has space"}, "whitespace or non-printable"),
        ({"OPENBAO_TOKEN": "s.newline\n"}, "whitespace or non-printable"),
        ({"OPENBAO_ADDR": ""}, "OPENBAO_ADDR is required"),
        ({"OPENBAO_ADDR": "ftp://127.0.0.1:8200"}, "OPENBAO_ADDR must be"),
        ({"OPENBAO_ADDR": "http://user:pw@127.0.0.1:8200"}, "OPENBAO_ADDR must be"),
        ({"OPENBAO_ADDR": "http://127.0.0.1:8200/v1/secret"}, "OPENBAO_ADDR must be"),
        ({"OPENBAO_ADDR": "http://127.0.0.1:notaport"}, "OPENBAO_ADDR must be"),
        ({"OPENBAO_MOUNT_POINT": "../sys"}, "OPENBAO_MOUNT_POINT is invalid"),
        ({"OPENBAO_MOUNT_POINT": "/secret"}, "OPENBAO_MOUNT_POINT is invalid"),
        ({"OPENBAO_SECRET_PATH_PREFIX": "a/../b"}, "OPENBAO_SECRET_PATH_PREFIX is invalid"),
        ({"OPENBAO_REQUEST_TIMEOUT_SECONDS": 0}, "TIMEOUT_SECONDS must be positive"),
    ],
)
def test_invalid_openbao_settings_fail_closed(overrides, message):
    with pytest.raises(SettingsError) as exc:
        make(**{**VALID, **overrides})
    assert message in str(exc.value)


def test_missing_openbao_config_never_falls_back_to_mock():
    with pytest.raises(SettingsError):
        make(SECRET_PROVIDER="openbao")


def test_production_refuses_mock_provider():
    with pytest.raises(SettingsError, match="not allowed when ENVIRONMENT=production"):
        make(ENVIRONMENT="production")


def test_production_requires_https():
    with pytest.raises(SettingsError, match="must use https"):
        make(**VALID, ENVIRONMENT="production")
    assert make(**{**VALID, "OPENBAO_ADDR": "https://bao.internal:8200"}, ENVIRONMENT="production",
                DEV_MODE=False, SECRET_KEY="k" * 48)


@pytest.mark.parametrize(
    "overrides",
    [{"OPENBAO_ADDR": "ftp://x"}, {"OPENBAO_ADDR": ""}, {"OPENBAO_MOUNT_POINT": "../x"}],
)
def test_validation_errors_never_contain_token(overrides):
    with pytest.raises(SettingsError) as exc:
        make(**{**VALID, **overrides})
    assert CANARY not in str(exc.value)
    assert CANARY not in repr(exc.value)


def test_token_hidden_in_settings_repr_and_dump():
    s = make(**VALID)
    assert CANARY not in repr(s)
    assert CANARY not in str(s.model_dump())
    assert s.OPENBAO_TOKEN.get_secret_value() == CANARY
