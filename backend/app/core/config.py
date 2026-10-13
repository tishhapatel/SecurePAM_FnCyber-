"""
SecurePAM Application Configuration.

All settings are loaded from environment variables.
Secrets must never have default values in production.
"""

import re
from pathlib import Path
from typing import List, Literal
from urllib.parse import urlsplit

from pydantic_settings import BaseSettings
from pydantic import SecretStr, field_validator, model_validator

# backend/ — .env is resolved relative to this, not to the process CWD, so
# `uvicorn` / `alembic` / `pytest` all read the same file no matter where
# they're launched from.
BACKEND_DIR = Path(__file__).resolve().parents[2]

# One or more slash-separated segments of safe characters. Used for the KV
# mount point and the server-side secret path prefix — never "..", never a
# leading/trailing slash.
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")


_DEV_MODE_ENVIRONMENTS = {"development", "test"}
_PLACEHOLDER_SECRET_KEY = "change-this-to-a-secure-random-string-in-production"
_MIN_SECRET_KEY_LENGTH = 32


class SettingsError(Exception):
    """Invalid configuration. Deliberately NOT a ValueError: pydantic wraps
    ValueErrors in a ValidationError whose message embeds the raw input
    (including OPENBAO_TOKEN); a non-ValueError propagates as-is, carrying
    only the sanitized message built below."""


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- Application ---
    APP_NAME: str = "SecurePAM"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEV_MODE: bool = True
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    SECRET_KEY: str = _PLACEHOLDER_SECRET_KEY

    # --- Backend ---
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]
    API_V1_PREFIX: str = "/api/v1"

    # --- Database ---
    DATABASE_URL: str = "postgresql+asyncpg://securepam:securepam_dev_password@localhost:5432/securepam"

    # --- Redis ---
    REDIS_URL: str = "redis://localhost:6379/0"

    # --- Identity Provider ---
    KEYCLOAK_URL: str = "http://keycloak:8080"
    KEYCLOAK_INTERNAL_URL: str = ""
    KEYCLOAK_REALM: str = "securepam"
    KEYCLOAK_CLIENT_ID: str = "securepam-app"
    KEYCLOAK_CLIENT_SECRET: str = ""
    KEYCLOAK_ADMIN_USER: str = "admin"
    KEYCLOAK_ADMIN_PASSWORD: str = ""

    # --- Keycloak MFA Event Synchronization ---
    KEYCLOAK_MFA_SYNC_ENABLED: bool = False
    KEYCLOAK_MFA_SYNC_INTERVAL_SECONDS: int = 60
    KEYCLOAK_MFA_SYNC_LOOKBACK_HOURS: int = 1

    # --- Secret provider (credential retrieval) ---
    # "mock" serves fake credentials only and is refused in production.
    # "openbao" requires OPENBAO_ADDR + OPENBAO_TOKEN; if either is missing
    # or invalid, startup fails — there is no silent fallback to mock.
    SECRET_PROVIDER: Literal["mock", "openbao"] = "mock"
    OPENBAO_ADDR: str = ""
    OPENBAO_MOUNT_POINT: str = "secret"
    OPENBAO_TOKEN: SecretStr = SecretStr("")
    # Alternative to OPENBAO_TOKEN: a file holding the token (e.g. the lab
    # bootstrap's /openbao/runtime/app-token). Read once at startup.
    OPENBAO_TOKEN_FILE: str = ""
    # Every credential reference must live under <mount>/data/<prefix>/...
    OPENBAO_SECRET_PATH_PREFIX: str = "securepam"
    OPENBAO_CONNECT_TIMEOUT_SECONDS: float = 3.0
    OPENBAO_REQUEST_TIMEOUT_SECONDS: float = 5.0
    # Optional CA bundle path for a TLS-terminated OpenBao; empty = system CAs.
    OPENBAO_CA_CERT: str = ""

    # --- Vault (legacy, superseded by SECRET_PROVIDER / OPENBAO_*) ---
    VAULT_URL: str = "http://vault:8200"
    VAULT_TOKEN: str = ""
    VAULT_MOUNT_PATH: str = "secret"
    VAULT_ENABLED: bool = False

    # --- Guacamole ---
    GUACAMOLE_URL: str = "http://guacamole:8080/guacamole"
    GUACAMOLE_ADMIN_USER: str = "guacadmin"
    GUACAMOLE_ADMIN_PASSWORD: str = ""
    GUACD_HOST: str = "guacd"
    GUACD_PORT: int = 4822

    # --- Wazuh SIEM ---
    WAZUH_URL: str = ""
    WAZUH_USER: str = ""
    WAZUH_PASSWORD: str = ""
    WAZUH_ENABLED: bool = False

    # --- Session Defaults ---
    DEFAULT_SESSION_TIMEOUT: int = 30  # minutes
    MAX_SESSION_TIMEOUT: int = 480  # minutes
    JIT_DEFAULT_DURATION: int = 30  # minutes
    JIT_MAX_DURATION: int = 480  # minutes

    # --- Security ---
    TOKEN_EXPIRY_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRY_DAYS: int = 7
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_AUTH_PER_MINUTE: int = 10

    # --- Recordings ---
    RECORDING_STORAGE_PATH: str = "/data/recordings"
    RECORDING_RETENTION_DAYS: int = 90

    # --- Monitoring ---
    PROMETHEUS_ENABLED: bool = False

    @property
    def KEYCLOAK_ISSUER_URL(self) -> str:
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}"

    @property
    def KEYCLOAK_JWKS_URL(self) -> str:
        base_url = self.KEYCLOAK_INTERNAL_URL or self.KEYCLOAK_URL
        return (
            f"{base_url}/realms/{self.KEYCLOAK_REALM}"
            "/protocol/openid-connect/certs"
        )

    @property
    def KEYCLOAK_TOKEN_URL(self) -> str:
        return f"{self.KEYCLOAK_ISSUER_URL}/protocol/openid-connect/token"

    @property
    def KEYCLOAK_AUTH_URL(self) -> str:
        return f"{self.KEYCLOAK_ISSUER_URL}/protocol/openid-connect/auth"

    @field_validator("SECRET_PROVIDER", mode="before")
    @classmethod
    def normalize_secret_provider(cls, v):
        return v.strip().lower() if isinstance(v, str) else v

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        # Messages name the offending setting but never echo a token value.
        errors: List[str] = []
        production = self.ENVIRONMENT.lower() == "production"

        # DEV_MODE enables /auth/login, the DevAuth HS256 validator and the
        # seeded admin123/operator123 accounts. Outside local development
        # or the test suite that is an authentication bypass, so refuse it.
        if self.DEV_MODE and self.ENVIRONMENT.lower() not in _DEV_MODE_ENVIRONMENTS:
            errors.append("DEV_MODE=true is only allowed when ENVIRONMENT is development or test")
        if production and (
            self.SECRET_KEY == _PLACEHOLDER_SECRET_KEY or len(self.SECRET_KEY) < _MIN_SECRET_KEY_LENGTH
        ):
            errors.append(f"SECRET_KEY must be changed and at least {_MIN_SECRET_KEY_LENGTH} characters when ENVIRONMENT=production")

        if self.SECRET_PROVIDER == "mock":
            if production:
                errors.append("SECRET_PROVIDER=mock is not allowed when ENVIRONMENT=production")
        else:
            if self.OPENBAO_TOKEN_FILE:
                if self.OPENBAO_TOKEN.get_secret_value():
                    errors.append("Set only one of OPENBAO_TOKEN and OPENBAO_TOKEN_FILE")
                else:
                    try:
                        file_token = Path(self.OPENBAO_TOKEN_FILE).read_text(encoding="utf-8").strip()
                    except (OSError, UnicodeDecodeError):
                        errors.append("OPENBAO_TOKEN_FILE could not be read")
                    else:
                        self.OPENBAO_TOKEN = SecretStr(file_token)
                        del file_token

            token = self.OPENBAO_TOKEN.get_secret_value()
            if not token.strip():
                errors.append("OPENBAO_TOKEN is required when SECRET_PROVIDER=openbao")
            elif not token.isprintable() or any(c.isspace() for c in token):
                errors.append("OPENBAO_TOKEN contains whitespace or non-printable characters")

            if not self.OPENBAO_ADDR.strip():
                errors.append("OPENBAO_ADDR is required when SECRET_PROVIDER=openbao")
            else:
                try:
                    parts = urlsplit(self.OPENBAO_ADDR)
                    valid = (
                        parts.scheme in ("http", "https")
                        and bool(parts.hostname)
                        and parts.path in ("", "/")
                        and not parts.query
                        and not parts.fragment
                        and parts.username is None
                        and parts.password is None
                    )
                    parts.port  # raises ValueError on a malformed port
                except ValueError:
                    valid = False
                if not valid:
                    errors.append("OPENBAO_ADDR must be a plain http(s)://host[:port] URL")
                elif production and parts.scheme != "https":
                    errors.append("OPENBAO_ADDR must use https when ENVIRONMENT=production")

            if not _SAFE_PATH_RE.match(self.OPENBAO_MOUNT_POINT) or ".." in self.OPENBAO_MOUNT_POINT:
                errors.append("OPENBAO_MOUNT_POINT is invalid")
            if not _SAFE_PATH_RE.match(self.OPENBAO_SECRET_PATH_PREFIX) or ".." in self.OPENBAO_SECRET_PATH_PREFIX:
                errors.append("OPENBAO_SECRET_PATH_PREFIX is invalid")
            if self.OPENBAO_CONNECT_TIMEOUT_SECONDS <= 0 or self.OPENBAO_REQUEST_TIMEOUT_SECONDS <= 0:
                errors.append("OPENBAO_*_TIMEOUT_SECONDS must be positive")

        if errors:
            raise SettingsError("; ".join(errors))
        return self

    model_config = {
        "env_file": str(BACKEND_DIR / ".env"),
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        # .env also carries vars consumed only by docker-compose / other
        # services (POSTGRES_*, REDIS_HOST, NGINX_*, GRAFANA_*) — ignore
        # rather than reject them.
        "extra": "ignore",
    }


# Global settings instance
settings = Settings()
