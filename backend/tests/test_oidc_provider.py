
"""Tests for Keycloak OIDC token validation."""

import time
from unittest.mock import Mock, patch
import httpx
import pytest
from jose import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from app.auth.base import InvalidTokenError
from app.auth.oidc_provider import OIDCProviderUnavailableError, OIDCTokenValidator
from app.core.config import settings


@pytest.fixture
def rsa_keys():
    """Generate trusted and untrusted RSA key pairs for tests."""

    def make_key(kid):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_numbers = private_key.public_key().public_numbers()

        def to_base64url(value):
            import base64

            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        jwk = {
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": to_base64url(public_numbers.n),
            "e": to_base64url(public_numbers.e),
        }
        return private_key, jwk

    trusted_private, trusted_jwk = make_key("trusted-key")
    untrusted_private, _ = make_key("untrusted-key")

    return trusted_private, trusted_jwk, untrusted_private



@pytest.fixture
def oidc_setup(rsa_keys, monkeypatch):
    trusted_private, trusted_jwk, untrusted_private = rsa_keys

    # These URLs are derived from KEYCLOAK_URL and KEYCLOAK_REALM.
    monkeypatch.setattr(settings, "KEYCLOAK_URL", "https://idp.example")
    monkeypatch.setattr(settings, "KEYCLOAK_REALM", "securepam")
    monkeypatch.setattr(settings, "KEYCLOAK_CLIENT_ID", "securepam-app")

    # Ensure one test cannot reuse another test's cached keys.
    OIDCTokenValidator._jwks_cache.clear()

    response = Mock()
    response.json.return_value = {"keys": [trusted_jwk]}
    response.raise_for_status.return_value = None

    patcher = patch(
        "app.auth.oidc_provider.httpx.get",
        return_value=response,
    )
    mock_get = patcher.start()

    yield trusted_private, untrusted_private, mock_get

    patcher.stop()
    OIDCTokenValidator._jwks_cache.clear()



def make_token(private_key, *, issuer=None, audience=None, exp=None, kid="trusted-key"):
    now = int(time.time())
    claims = {
        "sub": "keycloak-user-123",
        "iss": issuer or settings.KEYCLOAK_ISSUER_URL,
        "aud": audience or settings.KEYCLOAK_CLIENT_ID,
        "iat": now,
        "exp": exp if exp is not None else now + 300,
        "email": "user@example.com",
        "name": "Example User",
        "realm_access": {"roles": ["USER"]},
    }
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


def test_valid_token_returns_identity(oidc_setup):
    trusted_private, _, mock_get = oidc_setup
    validator = OIDCTokenValidator()

    token = make_token(trusted_private)
    identity = validator.validate(token)

    assert identity.subject == "keycloak-user-123"
    assert identity.email == "user@example.com"
    assert identity.name == "Example User"
    assert identity.token_roles == ["USER"]
    mock_get.assert_called_once()


def test_expired_token_is_rejected(oidc_setup):
    trusted_private, _, _ = oidc_setup
    token = make_token(trusted_private, exp=int(time.time()) - 60)

    with pytest.raises(InvalidTokenError):
        OIDCTokenValidator().validate(token)


def test_wrong_issuer_is_rejected(oidc_setup):
    trusted_private, _, _ = oidc_setup
    token = make_token(trusted_private, issuer="https://evil.example/")

    with pytest.raises(InvalidTokenError):
        OIDCTokenValidator().validate(token)


def test_wrong_audience_is_rejected(oidc_setup):
    trusted_private, _, _ = oidc_setup
    token = make_token(trusted_private, audience="another-app")

    with pytest.raises(InvalidTokenError):
        OIDCTokenValidator().validate(token)


def test_untrusted_signing_key_is_rejected(oidc_setup):
    _, untrusted_private, mock_get = oidc_setup
    token = make_token(untrusted_private, kid="untrusted-key")

    with pytest.raises(InvalidTokenError):
        OIDCTokenValidator().validate(token)

    # One initial lookup and one refresh after the key ID isn't found.
    assert mock_get.call_count == 2



def test_jwks_outage_is_not_misreported_as_invalid_token(oidc_setup):
    trusted_private, _, mock_get = oidc_setup

    mock_get.side_effect = httpx.ConnectError(
        "network unavailable",
        request=httpx.Request("GET", settings.KEYCLOAK_JWKS_URL),
    )

    token = make_token(trusted_private)

    with pytest.raises(OIDCProviderUnavailableError):
        OIDCTokenValidator().validate(token)


def _forge(header: dict, claims: dict, key: bytes | None) -> str:
    """Hand-build a JWT so the library can't refuse to create the attack token."""
    import base64
    import hashlib
    import hmac
    import json

    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
    sig = b64(hmac.new(key, signing_input.encode(), hashlib.sha256).digest()) if key else ""
    return f"{signing_input}.{sig}"


@pytest.mark.parametrize("encoding", ["DER", "PEM"])
def test_hs256_key_confusion_with_public_key_is_rejected(oidc_setup, encoding):
    """CVE-2024-33663 / CVE-2026-85394 class: an attacker who knows the IdP's
    public key HMAC-signs a token with it. The validator must never accept
    a non-RS256 algorithm, whatever key material the token implies."""
    trusted_private, _, _ = oidc_setup
    public_key = trusted_private.public_key()
    key_bytes = (
        public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if encoding == "DER"
        else public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    now = int(time.time())
    claims = {"sub": "attacker", "iss": settings.KEYCLOAK_ISSUER_URL, "aud": settings.KEYCLOAK_CLIENT_ID,
              "iat": now, "exp": now + 300}
    token = _forge({"alg": "HS256", "typ": "JWT", "kid": "trusted-key"}, claims, key_bytes)
    with pytest.raises(InvalidTokenError):
        OIDCTokenValidator().validate(token)


def test_alg_none_is_rejected(oidc_setup):
    now = int(time.time())
    claims = {"sub": "attacker", "iss": settings.KEYCLOAK_ISSUER_URL, "aud": settings.KEYCLOAK_CLIENT_ID,
              "iat": now, "exp": now + 300}
    with pytest.raises(InvalidTokenError):
        OIDCTokenValidator().validate(_forge({"alg": "none", "kid": "trusted-key"}, claims, None))
