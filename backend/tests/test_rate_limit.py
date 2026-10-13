import uuid
import httpx
import pytest
from pydantic import SecretStr

from app.core.config import settings
from app.core.rate_limit import RateLimitUnavailable, RedisRateLimiter
from app.main import app


@pytest.mark.asyncio
async def test_rate_limiter_allows_requests_under_limit():
    limiter = RedisRateLimiter("redis://localhost:6379/0")
    key = f"securepam-test-rate-limit-{uuid.uuid4().hex}"

    try:
        await limiter._redis.delete(key)

        for _ in range(2):
            allowed, retry_after = await limiter.check(
                key=key,
                limit=2,
                window_seconds=60,
            )
            assert allowed is True
            assert retry_after == 0

        allowed, retry_after = await limiter.check(
            key=key,
            limit=2,
            window_seconds=60,
        )
        assert allowed is False
        assert retry_after >= 1
    finally:
        await limiter._redis.delete(key)
        await limiter.close()


@pytest.mark.asyncio
async def test_rate_limiter_reports_redis_unavailable():
    limiter = RedisRateLimiter("redis://127.0.0.1:1/0")

    try:
        with pytest.raises(RateLimitUnavailable):
            await limiter.check(
                key="securepam-test-unavailable",
                limit=1,
                window_seconds=60,
            )
    finally:
        await limiter.close()


class FakeRateLimiter:
    def __init__(self, allowed=True, unavailable=False):
        self.allowed = allowed
        self.unavailable = unavailable

    async def check(self, *, key, limit, window_seconds=60):
        if self.unavailable:
            raise RateLimitUnavailable()
        return self.allowed, 0 if self.allowed else 42


@pytest.mark.asyncio
async def test_middleware_returns_429_when_limit_is_exceeded(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    app.state.rate_limiter = FakeRateLimiter(allowed=False)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get("/api/v1/__rate_limit_test__")

        assert response.status_code == 429
        assert response.json()["error_code"] == "RATE_LIMIT_EXCEEDED"
        assert response.headers["Retry-After"] == "42"
        assert "X-Request-ID" in response.headers
    finally:
        del app.state.rate_limiter


@pytest.mark.asyncio
async def test_middleware_returns_503_when_redis_is_unavailable(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    app.state.rate_limiter = FakeRateLimiter(unavailable=True)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get("/api/v1/__rate_limit_test__")

        assert response.status_code == 503
        assert response.json()["error_code"] == "RATE_LIMIT_UNAVAILABLE"
        assert response.headers["Retry-After"] == "1"
        assert "X-Request-ID" in response.headers
    finally:
        del app.state.rate_limiter


@pytest.mark.asyncio
async def test_middleware_allows_requests_under_limit(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    app.state.rate_limiter = FakeRateLimiter(allowed=True)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get("/api/v1/__rate_limit_test__")

        # The test URL does not exist, so routing should return 404.
        # A 404 confirms the rate limiter allowed the request through.
        assert response.status_code == 404
        assert "X-Request-ID" in response.headers
    finally:
        del app.state.rate_limiter


GATEWAY_TOKEN = "r" * 48
HOOK = "/api/v1/gateway/internal/auth"
APP_ID = "00000000-0000-0000-0000-000000000000"


async def _call(method, path, headers=None):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(method, path, headers=headers or {})


@pytest.mark.asyncio
@pytest.mark.parametrize("unavailable", [False, True])
async def test_only_the_authenticated_gateway_callback_skips_the_limiter(monkeypatch, unavailable):
    """With a limiter refusing everything, only GET to the hook with the valid
    token reaches its handler; every other request is limited (429) or, with
    Redis down, fails closed (503)."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "GATEWAY_AUTH_TOKEN", SecretStr(GATEWAY_TOKEN))
    app.state.rate_limiter = FakeRateLimiter(allowed=False, unavailable=unavailable)
    blocked = 503 if unavailable else 429
    try:
        exempt = await _call("GET", HOOK, {"X-Gateway-Auth-Token": GATEWAY_TOKEN})
        # Reached the handler, which refuses the missing gateway credential.
        assert exempt.status_code == 403

        for method, path, headers in (
            ("GET", HOOK, {}),                                          # no token
            ("GET", HOOK, {"X-Gateway-Auth-Token": "x" * 48}),          # wrong token
            ("POST", HOOK, {"X-Gateway-Auth-Token": GATEWAY_TOKEN}),    # other method
            ("GET", HOOK + "/", {"X-Gateway-Auth-Token": GATEWAY_TOKEN}),  # other path
            ("GET", f"/api/v1/gateway/apps/{APP_ID}/launch?ticket=x", {"X-Gateway-Auth-Token": GATEWAY_TOKEN}),
            ("GET", f"/api/v1/gateway/apps/{APP_ID}/info", {"X-Gateway-Auth-Token": GATEWAY_TOKEN}),
        ):
            resp = await _call(method, path, headers)
            assert resp.status_code == blocked, (method, path, resp.status_code)
    finally:
        del app.state.rate_limiter


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", ["", "dev-insecure-change-me-in-production", "s" * 31])
async def test_unconfigured_gateway_token_never_skips_the_limiter(monkeypatch, configured):
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "GATEWAY_AUTH_TOKEN", SecretStr(configured))
    app.state.rate_limiter = FakeRateLimiter(allowed=False)
    try:
        resp = await _call("GET", HOOK, {"X-Gateway-Auth-Token": configured})
        assert resp.status_code == 429
    finally:
        del app.state.rate_limiter
