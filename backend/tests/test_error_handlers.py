import pytest
from fastapi import HTTPException
import httpx
from app.main import app


@pytest.mark.asyncio
async def test_http_exception_uses_standard_error_envelope(client):
    @app.get("/__test_http_exception__")
    async def test_http_exception_route():
        raise HTTPException(status_code=418, detail="Test error")

    try:
        response = await client.get("/__test_http_exception__")

        assert response.status_code == 418
        assert response.json() == {
            "detail": "Test error",
            "error_code": None,
            "errors": None,
        }
        assert "x-request-id" in response.headers
    finally:
        app.router.routes[:] = [
            route
            for route in app.router.routes
            if getattr(route, "path", None) != "/__test_http_exception__"
        ]


@pytest.mark.asyncio
async def test_unexpected_exception_returns_safe_500_response(client):
    @app.get("/__test_unexpected_exception__")
    async def test_unexpected_exception_route():
        raise RuntimeError("internal-secret-test-detail")

    try:

        transport = httpx.ASGITransport(
            app=app,
            raise_app_exceptions=False,
        )

        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as test_client:
            response = await test_client.get(
                "/__test_unexpected_exception__",
                headers={"X-Request-ID": "safe-error-test-123"},
            )

        assert response.status_code == 500
        body = response.json()
        assert body["detail"] == (
            "An internal error occurred. Please try again later."
        )
        assert body["error_code"] == "INTERNAL_ERROR"
        assert body["errors"] is None
        assert "internal-secret-test-detail" not in response.text
        assert response.headers["x-request-id"] == "safe-error-test-123"
    finally:
        app.router.routes[:] = [
            route
            for route in app.router.routes
            if getattr(route, "path", None) != "/__test_unexpected_exception__"
        ]