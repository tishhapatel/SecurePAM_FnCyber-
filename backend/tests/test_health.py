"""Application startup, DB/Redis connectivity, and health endpoint behavior."""

import pytest
from httpx import AsyncClient


async def test_app_starts_and_root_health_responds(client: AsyncClient):
    """Covers 'application startup' — the ASGI app served a request at all."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["dev_mode"] is True


async def test_health_response_includes_request_id_header(client: AsyncClient):
    resp = await client.get("/health")
    assert "x-request-id" in resp.headers


async def test_liveness_never_touches_dependencies(client: AsyncClient):
    """/health/live must succeed even if it never checks DB/Redis."""
    resp = await client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json() == {"status": "alive"}


async def test_readiness_reports_database_and_redis_healthy(client: AsyncClient):
    """Covers 'database connection' — readiness actually queries Postgres + Redis."""
    resp = await client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    services = {c["service"]: c["status"] for c in body["checks"]}
    assert services["database"] == "healthy"
    assert services["redis"] == "healthy"


async def test_detailed_health_reports_all_dev_mode_services_healthy(client: AsyncClient):
    resp = await client.get("/health/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    services = {s["service"]: s["status"] for s in body["services"]}
    assert services["database"] == "healthy"
    assert services["redis"] == "healthy"
    assert services["identity_provider"] == "healthy"
    assert services["vault"] == "healthy"
    assert services["gateway"] == "healthy"
    assert services["siem"] == "healthy"

async def test_health_preserves_caller_supplied_request_id(client: AsyncClient):
    request_id = "securepam-test-request-123"

    resp = await client.get(
        "/health",
        headers={"X-Request-ID": request_id},
    )

    assert resp.status_code == 200
    assert resp.headers["x-request-id"] == request_id


async def test_health_generates_request_id_when_missing(client: AsyncClient):
    resp = await client.get("/health")

    assert resp.status_code == 200
    assert resp.headers["x-request-id"]
    assert len(resp.headers["x-request-id"]) == 36
