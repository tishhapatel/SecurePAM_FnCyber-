"""
Application CRUD + RBAC + the SSRF-safety requirements from Phase 3's
spec: reject localhost/loopback/link-local/metadata/malformed targets,
accept legitimate internal hostnames, and always derive target_url
server-side (never accept it as client input).
"""

from httpx import AsyncClient

from tests.conftest import auth_header

VALID_APP = {
    "name": "TEST-APP",
    "hostname": "test-app.internal",
    "port": 443,
    "protocol": "HTTPS",
}


async def test_list_applications_requires_authentication(client: AsyncClient):
    resp = await client.get("/api/v1/applications")
    assert resp.status_code == 401


async def test_operator_can_read_applications(client: AsyncClient, operator_token: str):
    resp = await client.get("/api/v1/applications", headers=auth_header(operator_token))
    assert resp.status_code == 200
    assert resp.json()["total"] == 3  # seed data: Admin Portal, Monitoring Dashboard, CI/CD Pipeline


async def test_admin_can_create_application(client: AsyncClient, admin_token: str):
    resp = await client.post("/api/v1/applications", json=VALID_APP, headers=auth_header(admin_token))
    assert resp.status_code == 201
    body = resp.json()
    assert body["target_url"] == "https://test-app.internal:443"
    assert body["created_by"] is not None


async def test_target_url_is_not_a_client_controllable_field(client: AsyncClient, admin_token: str):
    """Even if a client sends target_url in the body, it's ignored — the
    schema has no such field, so it's derived server-side regardless."""
    resp = await client.post(
        "/api/v1/applications",
        json={**VALID_APP, "name": "IGNORE-TARGET-URL", "target_url": "https://evil.example.com"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201
    assert resp.json()["target_url"] == "https://test-app.internal:443"


async def test_operator_cannot_create_application(client: AsyncClient, operator_token: str):
    resp = await client.post(
        "/api/v1/applications", json={**VALID_APP, "name": "OP-TRY"}, headers=auth_header(operator_token)
    )
    assert resp.status_code == 403


async def test_auditor_cannot_create_application(client: AsyncClient, auditor_token: str):
    resp = await client.post(
        "/api/v1/applications", json={**VALID_APP, "name": "AUD-TRY"}, headers=auth_header(auditor_token)
    )
    assert resp.status_code == 403


async def test_reject_localhost(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/applications",
        json={**VALID_APP, "name": "bad-localhost", "hostname": "localhost"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_reject_loopback_ip(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/applications",
        json={**VALID_APP, "name": "bad-loopback", "hostname": "127.0.0.1"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_reject_ipv6_loopback(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/applications",
        json={**VALID_APP, "name": "bad-loopback6", "hostname": "::1"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_reject_cloud_metadata_link_local(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/applications",
        json={**VALID_APP, "name": "bad-metadata", "hostname": "169.254.169.254"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_reject_malformed_hostname(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/applications",
        json={**VALID_APP, "name": "bad-malformed", "hostname": "not a host!"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_reject_unsupported_protocol(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/applications",
        json={**VALID_APP, "name": "bad-protocol", "protocol": "FTP"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_reject_port_out_of_range(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/applications",
        json={**VALID_APP, "name": "bad-port", "port": 99999},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_internal_hostname_is_allowed(client: AsyncClient, admin_token: str):
    """Private-network internal hostnames ARE the point of this product —
    only the specific disallowed categories above should ever be rejected."""
    resp = await client.post(
        "/api/v1/applications",
        json={**VALID_APP, "name": "legit-internal", "hostname": "payroll.internal"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201


async def test_update_revalidates_and_rederives_target_url(client: AsyncClient, admin_token: str):
    create = await client.post(
        "/api/v1/applications", json={**VALID_APP, "name": "UPDATE-TARGET"}, headers=auth_header(admin_token)
    )
    app_id = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/applications/{app_id}", json={"hostname": "new-host.internal"}, headers=auth_header(admin_token)
    )
    assert resp.status_code == 200
    assert resp.json()["target_url"] == "https://new-host.internal:443"


async def test_update_to_unsafe_hostname_is_rejected(client: AsyncClient, admin_token: str):
    create = await client.post(
        "/api/v1/applications", json={**VALID_APP, "name": "UPDATE-TO-BAD"}, headers=auth_header(admin_token)
    )
    app_id = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/applications/{app_id}", json={"hostname": "localhost"}, headers=auth_header(admin_token)
    )
    assert resp.status_code == 422


async def test_get_nonexistent_application_returns_404(client: AsyncClient, admin_token: str):
    resp = await client.get(
        "/api/v1/applications/00000000-0000-0000-0000-000000000000", headers=auth_header(admin_token)
    )
    assert resp.status_code == 404


async def test_admin_can_delete_application(client: AsyncClient, admin_token: str):
    create = await client.post(
        "/api/v1/applications", json={**VALID_APP, "name": "DELETE-ME"}, headers=auth_header(admin_token)
    )
    app_id = create.json()["id"]

    delete = await client.delete(f"/api/v1/applications/{app_id}", headers=auth_header(admin_token))
    assert delete.status_code == 204

    get_after = await client.get(f"/api/v1/applications/{app_id}", headers=auth_header(admin_token))
    assert get_after.status_code == 404


async def test_invalid_sort_order_returns_422(
    client: AsyncClient, admin_token: str
):
    resp = await client.get(
        "/api/v1/applications",
        params={"sort_order": "invalid"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422
