"""
Asset CRUD + RBAC (at the HTTP level — Phase 2's test_rbac.py already
covers the RoleChecker/PermissionChecker mechanism directly; these test
the real endpoints) + pagination/filtering/sorting.
"""

from httpx import AsyncClient

from tests.conftest import auth_header

VALID_ASSET = {
    "name": "TEST-ASSET",
    "hostname": "test-asset.internal",
    "ip_address": "10.0.9.1",
    "port": 22,
    "protocol": "SSH",
    "asset_type": "LINUX_SERVER",
    "environment": "TEST",
    "criticality": "LOW",
}


async def test_list_assets_requires_authentication(client: AsyncClient):
    resp = await client.get("/api/v1/assets")
    assert resp.status_code == 401


async def test_operator_can_read_assets(client: AsyncClient, operator_token: str):
    resp = await client.get("/api/v1/assets", headers=auth_header(operator_token))
    assert resp.status_code == 200
    # Seed data creates exactly 5 assets.
    assert resp.json()["total"] == 5


async def test_auditor_can_read_assets(client: AsyncClient, auditor_token: str):
    resp = await client.get("/api/v1/assets", headers=auth_header(auditor_token))
    assert resp.status_code == 200


async def test_admin_can_create_asset(client: AsyncClient, admin_token: str):
    resp = await client.post("/api/v1/assets", json=VALID_ASSET, headers=auth_header(admin_token))
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "TEST-ASSET"
    assert body["created_by"] is not None
    assert body["id"]


async def test_operator_cannot_create_asset(client: AsyncClient, operator_token: str):
    resp = await client.post(
        "/api/v1/assets", json={**VALID_ASSET, "name": "OP-TRY"}, headers=auth_header(operator_token)
    )
    assert resp.status_code == 403


async def test_auditor_cannot_create_asset(client: AsyncClient, auditor_token: str):
    resp = await client.post(
        "/api/v1/assets", json={**VALID_ASSET, "name": "AUD-TRY"}, headers=auth_header(auditor_token)
    )
    assert resp.status_code == 403


async def test_create_asset_invalid_input_returns_422(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/assets",
        json={**VALID_ASSET, "name": "BAD-IP", "ip_address": "not-an-ip"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_create_asset_invalid_enum_returns_422(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/assets",
        json={**VALID_ASSET, "name": "BAD-TYPE", "asset_type": "MAINFRAME"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_get_nonexistent_asset_returns_404(client: AsyncClient, admin_token: str):
    resp = await client.get(
        "/api/v1/assets/00000000-0000-0000-0000-000000000000", headers=auth_header(admin_token)
    )
    assert resp.status_code == 404


async def test_admin_can_update_asset(client: AsyncClient, admin_token: str):
    create = await client.post(
        "/api/v1/assets", json={**VALID_ASSET, "name": "UPDATE-ME"}, headers=auth_header(admin_token)
    )
    asset_id = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/assets/{asset_id}", json={"criticality": "CRITICAL"}, headers=auth_header(admin_token)
    )
    assert resp.status_code == 200
    assert resp.json()["criticality"] == "CRITICAL"
    # Untouched fields are preserved (PATCH semantics, not full replace).
    assert resp.json()["name"] == "UPDATE-ME"


async def test_operator_cannot_update_asset(client: AsyncClient, admin_token: str, operator_token: str):
    create = await client.post(
        "/api/v1/assets", json={**VALID_ASSET, "name": "NO-OP-UPDATE"}, headers=auth_header(admin_token)
    )
    asset_id = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/assets/{asset_id}", json={"criticality": "HIGH"}, headers=auth_header(operator_token)
    )
    assert resp.status_code == 403


async def test_admin_can_delete_asset_and_it_then_404s(client: AsyncClient, admin_token: str):
    create = await client.post(
        "/api/v1/assets", json={**VALID_ASSET, "name": "DELETE-ME"}, headers=auth_header(admin_token)
    )
    asset_id = create.json()["id"]

    delete = await client.delete(f"/api/v1/assets/{asset_id}", headers=auth_header(admin_token))
    assert delete.status_code == 204

    get_after = await client.get(f"/api/v1/assets/{asset_id}", headers=auth_header(admin_token))
    assert get_after.status_code == 404


async def test_auditor_cannot_delete_asset(client: AsyncClient, admin_token: str, auditor_token: str):
    create = await client.post(
        "/api/v1/assets", json={**VALID_ASSET, "name": "NO-AUDITOR-DELETE"}, headers=auth_header(admin_token)
    )
    asset_id = create.json()["id"]

    resp = await client.delete(f"/api/v1/assets/{asset_id}", headers=auth_header(auditor_token))
    assert resp.status_code == 403


# --- Pagination / filtering / sorting ---

async def test_pagination_page_size_is_respected(client: AsyncClient, admin_token: str):
    resp = await client.get(
        "/api/v1/assets", params={"page": 1, "page_size": 2}, headers=auth_header(admin_token)
    )
    body = resp.json()
    assert len(body["items"]) == 2
    assert body["total"] == 5
    assert body["pages"] == 3


async def test_filter_by_environment(client: AsyncClient, admin_token: str):
    resp = await client.get(
        "/api/v1/assets", params={"environment": "PRODUCTION"}, headers=auth_header(admin_token)
    )
    body = resp.json()
    assert body["total"] == 2  # WIN-PROD-01, LINUX-PROD-01
    assert all(item["environment"] == "PRODUCTION" for item in body["items"])


async def test_filter_by_search_matches_hostname(client: AsyncClient, admin_token: str):
    resp = await client.get(
        "/api/v1/assets", params={"search": "staging"}, headers=auth_header(admin_token)
    )
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["name"] == "LINUX-STAGING-01"


async def test_sort_by_name_ascending(client: AsyncClient, admin_token: str):
    resp = await client.get(
        "/api/v1/assets",
        params={"sort_by": "name", "sort_order": "asc", "page_size": 10},
        headers=auth_header(admin_token),
    )
    names = [item["name"] for item in resp.json()["items"]]
    assert names == sorted(names)


async def test_sort_by_disallowed_column_is_ignored_not_errored(client: AsyncClient, admin_token: str):
    # ip_address isn't in the sortable allowlist (app/api/v1/assets.py) —
    # must not 500, must not leak an arbitrary ORDER BY.
    resp = await client.get(
        "/api/v1/assets", params={"sort_by": "ip_address"}, headers=auth_header(admin_token)
    )
    assert resp.status_code == 200


async def test_invalid_sort_order_returns_422(
    client: AsyncClient, admin_token: str
):
    resp = await client.get(
        "/api/v1/assets",
        params={"sort_order": "invalid"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


async def test_zero_page_is_clamped_to_first_page(
    client: AsyncClient, admin_token: str
):
    resp = await client.get(
        "/api/v1/assets",
        params={"page": 0},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200
    assert resp.json()["page"] == 1


async def test_negative_page_is_clamped_to_first_page(
    client: AsyncClient, admin_token: str
):
    resp = await client.get(
        "/api/v1/assets",
        params={"page": -1},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200
    assert resp.json()["page"] == 1


async def test_oversized_page_size_is_capped_at_100(
    client: AsyncClient, admin_token: str
):
    resp = await client.get(
        "/api/v1/assets",
        params={"page_size": 10000},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200
    assert resp.json()["page_size"] == 100


async def test_zero_page_size_is_clamped_to_one(
    client: AsyncClient, admin_token: str
):
    resp = await client.get(
        "/api/v1/assets",
        params={"page_size": 0},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200
    assert resp.json()["page_size"] == 1


async def test_negative_page_size_is_clamped_to_one(
    client: AsyncClient, admin_token: str
):
    resp = await client.get(
        "/api/v1/assets",
        params={"page_size": -1},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200
    assert resp.json()["page_size"] == 1
