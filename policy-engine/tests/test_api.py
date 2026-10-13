import pytest
pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from datetime import datetime, timezone
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from securepam_policy_engine import AccessContext, PolicyEvaluator
from securepam_policy_engine.api import create_policy_router
from securepam_policy_engine.db import Base, SqlAlchemyPolicyRepository
from securepam_policy_engine.default_policies import DEFAULT_POLICIES
from securepam_policy_engine.repository import InMemoryPolicyRepository


def authenticated(authorization: str = Header(None)):
    """Stand-in for the backend's auth dependency."""
    if authorization not in ("Bearer u1", "Bearer u2"):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return authorization.removeprefix("Bearer ")


def provider(request_id, request, actor):
    if actor != "u1":  # REQ-* belong to u1 in this fixture
        raise HTTPException(status_code=404, detail="Access request not found")
    return AccessContext(request_id=request_id, user_id="u1", role="Operator", target_id="srv-1",
                         target_registered=True, environment="staging", protocol="SSH",
                         requested_duration_minutes=20, mfa_satisfied=True, risk_score=10,
                         now=datetime(2026, 10, 12, 5, 30, tzinfo=timezone.utc))


def build(admin=False):
    audit = []
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=__import__("sqlalchemy.pool", fromlist=["StaticPool"]).StaticPool)
    Base.metadata.create_all(engine)
    repo = SqlAlchemyPolicyRepository(sessionmaker(engine), audit_sink=audit.append)
    for p in DEFAULT_POLICIES:
        repo.publish(p, actor="seed")
    audit.clear()
    app = FastAPI()
    kw = dict(repository=repo, admin_dependency=lambda: "admin-1") if admin else {}
    app.include_router(create_policy_router(PolicyEvaluator(repo), provider, audit_sink=audit.append,
                                            auth_dependency=authenticated, **kw))
    return TestClient(app, headers={"Authorization": "Bearer u1"}), audit


def test_evaluation_endpoint_returns_decision_and_audits():
    client, audit = build()
    r = client.post("/access-requests/REQ-7/policy-evaluation")
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "ALLOW" and body["can_proceed"] and body["request_id"] == "REQ-7"
    assert audit[0]["event"] == "policy.evaluated" and audit[0]["decision"] == "ALLOW"


def test_client_cannot_inject_authoritative_values():
    client, _ = build()
    r = client.post("/access-requests/REQ-7/policy-evaluation",
                    json={"role": "Administrator", "risk_score": 0, "mfa_satisfied": True, "decision": "ALLOW"})
    assert r.status_code == 200 and r.json()["risk_score"] == 10  # server-side context only


def test_admin_routes_not_mounted_without_dependency():
    client, _ = build(admin=False)
    assert client.get("/policies").status_code == 404
    assert client.post("/policies", json={}).status_code in (404, 405)


def test_admin_publish_list_disable():
    client, audit = build(admin=True)
    new = {"policy_id": "POL-900", "name": "Test", "allowed_roles": ["Operator"], "environments": ["staging"],
           "protocols": ["SSH"], "change_note": "demo"}
    r = client.post("/policies", json=new)
    assert r.status_code == 201 and r.json()["version"] == 1
    assert any(p["policy_id"] == "POL-900" for p in client.get("/policies").json())
    assert client.post("/policies/POL-900/disable").json()["enabled"] is False
    assert client.post("/policies/NOPE/disable").status_code == 404
    assert [e["actor"] for e in audit if e["event"].startswith("policy.")] == ["admin-1", "admin-1"]


def test_admin_rejects_unsafe_or_unknown_input():
    client, _ = build(admin=True)
    wildcard = {"policy_id": "POL-901", "name": "oops"}  # ALLOW with empty selectors
    assert client.post("/policies", json=wildcard).status_code == 422
    assert client.post("/policies", json={**wildcard, "version": 50, "allowed_roles": ["x"]}).status_code == 422


def test_router_cannot_be_built_without_authentication():
    with pytest.raises(TypeError):
        create_policy_router(PolicyEvaluator(InMemoryPolicyRepository([])), provider)
    with pytest.raises(ValueError):
        create_policy_router(PolicyEvaluator(InMemoryPolicyRepository([])), provider, auth_dependency=None)


def test_evaluation_requires_authentication():
    client, audit = build()
    r = client.post("/access-requests/REQ-7/policy-evaluation", headers={"Authorization": ""})
    assert r.status_code == 401 and audit == []


def test_evaluation_of_another_users_request_is_refused():
    client, audit = build()
    r = client.post("/access-requests/REQ-7/policy-evaluation", headers={"Authorization": "Bearer u2"})
    assert r.status_code == 404 and audit == []
