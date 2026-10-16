"""
Integrated asset + credential provisioning: fail closed when not configured, write through the writer,
verify with the reader, bind only after verification, roll back on any failure, never leak the secret.
"""

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.vault_ref import VaultRef
from app.secret_providers import (
    SecretAccessDeniedError,
    SecretProviderUnavailableError,
    SecretRecord,
)
from tests.conftest import auth_header

PASSWORD = "PW-CANARY-provision-not-real"
STATUS = "/api/v1/credential-provisioning/status"
CREATE = "/api/v1/credential-provisioning/assets"


def asset_body(name="Kali Lab SSH", ip="10.10.0.5"):
    return {"name": name, "hostname": "kali.lab", "ip_address": ip, "port": 22, "protocol": "SSH",
            "asset_type": "LINUX_SERVER", "environment": "DEVELOPMENT", "criticality": "MEDIUM"}


def cred(name="kali", password=PASSWORD):
    return {"secret_name": name, "username": "kali-admin", "password": password}


class FakeWriter:
    def __init__(self, store, fail=None):
        self.store, self.fail, self.writes = store, fail, []

    async def write(self, path, data):
        if self.fail:
            raise self.fail
        self.writes.append(path)
        versions = self.store.setdefault(path, [])
        versions.append(dict(data))
        return len(versions)


class FakeReader:
    def __init__(self, store, tamper=False):
        self.store, self.tamper = store, tamper

    async def read_secret(self, path, version=None):
        data = dict(self.store[path][(version or len(self.store[path])) - 1])
        if self.tamper:
            data["password"] = "something-else"
        return SecretRecord(data=data, version=version)


@pytest.fixture
def openbao(monkeypatch):
    """Pretend this deployment has AWS OpenBao + a writer identity, with in-memory KV behind fakes."""
    import app.secret_providers.writer as writer_mod
    import app.services.credential_provisioning as prov
    from pydantic import SecretStr

    store: dict = {}
    state = {"writer": FakeWriter(store), "reader": FakeReader(store)}
    monkeypatch.setattr(settings, "SECRET_PROVIDER", "openbao")
    monkeypatch.setattr(settings, "OPENBAO_WRITER_TOKEN", SecretStr("writer-canary"))
    monkeypatch.setattr(prov, "get_credential_writer", lambda: state["writer"])
    monkeypatch.setattr(prov, "get_secret_provider", lambda: state["reader"])
    monkeypatch.setattr(writer_mod, "settings", settings)
    state["store"] = store
    return state


async def _no_leak(client, admin_token, db_session, *texts):
    rows = (await db_session.execute(select(AuditLog))).scalars().all()
    assert all(PASSWORD not in str(r.details) for r in rows)
    for t in texts:
        assert PASSWORD not in t


async def test_not_configured_fails_closed_and_creates_nothing(client, db_session, admin_token):
    # default test settings: mock provider, no writer -> never accepts real credentials
    s = await client.get(STATUS, headers=auth_header(admin_token))
    assert s.status_code == 200 and s.json()["configured"] is False and "development stand-in" in s.json()["reason"]
    r = await client.post(CREATE, headers=auth_header(admin_token), json={"asset": asset_body(), "credential": cred()})
    assert r.status_code == 503 and r.json()["error_code"] == "PROVISIONING_NOT_CONFIGURED"
    assert (await db_session.execute(select(Asset).where(Asset.name == "Kali Lab SSH"))).scalar_one_or_none() is None
    await _no_leak(client, admin_token, db_session, r.text)


async def test_create_with_credential_writes_verifies_and_binds(client, db_session, admin_token, openbao):
    r = await client.post(CREATE, headers=auth_header(admin_token), json={"asset": asset_body(), "credential": cred()})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["vault_path"] == "securepam/assets/kali" and body["version"] == 1 and body["verified"] is True
    assert openbao["writer"].writes == ["securepam/assets/kali"]
    asset = (await db_session.execute(select(Asset).where(Asset.name == "Kali Lab SSH"))).scalar_one()
    ref = (await db_session.execute(select(VaultRef).where(VaultRef.asset_id == asset.id))).scalar_one()
    assert ref.is_active and ref.vault_path == "securepam/assets/kali" and ref.username == "kali-admin"
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "CREDENTIAL_PROVISIONED"))).scalar_one()
    assert audit.result == "SUCCESS" and audit.details["version"] == 1 and audit.details["verified"] is True
    s = await client.get(STATUS, headers=auth_header(admin_token))
    kali = next(x for x in s.json()["references"] if x["name"] == "kali")
    assert kali["bound_asset_name"] == "Kali Lab SSH"
    await _no_leak(client, admin_token, db_session, r.text, s.text,
                   (await client.get(f"/api/v1/assets/{asset.id}", headers=auth_header(admin_token))).text)


@pytest.mark.parametrize("failure, stage, code, http", [
    (SecretAccessDeniedError("denied"), "write", "WRITE_DENIED", 502),
    (SecretProviderUnavailableError("OpenBao is unreachable"), "write", "OPENBAO_UNAVAILABLE", 503),
])
async def test_write_failure_rolls_back_the_asset(client, db_session, admin_token, openbao, failure, stage, code, http):
    openbao["writer"].fail = failure
    r = await client.post(CREATE, headers=auth_header(admin_token), json={"asset": asset_body(), "credential": cred()})
    assert r.status_code == http and r.json()["stage"] == stage and r.json()["error_code"] == code
    assert r.json()["recovery"]
    assert (await db_session.execute(select(Asset).where(Asset.name == "Kali Lab SSH"))).scalar_one_or_none() is None
    assert (await db_session.execute(select(VaultRef))).scalars().all() == []
    failed = (await db_session.execute(select(AuditLog).where(AuditLog.action == "CREDENTIAL_PROVISIONED"))).scalar_one()
    assert failed.result == "FAILURE" and failed.details["stage"] == stage
    await _no_leak(client, admin_token, db_session, r.text)


async def test_unverifiable_write_is_not_bound_and_reports_the_written_version(client, db_session, admin_token, openbao):
    openbao["reader"].tamper = True
    r = await client.post(CREATE, headers=auth_header(admin_token), json={"asset": asset_body(), "credential": cred()})
    assert r.status_code == 502 and r.json()["stage"] == "verify" and r.json()["written_version"] == 1
    assert "NOT bound" in r.json()["recovery"]
    assert (await db_session.execute(select(VaultRef))).scalars().all() == []
    assert (await db_session.execute(select(Asset).where(Asset.name == "Kali Lab SSH"))).scalar_one_or_none() is None


@pytest.mark.parametrize("payload", [
    {"secret_name": "win11-lab/../kali", "username": "u", "password": PASSWORD},
    {"secret_name": "kali", "username": "u", "password": PASSWORD, "vault_path": "secret/data/x"},
    {"secret_name": "kali", "username": "u", "password": ""},
    {"secret_name": "kali", "username": "u", "password": PASSWORD, "secret_type": "ROOT_TOKEN"},
])
async def test_invalid_input_rejected_without_echoing_the_password(client, db_session, admin_token, openbao, payload):
    r = await client.post(CREATE, headers=auth_header(admin_token), json={"asset": asset_body(), "credential": payload})
    assert r.status_code == 422 and PASSWORD not in r.text
    assert openbao["writer"].writes == []


async def test_only_allowlisted_names_and_one_asset_per_reference(client, db_session, admin_token, openbao):
    r = await client.post(CREATE, headers=auth_header(admin_token),
                          json={"asset": asset_body(), "credential": cred(name="wazuh-dashboard")})
    assert r.status_code == 422 and r.json()["error_code"] == "SECRET_NAME_NOT_ALLOWLISTED"
    assert (await client.post(CREATE, headers=auth_header(admin_token),
                              json={"asset": asset_body(), "credential": cred()})).status_code == 201
    second = await client.post(CREATE, headers=auth_header(admin_token),
                               json={"asset": asset_body(name="Other", ip="10.10.0.6"), "credential": cred()})
    assert second.status_code == 409 and second.json()["error_code"] == "SECRET_ALREADY_BOUND"
    assert openbao["writer"].writes == ["securepam/assets/kali"]


async def test_rotate_existing_asset_credential_and_retry_path(client, db_session, admin_token, openbao):
    created = await client.post(CREATE, headers=auth_header(admin_token), json={"asset": asset_body(), "credential": cred()})
    asset_id = created.json()["asset"]["id"]
    r = await client.put(f"/api/v1/assets/{asset_id}/credential", headers=auth_header(admin_token),
                         json=cred(password=PASSWORD + "-2"))
    assert r.status_code == 200 and r.json()["version"] == 2
    refs = (await db_session.execute(select(VaultRef).where(VaultRef.is_active == True))).scalars().all()  # noqa: E712
    assert len(refs) == 1 and str(refs[0].asset_id) == asset_id
    assert PASSWORD not in r.text


async def test_reference_held_by_a_deleted_asset_is_free_again_and_not_shared_between_live_assets(
        client, db_session, admin_token, openbao):
    h = auth_header(admin_token)
    old = (await client.post(CREATE, headers=h, json={"asset": asset_body(), "credential": cred()})).json()["asset"]["id"]
    assert (await client.delete(f"/api/v1/assets/{old}", headers=h)).status_code == 204
    status = (await client.get(STATUS, headers=h)).json()["references"]
    assert {r["name"]: r["bound_asset_id"] for r in status}["kali"] is None      # ghost binding ignored
    # the reference can be bound to a new live asset ...
    new = await client.post(CREATE, headers=h, json={"asset": asset_body(name="Other", ip="10.10.0.6"), "credential": cred()})
    assert new.status_code == 201
    # ... and a different live asset still cannot take it, nor the other asset's reference
    third = await client.post(CREATE, headers=h, json={"asset": asset_body(name="Third", ip="10.10.0.7"), "credential": cred()})
    assert third.status_code == 409 and third.json()["error_code"] == "SECRET_ALREADY_BOUND"
    assert PASSWORD not in third.text


@pytest.mark.parametrize("token_fixture", ["operator_token", "approver_token", "auditor_token"])
async def test_non_admins_cannot_provision_or_see_status(client, db_session, request, token_fixture, openbao):
    h = auth_header(request.getfixturevalue(token_fixture))
    assert (await client.get(STATUS, headers=h)).status_code == 403
    assert (await client.post(CREATE, headers=h, json={"asset": asset_body(), "credential": cred()})).status_code == 403
    assert openbao["writer"].writes == []


async def test_validation_errors_never_log_submitted_values(client, admin_token, caplog):
    import logging
    caplog.set_level(logging.INFO)
    too_long = "X" * 5000 + PASSWORD
    await client.post(CREATE, headers=auth_header(admin_token),
                      json={"asset": asset_body(), "credential": cred(password=too_long)})
    assert PASSWORD not in caplog.text


def test_writer_identity_must_be_separate_and_openbao_only():
    from app.core.config import Settings, SettingsError
    base = dict(_env_file=None, SECRET_PROVIDER="openbao", OPENBAO_ADDR="https://bao.test:8200", OPENBAO_TOKEN="same")
    with pytest.raises(SettingsError, match="separate identity"):
        Settings(**base, OPENBAO_WRITER_TOKEN="same")
    with pytest.raises(SettingsError, match="requires SECRET_PROVIDER=openbao"):
        Settings(_env_file=None, OPENBAO_WRITER_TOKEN="w")
    with pytest.raises(SettingsError, match="OPENBAO_UI_URL"):
        Settings(**base, OPENBAO_UI_URL="https://admin:pw@bao.test/ui?x=1")
    assert Settings(**base, OPENBAO_WRITER_TOKEN="other", OPENBAO_UI_URL="https://bao.ops.example.com:8200/ui/").OPENBAO_UI_URL


# --- opt-in live check against a REAL OpenBao (never the shared lab server) -------------------
# SECUREPAM_LIVE_OPENBAO_ADDR + _READER_TOKEN + _WRITER_TOKEN: tokens carrying the repository's
# securepam-app / securepam-writer policies on a disposable instance.
import os as _os

_LIVE = _os.environ.get("SECUREPAM_LIVE_OPENBAO_ADDR")


@pytest.mark.skipif(not _LIVE, reason="set SECUREPAM_LIVE_OPENBAO_* to run against a disposable OpenBao")
async def test_live_openbao_create_verify_bind_then_rotate(client, db_session, admin_token, monkeypatch):
    from pydantic import SecretStr
    monkeypatch.setattr(settings, "SECRET_PROVIDER", "openbao")
    monkeypatch.setattr(settings, "OPENBAO_ADDR", _LIVE)
    monkeypatch.setattr(settings, "OPENBAO_TOKEN", SecretStr(_os.environ["SECUREPAM_LIVE_OPENBAO_READER_TOKEN"]))
    monkeypatch.setattr(settings, "OPENBAO_WRITER_TOKEN", SecretStr(_os.environ["SECUREPAM_LIVE_OPENBAO_WRITER_TOKEN"]))
    r = await client.post(CREATE, headers=auth_header(admin_token), json={"asset": asset_body(), "credential": cred()})
    assert r.status_code == 201, r.text
    first = r.json()["version"]
    asset_id = r.json()["asset"]["id"]
    r2 = await client.put(f"/api/v1/assets/{asset_id}/credential", headers=auth_header(admin_token),
                          json=cred(password=PASSWORD + "-rotated"))
    assert r2.status_code == 200 and r2.json()["version"] == first + 1
    # Writer may not write outside the policy even if the allowlist were widened by mistake.
    monkeypatch.setattr(settings, "ASSET_CREDENTIAL_SECRET_NAMES", ["win11-lab", "kali", "not-in-policy"])
    r3 = await client.post(CREATE, headers=auth_header(admin_token),
                           json={"asset": asset_body(name="X", ip="10.10.0.9"), "credential": cred(name="not-in-policy")})
    assert r3.status_code == 502 and r3.json()["error_code"] == "WRITE_DENIED"
    for text in (r.text, r2.text, r3.text):
        assert PASSWORD not in text
