import pytest
pytest.importorskip("sqlalchemy")
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from securepam_policy_engine import Decision, PolicyConfigurationError, PolicyEvaluator
from securepam_policy_engine.db import Base, SqlAlchemyPolicyRepository
from securepam_policy_engine.default_policies import DEFAULT_POLICIES
from conftest import make_policy


@pytest.fixture
def repo_and_audit():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    events = []
    return SqlAlchemyPolicyRepository(sessionmaker(engine), audit_sink=events.append), events


def test_publish_assigns_versions_and_keeps_history(repo_and_audit):
    repo, events = repo_and_audit
    v1 = repo.publish(make_policy(version=99), actor="admin-1", change_note="initial")
    v2 = repo.publish(make_policy(max_duration_minutes=20), actor="admin-2")
    assert (v1.version, v2.version) == (1, 2)
    assert [h["version"] for h in repo.history("POL-TEST")] == [1, 2]
    assert repo.list_active() == [v2]
    assert [e["event"] for e in events] == ["policy.published"] * 2 and events[1]["actor"] == "admin-2"


def test_disable_creates_new_disabled_version(repo_and_audit):
    repo, events = repo_and_audit
    repo.publish(make_policy(), actor="a")
    repo.disable("POL-TEST", actor="a")
    assert repo.list_active() == [] and len(repo.list_current()) == 1
    assert [h["enabled"] for h in repo.history("POL-TEST")] == [True, False]
    assert events[-1]["event"] == "policy.disabled"
    with pytest.raises(KeyError):
        repo.disable("NOPE", actor="a")


def test_invalid_policy_and_missing_actor_rejected(repo_and_audit):
    repo, _ = repo_and_audit
    with pytest.raises(PolicyConfigurationError):
        repo.publish(make_policy(allowed_roles=frozenset()), actor="a")
    with pytest.raises(PolicyConfigurationError):
        repo.publish(make_policy(), actor="")
    assert repo.list_active() == []


def test_failed_audit_rolls_back_the_change():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    def broken(_event):
        raise RuntimeError("audit down")
    repo = SqlAlchemyPolicyRepository(sessionmaker(engine), audit_sink=broken)
    with pytest.raises(RuntimeError):
        repo.publish(make_policy(), actor="a")
    assert repo.list_active() == []


def test_evaluator_works_against_db_policies(repo_and_audit, context):
    repo, _ = repo_and_audit
    for p in DEFAULT_POLICIES:
        repo.publish(p, actor="seed")
    d = PolicyEvaluator(repo).evaluate(context)
    assert d.decision is Decision.ALLOW and {m["version"] for m in d.matched_policies} == {1}


def test_table_does_not_collide_with_backend_policies_table():
    # The backend's Alembic schema owns "policies"; the SQL migration and the
    # ORM must agree on the engine's own name.
    from pathlib import Path
    from securepam_policy_engine.db import PolicyRow
    assert PolicyRow.__tablename__ == "policy_engine_policies"
    sql = (Path(__file__).resolve().parents[1] / "migrations/001_create_policy_engine_policies.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS policy_engine_policies (" in sql
    assert " policies " not in sql and " policies(" not in sql
