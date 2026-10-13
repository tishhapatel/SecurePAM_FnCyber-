import json
from pathlib import Path
import pytest
from securepam_policy_engine import (Decision, Policy, PolicyConfigurationError, PolicyEvaluator,
                                     ReasonCode)
from securepam_policy_engine.default_policies import DEFAULT_POLICIES
from securepam_policy_engine.repository import (InMemoryPolicyRepository, JsonPolicyRepository,
                                                policy_from_record, policy_to_record)

ROOT = Path(__file__).parents[1]


def test_json_repository_loads_active_policies():
    policies = JsonPolicyRepository(ROOT / "policies.json").list_active()
    assert len(policies) >= 1 and all(p.enabled for p in policies)


def test_policies_json_is_in_sync_with_default_policies():
    assert JsonPolicyRepository(ROOT / "policies.json").list_active() == DEFAULT_POLICIES


def test_record_round_trip():
    for p in DEFAULT_POLICIES:
        assert policy_from_record(json.loads(json.dumps(policy_to_record(p)))) == p


def test_in_memory_repository_filters_disabled():
    repo = InMemoryPolicyRepository([
        Policy(policy_id="A", version=1, name="A", effect="DENY"),
        Policy(policy_id="B", version=1, name="B", effect="DENY", enabled=False)])
    assert [p.policy_id for p in repo.list_active()] == ["A"]


def test_store_outage_has_distinct_code(context):
    class Broken:
        def list_active(self):
            raise RuntimeError("database unavailable")
    out = PolicyEvaluator(Broken()).evaluate(context)
    assert out.decision is Decision.DENY and out.reason_codes == (ReasonCode.POLICY_STORE_UNAVAILABLE.value,)


def test_missing_file_is_store_unavailable(context, tmp_path):
    out = PolicyEvaluator(JsonPolicyRepository(tmp_path / "nope.json")).evaluate(context)
    assert out.reason_codes == ("POLICY_STORE_UNAVAILABLE",)


@pytest.mark.parametrize("content", ['{"not": "a list"}', "[1, 2]", "not json",
                                     '[{"policy_id": "A", "version": 1, "name": "a", "typo_field": 1}]'])
def test_malformed_policy_file_is_policy_invalid(context, tmp_path, content):
    f = tmp_path / "p.json"
    f.write_text(content)
    out = PolicyEvaluator(JsonPolicyRepository(f)).evaluate(context)
    assert out.decision is Decision.DENY and out.reason_codes == ("POLICY_INVALID",)


def test_record_with_non_list_selector_rejected():
    with pytest.raises(PolicyConfigurationError):
        policy_from_record({"policy_id": "A", "version": 1, "name": "a", "effect": "DENY", "environments": "production"})
