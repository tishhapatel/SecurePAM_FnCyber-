"""Repository interfaces and JSON-backed local/demo implementation.

Production should use `SqlAlchemyPolicyRepository` (see db.py). Policy writes must be
authorized, versioned, reviewed and audited by the backend.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
import json
from dataclasses import fields as dc_fields
from pathlib import Path
from typing import Iterable
from .models import Policy, PolicyConfigurationError
from .validation import validate_policy

_SET_KEYS = ("allowed_roles", "environments", "protocols", "target_ids", "criticalities", "allowed_weekdays")


class PolicyRepository(ABC):
    @abstractmethod
    def list_active(self) -> list[Policy]:
        """Return active, versioned policies from trusted server-side storage."""
        raise NotImplementedError


class InMemoryPolicyRepository(PolicyRepository):
    def __init__(self, policies: Iterable[Policy]):
        self._policies = list(policies)

    def list_active(self) -> list[Policy]:
        return [p for p in self._policies if p.enabled]


class JsonPolicyRepository(PolicyRepository):
    """Read-only JSON policy source for local demos/tests; not a production DB.

    A missing/unreadable file raises OSError (store unavailable); malformed content raises
    PolicyConfigurationError (invalid policy). The evaluator maps both to DENY with distinct codes.
    """
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def list_active(self) -> list[Policy]:
        with self.path.open("r", encoding="utf-8") as f:
            try:
                records = json.load(f)
            except json.JSONDecodeError as exc:
                raise PolicyConfigurationError(f"Policy file is not valid JSON: {exc.msg}")
        if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
            raise PolicyConfigurationError("Policy file must contain a list of policy objects")
        return [policy_from_record(r) for r in records if r.get("enabled", True)]


def policy_from_record(record: dict) -> Policy:
    """Build and validate a Policy from a JSON/DB record (lists become frozensets)."""
    fields = dict(record)
    for key in _SET_KEYS:
        if fields.get(key) is not None:
            if not isinstance(fields[key], (list, tuple, set, frozenset)):
                raise PolicyConfigurationError(f"{key} must be a list")
            fields[key] = frozenset(fields[key])
    try:
        policy = Policy(**fields)
    except TypeError as exc:
        raise PolicyConfigurationError(f"Bad policy record: {exc}")
    validate_policy(policy)
    return policy


def policy_to_record(policy: Policy) -> dict:
    out = {}
    for f in dc_fields(Policy):
        value = getattr(policy, f.name)
        out[f.name] = sorted(value) if isinstance(value, (set, frozenset)) else value
    return out


def export_policies_json(path: str | Path, policies: Iterable[Policy]) -> None:
    """Write policies to a JSON file (keeps policies.json in sync with default_policies.py)."""
    records = [policy_to_record(p) for p in policies]
    Path(path).write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
