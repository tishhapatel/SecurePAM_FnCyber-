"""Regenerate policies.json from default_policies.py:  python tools/export_policies.py"""
from pathlib import Path
from securepam_policy_engine.default_policies import DEFAULT_POLICIES
from securepam_policy_engine.repository import export_policies_json

if __name__ == "__main__":
    out = Path(__file__).resolve().parents[1] / "policies.json"
    export_policies_json(out, DEFAULT_POLICIES)
    print(f"wrote {out}")
