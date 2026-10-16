"""
Verify that a scoped OpenBao token matches SecurePAM's least-privilege model.

    OPENBAO_ADMIN_TOKEN=... OPENBAO_TOKEN=... python -m scripts.verify_openbao_token

Tokens come only from the environment (or a hidden prompt for the admin token): never from argv.
Output is PASS/FAIL lines with status codes, path names and field NAMES only: no token, secret value
or response body is ever printed.

Why two kinds of check: a token created with `-no-default-policy` (as the backend's must be) cannot
call `sys/capabilities-self`, so it cannot be asked what it may do. Capabilities are therefore read from the
ADMIN side (`sys/capabilities`), and the scoped token's real behaviour is then proven with actual KV v2 reads
plus a denied read and a denied write on unregistered paths. Destructive operations are never attempted on
registered paths; their absence is shown by the capability lists alone.
"""

import getpass
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import httpx

POLICY_FILE = Path(__file__).resolve().parents[2] / "infrastructure" / "openbao" / "policies" / "securepam-read.hcl"
POLICY_NAME = "securepam-read"
REQUIRED_FIELDS = {"username", "password"}
UNREGISTERED = "securepam/assets/zz-not-registered"
WRITE_PROBE = "securepam/assets/zz-policy-probe"
_ADDR_RE = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?$")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""

    def line(self) -> str:
        return f"{'PASS' if self.ok else 'FAIL'} {self.name}" + (f" - {self.detail}" if self.detail else "")


def valid_addr(addr: str) -> bool:
    """A literal scheme://host[:port]. Rejects Markdown-formatted links, paths and credentials."""
    return bool(_ADDR_RE.match(addr or ""))


def required_data_paths(policy_text: str, mount: str = "secret") -> List[str]:
    """The registered paths the policy grants, relative to the mount (single source of truth)."""
    found = re.findall(r'path\s+"%s/data/([^"*]+)"' % re.escape(mount), policy_text)
    return sorted(set(found))


def verify(client: httpx.Client, admin_token: str, app_token: str, paths: List[str], mount: str = "secret",
           policy_name: str = POLICY_NAME, allow_unstored: Optional[List[str]] = None) -> List[Check]:
    """policy_name: the exact single policy the scoped token must carry (lab: securepam-read; AWS:
    securepam-app). allow_unstored: registered paths whose secret may legitimately not exist YET (e.g.
    the Wazuh reference before an operator stores it) - a 404 there is reported as PENDING, not hidden."""
    checks: List[Check] = []
    admin = {"X-Vault-Token": admin_token}
    scoped = {"X-Vault-Token": app_token}

    # 1. server reachable, initialised, unsealed
    try:
        health = client.get("/v1/sys/health", params={"standbyok": "true"})
        info = health.json()
    except (httpx.HTTPError, ValueError) as exc:
        return [Check("OpenBao reachable", False, f"OPENBAO_UNREACHABLE ({type(exc).__name__})")]
    if not info.get("initialized") or info.get("sealed"):
        return [Check("OpenBao reachable, initialised and unsealed", False,
                      "OPENBAO_SEALED_OR_UNINITIALISED")]
    checks.append(Check("OpenBao reachable, initialised and unsealed", True))

    # 2. the ADMIN token is valid on its own (so a bad admin token is never blamed on the scoped one),
    #    then the scoped token exists and carries the policy (admin lookup; no secrets involved)
    own = client.get("/v1/auth/token/lookup-self", headers=admin)
    if own.status_code != 200:
        return checks + [Check("administrator token accepted", False,
                               f"ADMIN_TOKEN_REJECTED (HTTP {own.status_code}: invalid, expired or revoked)")]
    lookup = client.post("/v1/auth/token/lookup", headers=admin, json={"token": app_token})
    if lookup.status_code != 200:
        return checks + [Check("administrator token accepted", True),
                         Check("scoped token is valid", False,
                               f"SCOPED_TOKEN_INVALID_OR_EXPIRED (lookup HTTP {lookup.status_code}): mint a new one")]
    meta = lookup.json().get("data", {})
    policies = sorted(meta.get("policies", []))
    checks.append(Check("administrator token accepted", True))
    checks.append(Check("scoped token carries exactly the application policy", policies == [policy_name],
                        f"policies={policies}" + ("" if policies == [policy_name] else " (POLICY_NOT_ATTACHED_OR_TOO_BROAD)")))
    ttl = meta.get("ttl", 0)
    checks.append(Check("scoped token is short-lived and not renewable", 0 < ttl <= 7 * 24 * 3600 and not meta.get("renewable"),
                        f"ttl={ttl}s renewable={meta.get('renewable')}"))

    # 3. capability lists, read from the admin side
    data_paths = [f"{mount}/data/{p}" for p in paths]
    destructive = [f"{mount}/{op}/{p}" for p in paths for op in ("delete", "undelete", "destroy", "metadata")]
    outside = [f"{mount}/data/{UNREGISTERED}", f"{mount}/data/{WRITE_PROBE}", "auth/token/create",
               f"sys/policies/acl/{policy_name}"]
    all_paths = data_paths + destructive + outside
    cap = client.post("/v1/sys/capabilities", headers=admin, json={"token": app_token, "paths": all_paths})
    if cap.status_code != 200:
        return checks + [Check("capabilities readable", False, f"CAPABILITY_LOOKUP_FAILED (HTTP {cap.status_code})")]
    body = cap.json().get("data", cap.json())

    def caps(path: str) -> List[str]:
        return sorted(body.get(path, []))

    for p in data_paths:
        got = caps(p)
        checks.append(Check(f"read-only on {p}", got == ["read"],
                            f"capabilities={got}" + ("" if got == ["read"] else (" (POLICY_TOO_BROAD)" if "read" in got else " (KV_READ_DENIED_BY_POLICY)"))))
    for p in destructive:
        got = caps(p)
        checks.append(Check(f"no access to {p}", got == ["deny"], f"capabilities={got}"))
    for p in outside:
        got = caps(p)
        checks.append(Check(f"denied outside the registered paths: {p}", got == ["deny"], f"capabilities={got}"))

    # 4. real behaviour of the scoped token
    for p in paths:
        r = client.get(f"/v1/{mount}/data/{p}", headers=scoped)
        if r.status_code == 200:
            fields = set((r.json().get("data") or {}).get("data") or {})
            missing = sorted(REQUIRED_FIELDS - fields)
            checks.append(Check(f"real KV read as the scoped token: {p}", not missing,
                                f"fields={sorted(fields)}" + (f" MISSING_FIELDS={missing}" if missing else "")))
        elif r.status_code == 404 and p in (allow_unstored or []):
            checks.append(Check(f"real KV read as the scoped token: {p}", True,
                                "PENDING: SECRET_NOT_STORED_YET (HTTP 404; policy permits the read)"))
        else:
            reason = {403: "KV_READ_DENIED", 404: "SECRET_NOT_FOUND"}.get(r.status_code, "KV_READ_FAILED")
            checks.append(Check(f"real KV read as the scoped token: {p}", False, f"{reason} (HTTP {r.status_code})"))
    r = client.get(f"/v1/{mount}/data/{UNREGISTERED}", headers=scoped)
    checks.append(Check("real read of an unregistered path is denied", r.status_code == 403, f"HTTP {r.status_code}"))
    # Write probe on an UNREGISTERED scratch path only; cleaned up if (wrongly) allowed.
    r = client.put(f"/v1/{mount}/data/{WRITE_PROBE}", headers=scoped, json={"data": {"probe": "1"}})
    denied = r.status_code == 403
    checks.append(Check("real write as the scoped token is denied", denied, f"HTTP {r.status_code}"))
    if not denied and r.status_code < 300:
        client.delete(f"/v1/{mount}/metadata/{WRITE_PROBE}", headers=admin)  # remove the probe we created
    return checks


def verify_writer(client: httpx.Client, admin_token: str, writer_token: str, paths: List[str],
                  mount: str = "secret", policy_name: str = "securepam-writer") -> List[Check]:
    """The credential-writer identity: exactly create+update on the registered data paths and nothing
    else. Never writes to a registered path (that would change a real credential); create/update are
    proven from the capability lists, and denials with real requests (read + unregistered write)."""
    checks: List[Check] = []
    admin, scoped = {"X-Vault-Token": admin_token}, {"X-Vault-Token": writer_token}
    try:
        info = client.get("/v1/sys/health", params={"standbyok": "true"}).json()
    except (httpx.HTTPError, ValueError) as exc:
        return [Check("OpenBao reachable", False, f"OPENBAO_UNREACHABLE ({type(exc).__name__})")]
    if not info.get("initialized") or info.get("sealed"):
        return [Check("OpenBao reachable, initialised and unsealed", False, "OPENBAO_SEALED_OR_UNINITIALISED")]
    if client.get("/v1/auth/token/lookup-self", headers=admin).status_code != 200:
        return [Check("administrator token accepted", False, "ADMIN_TOKEN_REJECTED")]
    lookup = client.post("/v1/auth/token/lookup", headers=admin, json={"token": writer_token})
    if lookup.status_code != 200:
        return [Check("writer token is valid", False, f"WRITER_TOKEN_INVALID_OR_EXPIRED (lookup HTTP {lookup.status_code})")]
    meta = lookup.json().get("data", {})
    policies = sorted(meta.get("policies", []))
    checks.append(Check("writer token carries exactly the writer policy", policies == [policy_name], f"policies={policies}"))
    ttl = meta.get("ttl", 0)
    checks.append(Check("writer token is short-lived and not renewable", 0 < ttl <= 24 * 3600 and not meta.get("renewable"),
                        f"ttl={ttl}s renewable={meta.get('renewable')}"))
    data_paths = [f"{mount}/data/{p}" for p in paths]
    other = [f"{mount}/{op}/{p}" for p in paths for op in ("delete", "undelete", "destroy", "metadata")] + \
            [f"{mount}/data/{UNREGISTERED}", "auth/token/create", f"sys/policies/acl/{policy_name}"]
    cap = client.post("/v1/sys/capabilities", headers=admin, json={"token": writer_token, "paths": data_paths + other})
    if cap.status_code != 200:
        return checks + [Check("capabilities readable", False, f"CAPABILITY_LOOKUP_FAILED (HTTP {cap.status_code})")]
    body = cap.json().get("data", cap.json())
    for p in data_paths:
        got = sorted(body.get(p, []))
        checks.append(Check(f"create+update only on {p}", got == ["create", "update"], f"capabilities={got}"))
    for p in other:
        got = sorted(body.get(p, []))
        checks.append(Check(f"no access to {p}", got == ["deny"], f"capabilities={got}"))
    if paths:
        r = client.get(f"/v1/{mount}/data/{paths[0]}", headers=scoped)
        checks.append(Check("real read as the writer is denied", r.status_code == 403, f"HTTP {r.status_code}"))
    r = client.put(f"/v1/{mount}/data/{WRITE_PROBE}", headers=scoped, json={"data": {"probe": "1"}})
    checks.append(Check("real write to an unregistered path is denied", r.status_code == 403, f"HTTP {r.status_code}"))
    if r.status_code < 300:
        client.delete(f"/v1/{mount}/metadata/{WRITE_PROBE}", headers=admin)
    return checks


def main() -> int:
    addr = os.environ.get("OPENBAO_ADDR") or os.environ.get("BAO_ADDR") or "http://127.0.0.1:18200"
    if not valid_addr(addr):
        print("FAIL OpenBao address - BAO_ADDR/OPENBAO_ADDR must be a literal like http://127.0.0.1:18200 "
              "(no Markdown brackets, path or credentials)")
        return 2
    app_token = os.environ.get("OPENBAO_TOKEN", "")
    admin_token = os.environ.get("OPENBAO_ADMIN_TOKEN", "")
    if not app_token:
        print("FAIL scoped token - OPENBAO_TOKEN is not set")
        return 2
    if not admin_token and sys.stdin.isatty():
        admin_token = getpass.getpass("OpenBao admin token (input hidden): ")
    if not admin_token:
        print("FAIL administrator token - OPENBAO_ADMIN_TOKEN is not set and there is no terminal to prompt on")
        return 2
    try:
        paths = required_data_paths(POLICY_FILE.read_text(), os.environ.get("OPENBAO_MOUNT_POINT", "secret"))
    except OSError:
        print(f"FAIL policy file - cannot read {POLICY_FILE}")
        return 2
    if not paths:
        print("FAIL policy file - it declares no registered paths")
        return 2
    with httpx.Client(base_url=addr, timeout=8.0, trust_env=False,
                      verify=os.environ.get("OPENBAO_CA_CERT") or True) as client:
        checks = verify(client, admin_token, app_token, paths, os.environ.get("OPENBAO_MOUNT_POINT", "secret"))
    for check in checks:
        print(check.line())
    return 0 if checks and all(c.ok for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
