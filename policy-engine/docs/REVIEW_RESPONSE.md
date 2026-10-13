# Review response (v1 -> v2)

| # | Review finding | Resolution | Test |
|---|---|---|---|
| 1 | Role names did not match project roles (Operator denied everything) | Baseline uses Administrator/Operator; Auditor explicitly denied (also as a secondary role); multi-role context (`extra_roles`) | `test_scenarios::test_project_roles_are_accepted`, `test_auditor_as_secondary_role_is_denied` |
| 2 | HTTP/HTTPS unsupported | Web protocols supported; `web_access_mode` STANDARD_PROXY / ISOLATED_BROWSER | `test_web_standard_vs_isolated_by_risk` |
| 3 | Not risk-adaptive | Tiered thresholds: `mfa_min_risk`, `approval_min_risk`, `isolated_browser_min_risk`, `deny_min_risk` | `test_risk_tier_boundaries`, `test_critical_risk_denied_everywhere` |
| 4 | Missing inputs/outputs | `criticality`, `assigned_policy_ids`/`requires_assignment`, session + idle timeout, `file_transfer_allowed`, `recording_mode` | `test_criticality_selector`, `test_requires_assignment`, `test_strictest_timeouts_win` |
| 5 | ALLOW could mean "MFA missing" | New `REQUIRE_MFA` decision + `can_proceed` | `test_unverified_mfa_is_require_mfa_not_allow` |
| 6 | Empty selector matched everyone | ALLOW policies must list roles, environments, protocols (validated, fail-closed) | `test_allow_policy_with_empty_selectors_is_rejected` |
| 7 | Misleading failure reasons | Stable `reason_codes`; `POLICY_STORE_UNAVAILABLE` vs `POLICY_INVALID` vs `EVALUATION_ERROR` | `test_store_outage_has_distinct_code`, `test_malformed_policy_file_is_policy_invalid` |
| 8 | Exact-match strings | Role/environment/protocol/criticality normalised (case, whitespace) | `test_case_and_whitespace_normalisation` |
| 9a | Overnight / 24:00 windows rejected | Supported; after-midnight hours belong to the start day's weekday | `test_overnight_window_...`, `test_end_of_day_24_00` |
| 9b | JSON vs Python policies drifted | JSON generated from Python; sync test | `test_policies_json_is_in_sync_with_default_policies` |
| 9c | Catalogue listed principles as policies | Catalogue rewritten: real policies + control-to-mechanism table | — |
| DB | No DB model/admin | `db.py` versioned append-only store, audited publish/disable, SQL migration, admin routes | `tests/test_db.py`, `tests/test_api.py` |
| API | No adapter | `api.py` router; evaluation endpoint reads no body | `test_client_cannot_inject_authoritative_values` |
| Tests | Boundary/DST/scenario gaps | Boundaries (risk, duration, 09:00/19:00), DST, demo scenario, malformed files | `tests/` |
| Hygiene | pycache in zip | Removed; `.gitignore` retained | — |

## Still open (need team decisions)
- Exact role/environment/criticality enum values and protocol names from Members 3/4 (the engine normalises case only).
- Risk Engine (M6) score scale confirmation; tier values (60/80) are the project-doc defaults, not an industry standard.
- Audit event schema (M12) — the sink receives a plain dict today.
- Holiday calendars and per-user (not just per-role) policies are not implemented.
- The API adapter needs the backend's real auth dependency and `context_provider`.
