# API and integration contract (proposal until team confirms)

## Python contract

```python
PolicyEvaluator(repository).evaluate(AccessContext(...)) -> PolicyDecision
PolicyDecision.to_dict() -> dict
```

The module is intentionally framework-independent. Backend Member 2 should wrap it inside the existing access-request workflow rather than duplicate policy logic in API routes or frontend code.

## Trusted context mapping

| Engine field | Source expected | Owner to confirm |
|---|---|---|
| `request_id` | Persisted access request ID | Member 2 |
| `user_id` | Authenticated OIDC subject / internal user ID | Members 1/2 |
| `role` | Server-side RBAC decision | Member 3 / Member 2 |
| `target_id` | Registered asset ID | Member 4 |
| `target_registered` | Asset registry lookup, not client assertion | Member 4 |
| `environment` | Registered asset metadata | Member 4 |
| `protocol` | Requested protocol constrained by asset configuration | Members 2/4 |
| `requested_duration_minutes` | Validated request field | Member 2 |
| `mfa_satisfied` | Trusted identity provider/MFA verification state | Member 3 / Member 2 |
| `risk_score` | Risk engine output, not client input | Member 6 |
| `now` | Backend clock in an aware datetime | Member 2 |

## Added in v2: new context fields and outputs
Optional context: `extra_roles`, `criticality` (asset/application registry, M4), `assigned_policy_ids` (application `policy_id`, M4).
New outputs: `can_proceed`, `reason_codes`, `recording_mode`, `session_timeout_minutes`, `idle_timeout_minutes`, `web_access_mode`,
`file_transfer_allowed`, `risk_score`. `REQUIRE_MFA` is a new decision. The adapter in `api.py` implements the endpoint below.

## Decision handling contract
- `DENY`: reject and record reason; no approval/JIT/session creation.
- `REQUIRE_APPROVAL`: create/continue approval workflow; verify approved state and separation-of-duties rules before proceeding.
- `REQUIRE_MFA`: run step-up MFA, then call the evaluator again.
- `ALLOW` (`can_proceed=true`): proceed only if all emitted requirements are satisfied.
- If `jit_required=true`, confirm an active JIT grant and enforce its server-side expiry.
- If `recording_required=true`, confirm the gateway recording path is available before starting a privileged session.
- Apply `max_duration_minutes` server-side. Never trust a client-calculated expiry.
- Send a sanitized audit event to the audit service with request ID, policy IDs/versions, decision, reason codes, actor, target, and timestamp.

## Suggested endpoint shape (do not add if backend already has an equivalent)
`POST /api/access-requests/{request_id}/policy-evaluation`

The request body should not let clients set authoritative `user_id`, role, target registration, risk score, policy decision, approval state, JIT grant, MFA state, or expiry. The backend should build the context from trusted sources. Return `PolicyDecision.to_dict()` or the project's agreed response DTO.

## Integration questions to settle in a short contract meeting
- Exact Python package layout and existing naming conventions.
- Role, environment, criticality and protocol enum values (HTTP vs HTTPS vs a single WEB value).
- Request/target/role/risk schema field names and enum values.
- Whether target IDs and protocols are case-normalized upstream.
- Business-hours timezone source and whether overnight shifts are required.
- Database policy model, versioning, migrations, and audit event schema.
- Who enforces MFA, approval, JIT, recording, and expiry at session creation.
- What happens when the risk engine is unavailable (recommended: DENY for policies that require risk).
