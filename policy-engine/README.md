# SecurePAM — Member 5: Policy Engine (v2.0)

A deterministic, side-effect-free, **risk-adaptive** policy decision module. It evaluates a trusted
access context against versioned policies and returns a structured decision for the backend coordinator.
It never creates sessions, approves requests, issues JIT grants, verifies MFA, opens vault secrets or
writes audit events itself.

> v2.0 addresses the review of v1: project role model, web (HTTP/HTTPS) support, risk tiers, explicit
> `REQUIRE_MFA`, wildcard-policy protection, distinct failure codes, overnight windows, DB-backed
> versioned store, FastAPI adapter and demo-scenario tests. See `docs/REVIEW_RESPONSE.md`.

## Decisions

| Decision | Meaning | `can_proceed` |
|---|---|---|
| `DENY` | Stop. Reason codes explain why. | false |
| `REQUIRE_MFA` | Run step-up MFA, then re-evaluate (checked before approval). | false |
| `REQUIRE_APPROVAL` | Start/continue the approval workflow (Member 7). Not an approval. | false |
| `ALLOW` | Policy gate open; coordinator must still enforce MFA/JIT/recording/duration signals. | true |

## Risk-adaptive model (matches the project doc: LOW 0-29, MEDIUM 30-59, HIGH 60-79, CRITICAL 80+)
Per-policy thresholds on the score supplied by the Risk Engine (Member 6): `mfa_min_risk`,
`approval_min_risk`, `isolated_browser_min_risk`, `deny_min_risk` (plus legacy `max_risk_score`).
A policy that uses any risk field and gets **no** score fails closed (`RISK_UNAVAILABLE`).
Baseline: approval at >= 60, deny at >= 80, isolated browser for web at >= 60.

## Outputs for downstream modules
`approval_required`, `mfa_required`, `recording_required` + `recording_mode` (VIDEO / TERMINAL_AND_COMMANDS /
HTTP_AUDIT / VIDEO_AND_HTTP_AUDIT), `jit_required`, `max_duration_minutes`, `session_timeout_minutes`,
`idle_timeout_minutes`, `web_access_mode` (STANDARD_PROXY / ISOLATED_BROWSER), `file_transfer_allowed`,
`reason_codes`, `matched_policies` (id + version), `risk_score`, `evaluated_at`.

## Quick start
```bash
python -m venv .venv            # Windows: .venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m pytest
```

```python
from datetime import datetime, timezone
from securepam_policy_engine import AccessContext, PolicyEvaluator
from securepam_policy_engine.repository import JsonPolicyRepository

evaluator = PolicyEvaluator(JsonPolicyRepository("policies.json"))
decision = evaluator.evaluate(AccessContext(
    request_id="REQ-1", user_id="u1", role="Operator", target_id="win-prod-01",
    target_registered=True, environment="production", protocol="RDP",
    requested_duration_minutes=30, mfa_satisfied=True, risk_score=65,
    now=datetime.now(timezone.utc)))
print(decision.decision, decision.can_proceed, decision.reason_codes)
```

## Production wiring
1. Create the table: `migrations/001_create_policy_engine_policies.sql` (PostgreSQL) or `Base.metadata.create_all(engine)`.
2. `repo = SqlAlchemyPolicyRepository(session_factory, audit_sink=audit_service.write)` — versioned, append-only; the
   audit sink runs before commit so a failed audit write rolls the policy change back.
3. `app.include_router(create_policy_router(PolicyEvaluator(repo), context_provider, audit_sink, repo, admin_dependency, auth_dependency=get_current_active_user))`.
   `auth_dependency` is required and protects every route. `context_provider(request_id, request, actor)` is *your* backend
   code building `AccessContext` from trusted sources; it must refuse when `actor` may not evaluate that request. The evaluation endpoint reads **no**
   request body. Admin routes mount only if you pass both a repository and an `admin_dependency` (RBAC check returning the actor id).
4. Seed baseline policies for review: `python tools/export_policies.py` regenerates `policies.json` from `default_policies.py`.

## Security rules for integrators
1. Build `AccessContext` server-side only (identity, RBAC, asset registry, risk engine, MFA verifier, server clock).
2. Act on `decision`: `DENY` stop; `REQUIRE_MFA` run MFA and re-evaluate; `REQUIRE_APPROVAL` verify a recorded approval (no self-approval);
   `ALLOW` proceed only after enforcing every emitted signal. Use `can_proceed` as the single gate.
3. Enforce JIT, `max_duration_minutes`, timeouts, recording and web mode in the gateways/session coordinator.
4. Audit every decision (including DENY) with policy ids/versions and reason codes; never log credentials, tokens or OTPs.
5. Role/environment/protocol matching is case/whitespace-insensitive; `target_id` is exact-match.
6. ALLOW policies must list roles, environments and protocols (validated); only DENY policies may be wildcards.
7. Do not deploy `default_policies.py` unchanged: it is a reviewed-by-team baseline, not a final policy set.

## File guide
- `securepam_policy_engine/models.py` — contracts (`AccessContext`, `Policy`, `PolicyDecision`, `Decision`, `ReasonCode`)
- `.../evaluator.py` — deterministic evaluator; `.../validation.py` — policy validation
- `.../repository.py` — interface + JSON/in-memory adapters; `.../db.py` — SQLAlchemy versioned store; `.../api.py` — FastAPI adapter
- `.../default_policies.py`, `policies.json` — baseline policies (JSON generated from Python; a test enforces they match)
- `migrations/` — SQL; `tools/` — export script; `tests/` — 97 tests incl. the plan's demo scenario; `docs/` — contracts and reviews
