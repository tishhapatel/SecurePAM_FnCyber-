# SecurePAM Member 5 — Baseline policy catalogue (v2)

Illustrative baseline in `default_policies.py` (exported to `policies.json`). Roles, targets and thresholds must be
reconciled with the team's approved role model and asset registry before deployment.

| ID | Effect | Intent | Key settings |
|---|---|---|---|
| POL-001 | DENY | Restricted production targets | env production, targets `prod-unknown`, `prod-restricted` |
| POL-002 | DENY | Auditors never operate targets (also as secondary role) | role Auditor |
| POL-003 | ALLOW | Baseline privileged access, risk-adaptive | Administrator/Operator; all envs; SSH/RDP/HTTP/HTTPS; max 60 min; MFA+recording+JIT; session 60 / idle 15; approval at risk >= 60; deny at risk >= 80 |
| POL-004 | ALLOW | Production requires approval | production; max 30 min; approval + MFA + recording + JIT |
| POL-005 | ALLOW | Web: isolated browser at HIGH risk | HTTP/HTTPS; isolated browser at risk >= 60 (also blocks file transfer) |
| POL-006 | ALLOW + time guard | Non-production business hours only | Mon-Sat 09:00-19:00 Asia/Kolkata, `deny_outside_time_window` |

## Security principles and where they are enforced
| Principle | Mechanism |
|---|---|
| Least privilege / default deny | ALLOW policies need explicit role+environment+protocol; no match => DENY |
| Time-bound access | `max_duration_minutes` (strictest wins), session/idle timeout, JIT signal |
| Separation of duties | Approval service (M7) rejects self-approval; engine only signals approval |
| Strong authentication | `REQUIRE_MFA` decision; coordinator verifies trusted MFA state |
| Accountability | `recording_required` + `recording_mode`; gateways enforce |
| Risk-based access | Score tiers (MFA / approval / isolated browser / deny) |
| No bypass | Missing/invalid policy, context, risk or evaluator error => DENY with reason code |

## Governance lifecycle
Propose -> peer/security review -> `publish` (new immutable version, audited with actor) -> tests -> deploy -> evaluate ->
audit evidence (policy id + version per decision) -> periodic review. Disabling writes a new disabled version; history is kept.
