# Security review notes / known limitations

- JSON and in-memory repositories are development adapters only; production uses `SqlAlchemyPolicyRepository` (versioned, audited). *Who may publish policies* is enforced by the backend's `admin_dependency`, not by this module.
- Policy configuration should be schema-validated and versioned. Policy changes need review and audit evidence.
- The evaluator does not authenticate users, verify identity-provider claims, approve requests, grant JIT, access a vault, create sessions, enforce recording, revoke access, or write audit events.
- `ALLOW` is not an end-to-end authorization guarantee; the coordinator must enforce all control signals before session creation.
- Role, environment, protocol and criticality are matched case/whitespace-insensitively; `target_id` is exact. Still normalise at trusted boundaries.
- The default catalogue is illustrative and must not be deployed unchanged.
- Holiday calendars and per-user policies are not supported.
- Risk tier values (60/80) are project-specific defaults, not an industry standard.
- Business-hours policies are selectors by default. For explicit out-of-hours prohibition even when another ALLOW policy matches, set `deny_outside_time_window=true` and test the result.
- Avoid returning internal exception details to untrusted clients. This module returns exception class only on evaluation failure.
- Audit policy decisions without storing credentials, tokens, OTPs, or secret values.
