# Policy precedence and failure behaviour (v2)

## Evaluation order
1. Validate trusted context (blank fields, aware timestamp, registered target, positive duration, risk 0-100).
2. Load active policies; validate **every** active policy (even non-matching ones). Any invalid policy => DENY `POLICY_INVALID`.
3. Time guards: an ALLOW policy with `deny_outside_time_window` whose non-time selectors match but time does not => DENY `OUTSIDE_TIME_WINDOW`.
4. Match selectors: role (any of primary/extra), environment, protocol, target, criticality, assignment, weekday, hours.
5. No match => DENY `NO_MATCHING_POLICY`. Any matching DENY policy => DENY `EXPLICIT_DENY` (priority never lets ALLOW beat DENY).
6. Risk: a matching policy with any risk field and no score => DENY `RISK_UNAVAILABLE`; score > `max_risk_score` or >= `deny_min_risk` => DENY `RISK_TOO_HIGH`.
7. Duration above the strictest `max_duration_minutes` => DENY `DURATION_EXCEEDED`.
8. Accumulate controls: approval/MFA/recording/JIT/isolated browser = OR; file transfer = AND; timeouts = minimum.
9. Decision: MFA required but unverified => `REQUIRE_MFA`; else approval => `REQUIRE_APPROVAL`; else `ALLOW`.

## Semantics
- Unknown criticality: ALLOW policies with a criticality selector do not match; DENY policies with one **do** match (conservative).
- Time windows: same-day, overnight (start > end) and `24:00` end are supported. After-midnight hours of an overnight window belong to the
  weekday the window started. Evaluation uses the policy's time zone (DST-aware).
- Selectors for role/environment/protocol/criticality are case- and whitespace-insensitive; `target_id` is exact.
- Only DENY policies may have empty selectors (global rules); ALLOW policies must list roles, environments and protocols.
- `REQUIRE_MFA` / `REQUIRE_APPROVAL` are never evidence that MFA/approval happened. Gate on `can_proceed`.
