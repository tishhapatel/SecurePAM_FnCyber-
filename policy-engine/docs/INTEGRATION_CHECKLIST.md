# Member 5 integration checklist

## Before PR
- [ ] Confirm package path and Python version with Member 1/2.
- [ ] Confirm request DTO and authenticated subject with Member 2.
- [ ] Confirm roles and role normalization with Member 3/2.
- [ ] Confirm target registry/environment/protocol identifiers with Member 4.
- [ ] Confirm risk score scale, availability semantics, and thresholds with Member 6.
- [ ] Confirm approval, JIT grant, expiry, MFA, and recording enforcement contracts with Members 3/7/2.
- [ ] Confirm audit event fields with Member 12 / backend lead.
- [ ] Replace example policy IDs, roles, target IDs, and business-hours settings with agreed values.
- [ ] Run unit tests and lint/type checks required by repository.
- [ ] Add adapter into the existing backend workflow; do not make a second independent authorization endpoint if one already exists.

## During integration
- [ ] Construct AccessContext only on server side.
- [ ] Evaluate before approval/JIT/session orchestration.
- [ ] Stop immediately on DENY.
- [ ] Verify approval state and no self-approval.
- [ ] On `REQUIRE_MFA`, run step-up MFA and re-evaluate; gate on `can_proceed`.
- [ ] Verify MFA state if required.
- [ ] Pass criticality and assigned policy IDs from Member 4; wire `web_access_mode` to Member 11 and timeouts/recording mode to Members 9/10/12.
- [ ] Verify JIT grant and expiration if required.
- [ ] Verify recording before opening session if required.
- [ ] Enforce duration on server side.
- [ ] Emit sanitized audit evidence for every decision, including DENY.
- [ ] Ensure evaluator exceptions map to DENY and are observable to operators without leaking secrets.

## Before merge
- [ ] Contract tests with backend and mock Member 4/6/7 services.
- [ ] Test no policy, invalid policy, deny-overrides, role mismatch, target mismatch, business hours, missing risk, and all control flags.
- [ ] Peer review by project lead for security-sensitive code.
- [ ] Protected `main`; feature branch and PR; no direct push to `main`.
