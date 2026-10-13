# Preliminary control mapping (not a compliance claim)

Mapping is indicative. Validate against the exact framework edition and official control wording before including it in a formal report.

| SecurePAM behavior | CIS Controls v8.1 candidate | NIST SP 800-53 Rev. 5 candidate | Evidence to retain |
|---|---|---|---|
| Role-based access and least privilege | Control 6; Safeguard 6.8 (role-based access control) | AC-2, AC-3, AC-6 | role decision, matched policy/version, target and decision |
| Grant/revoke access workflow | Safeguards 6.1, 6.2 | AC-2, AC-3 | request, approval, grant/revocation timestamps |
| MFA for privileged access | Safeguard 6.5 | IA-2 | trusted MFA result reference, never OTP/secret |
| Centralized access policy | Safeguard 6.7 | AC-3, AC-6 | policy evaluation record and policy version |
| Session time-bound/JIT access | Control 6 (access management) | AC-2, AC-12, AC-6 | grant ID, effective expiry, revocation |
| Auditability of decisions | Control 8 (Audit Log Management) | AU-2, AU-3, AU-12 | decision, actor, target, timestamp, policy IDs, reason code |
| Controlled policy changes | — | CM-3, CM-6 | PR/review, change record, policy version, deployment record |

Sources to verify: CIS Controls v8.1 official materials and CIS Controls Navigator; NIST SP 800-53 Rev. 5 official publication. A mapping documents design intent only; it does not establish implementation effectiveness or certification.
