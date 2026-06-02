---
name: mainframe-security-assessment
description: Use for mainframe, z/OS, RACF, ACF2, Top Secret, CICS, IMS, DB2, JCL, JES, APF libraries, USS, TN3270, privileged dataset, and legacy enterprise security assessment work.
---

# Mainframe security assessment

Use this skill when reviewing IBM z/OS or similar mainframe environments, identity controls, privileged datasets, transaction systems, and batch operations.

## Guardrails

- Treat production mainframes as safety-critical business systems. Avoid invasive testing unless explicitly approved.
- Prefer configuration review, evidence collection, and read-only queries.
- Coordinate with platform owners before touching RACF/ACF2/Top Secret policy, APF libraries, JES, CICS, or DB2 privileges.

## Workflow

1. Scope platform, security manager, LPARs, subsystems, network paths, and business-critical workloads.
2. Review identity and access:
   - privileged users and groups
   - dataset profiles and universal access
   - password/MFA/session policy
   - service IDs and stale accounts
3. Review system integrity:
   - APF-authorized libraries
   - program properties table
   - exits and started tasks
   - USS permissions
   - operator commands and console access
4. Review application surfaces:
   - CICS transactions
   - DB2 privileges
   - IMS regions
   - JCL libraries and scheduler access
   - TN3270 exposure and encryption
5. Produce a risk-ranked remediation plan with operational impact.

## Output pattern

| Area | Control weakness | Evidence needed | Business impact | Remediation | Change risk |
| --- | --- | --- | --- | --- | --- |
