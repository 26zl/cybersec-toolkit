---
name: sap-erp-security-assessment
description: Use for SAP and ERP security assessments, S/4HANA, NetWeaver, ABAP, HANA DB, RFC trust, SAP Gateway, ICM, transports, default users, authorization roles, SoD, patching, and business-critical ERP control review.
---

# SAP and ERP security assessment

Use this skill for SAP, S/4HANA, NetWeaver, HANA, ABAP, RFC, Gateway, transports, and ERP authorization/security reviews.

## Guardrails

- Coordinate with SAP Basis, application owners, and change management before active testing.
- Avoid destructive transactions, mass role changes, and production data extraction unless explicitly approved.
- Separate technical security risks from segregation-of-duties and business-process risks.

## Workflow

1. Scope systems, clients, landscapes, internet exposure, trust relationships, and critical business processes.
2. Review platform security:
   - patch and kernel level
   - default users and passwords
   - RFC destinations and trust
   - Gateway and ICM exposure
   - HANA privileges and network access
   - SNC/TLS configuration
3. Review application security:
   - privileged roles and wildcard authorizations
   - SoD conflicts
   - emergency access/firefighter controls
   - transport approval and code review
   - custom ABAP security issues
   - logging and audit trails
4. Tie each finding to business impact: financial posting, master data, payroll, supply chain, or reporting integrity.

## Output pattern

| SAP area | Finding | Evidence | Business risk | Technical fix | Process fix |
| --- | --- | --- | --- | --- | --- |
