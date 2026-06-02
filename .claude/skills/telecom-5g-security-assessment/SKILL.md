---
name: telecom-5g-security-assessment
description: Use for telecom and 5G security, mobile core, RAN, roaming, SS7, Diameter, GTP, IMS, SBA APIs, network slicing, SIM/eSIM, fraud, signaling, lawful intercept control review, and carrier-grade security assessments.
---

# Telecom and 5G security assessment

Use this skill for carrier, private 5G, mobile core, roaming, signaling, RAN, IMS, and telecom fraud/security work.

## Guardrails

- Do not run signaling, radio, roaming, or carrier tests without explicit authorization and lab constraints.
- Treat lawful intercept, emergency services, and billing systems as high-impact environments.
- Prefer architecture review and controlled validation over live-network probing.

## Workflow

1. Scope network type: private 5G, public carrier, MVNO, enterprise edge, lab, or roaming partner.
2. Map major domains:
   - RAN and gNodeB/eNodeB management
   - 5G core network functions
   - SBA/API exposure and service mesh
   - SS7/Diameter/GTP roaming paths
   - IMS/VoLTE
   - SIM/eSIM provisioning
   - billing, charging, and fraud systems
3. Review controls:
   - mutual authentication and certificate lifecycle
   - API authorization and segmentation
   - signaling firewall rules
   - slice isolation
   - management-plane hardening
   - roaming partner trust
   - logging, fraud detection, and incident response
4. Classify findings by subscriber privacy, availability, fraud, lawful intercept exposure, and network integrity.

## Output pattern

| Domain | Risk | Trust boundary | Evidence | Impact | Mitigation | Validation |
| --- | --- | --- | --- | --- | --- | --- |
