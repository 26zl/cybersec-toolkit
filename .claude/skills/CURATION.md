# Claude Skill Curation

Generated from local `SKILL.md` frontmatter by `scripts/curate_claude_skills.py --write`.
Edit the script rules, then regenerate this file when skill inventory changes.

## How to use this index

1. Start broad work with T0/T1 skills, then add a specialist only when the target platform or tool is clear.
1. Prefer coverage anchors for GRC, AI/LLM, IoT/embedded, mainframe, telecom/5G, SAP/ERP, and supply-chain work.
1. Treat T3 skills as exact-match playbooks. They are useful, but noisy for open-ended prompts.
1. For offensive or simulation skills, confirm authorization and environment before acting.

## Tier Counts

| Tier | Skills |
| --- | ---: |
| T0-router-and-project | 12 |
| T1-core | 78 |
| T1-coverage-anchor | 7 |
| T2-operational | 29 |
| T3-specialist | 734 |

## Domain Counts

| Domain | Skills |
| --- | ---: |
| agent_workflow | 6 |
| ai_llm_security | 15 |
| appsec_web_api | 84 |
| cloud_security | 92 |
| code_audit | 14 |
| crypto_blockchain | 14 |
| ctf_bounty | 10 |
| detection_soc_hunting | 102 |
| dfir_malware | 114 |
| general_security | 112 |
| grc_privacy | 38 |
| identity_access | 44 |
| iot_embedded_hardware | 15 |
| mobile_security | 13 |
| network_wireless | 47 |
| ot_ics_security | 15 |
| project_tooling | 9 |
| redteam_pentest | 90 |
| security_coordination | 3 |
| supply_chain_prodsec | 20 |
| telecom_mainframe_sap | 3 |

## Highest Priority Skills

| Priority | Skill | Domain | Tier |
| ---: | --- | --- | --- |
| 100 | `ai-llm-security-review` | ai_llm_security | T1-coverage-anchor |
| 100 | `grc-compliance-privacy-program` | grc_privacy | T1-coverage-anchor |
| 100 | `iot-embedded-hardware-security-assessment` | iot_embedded_hardware | T1-coverage-anchor |
| 100 | `skill-dependency-audit` | project_tooling | T0-router-and-project |
| 100 | `writeup-template` | project_tooling | T0-router-and-project |
| 100 | `authorization-gate` | security_coordination | T0-router-and-project |
| 100 | `finding-triage` | security_coordination | T0-router-and-project |
| 100 | `security-comms` | security_coordination | T0-router-and-project |
| 100 | `supply-chain-prodsec-hardening` | supply_chain_prodsec | T1-coverage-anchor |
| 100 | `mainframe-security-assessment` | telecom_mainframe_sap | T1-coverage-anchor |
| 100 | `sap-erp-security-assessment` | telecom_mainframe_sap | T1-coverage-anchor |
| 100 | `telecom-5g-security-assessment` | telecom_mainframe_sap | T1-coverage-anchor |
| 99 | `constant-time-analysis` | code_audit | T1-core |
| 99 | `insecure-defaults` | code_audit | T1-core |
| 99 | `semgrep` | code_audit | T1-core |
| 99 | `sharp-edges` | code_audit | T1-core |
| 99 | `supply-chain-risk-auditor` | code_audit | T1-core |
| 99 | `variant-analysis` | code_audit | T1-core |
| 99 | `yara-rule-authoring` | code_audit | T1-core |
| 99 | `add-tool` | project_tooling | T0-router-and-project |
| 99 | `mcp-sync-check` | project_tooling | T0-router-and-project |
| 99 | `module-scaffold` | project_tooling | T0-router-and-project |
| 99 | `security-payloads` | project_tooling | T0-router-and-project |
| 99 | `security-wordlists` | project_tooling | T0-router-and-project |
| 99 | `skill-curation-router` | project_tooling | T0-router-and-project |
| 97 | `karpathy-guidelines` | agent_workflow | T1-core |
| 96 | `differential-review` | code_audit | T1-core |
| 96 | `zeroize-audit` | code_audit | T1-core |
| 96 | `validate-all` | project_tooling | T0-router-and-project |
| 93 | `offensive-ai-security` | ai_llm_security | T1-core |

## Domain Anchors

Top skills per domain. Use these as the first candidates before searching the long tail.

### agent_workflow

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 97 | `karpathy-guidelines` | T1-core | normal |
| 58 | `extracting-config-from-agent-tesla-rat` | T3-specialist | normal |
| 58 | `implementing-runtime-application-self-protection` | T3-specialist | normal |
| 52 | `deploying-edr-agent-with-crowdstrike` | T3-specialist | requires-environment-check |
| 52 | `implementing-policy-as-code-with-open-policy-agent` | T3-specialist | normal |
| 52 | `performing-agentless-vulnerability-scanning` | T3-specialist | requires-environment-check |

### ai_llm_security

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `ai-llm-security-review` | T1-coverage-anchor | normal |
| 93 | `offensive-ai-security` | T1-core | sensitive-offensive |
| 92 | `ai-threat-testing` | T1-core | sensitive-offensive |
| 66 | `implementing-diamond-model-analysis` | T3-specialist | normal |
| 62 | `implementing-threat-modeling-with-mitre-attack` | T3-specialist | sensitive-offensive |
| 61 | `detecting-ai-model-prompt-injection-attacks` | T3-specialist | sensitive-offensive |
| 61 | `detecting-deepfake-audio-in-vishing-attacks` | T3-specialist | sensitive-offensive |
| 58 | `implementing-beyondcorp-zero-trust-access-model` | T3-specialist | normal |
| 58 | `implementing-cisa-zero-trust-maturity-model` | T3-specialist | normal |
| 58 | `implementing-llm-guardrails-for-security` | T3-specialist | normal |

### appsec_web_api

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 93 | `offensive-business-logic` | T1-core | sensitive-offensive |
| 93 | `offensive-deserialization` | T1-core | sensitive-offensive |
| 93 | `offensive-graphql` | T1-core | sensitive-offensive |
| 93 | `offensive-parameter-pollution` | T1-core | sensitive-offensive |
| 93 | `offensive-request-smuggling` | T1-core | sensitive-offensive |
| 93 | `offensive-sqli` | T1-core | sensitive-offensive |
| 93 | `offensive-ssti` | T1-core | sensitive-offensive |
| 93 | `offensive-waf-bypass` | T1-core | sensitive-offensive |
| 90 | `offensive-file-upload` | T1-core | sensitive-offensive |
| 90 | `offensive-idor` | T1-core | normal |

### cloud_security

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 93 | `offensive-cloud` | T1-core | sensitive-offensive |
| 69 | `hardening-docker-containers-for-production` | T2-operational | normal |
| 69 | `hardening-docker-daemon-configuration` | T2-operational | normal |
| 69 | `securing-aws-iam-permissions` | T2-operational | normal |
| 69 | `securing-kubernetes-on-cloud` | T2-operational | normal |
| 68 | `conducting-cloud-incident-response` | T2-operational | normal |
| 66 | `auditing-aws-s3-bucket-permissions` | T3-specialist | normal |
| 66 | `auditing-gcp-iam-permissions` | T3-specialist | normal |
| 66 | `implementing-cloud-security-posture-management` | T3-specialist | normal |
| 66 | `implementing-cloud-vulnerability-posture-management` | T3-specialist | normal |

### code_audit

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 99 | `constant-time-analysis` | T1-core | normal |
| 99 | `insecure-defaults` | T1-core | normal |
| 99 | `semgrep` | T1-core | normal |
| 99 | `sharp-edges` | T1-core | normal |
| 99 | `supply-chain-risk-auditor` | T1-core | sensitive-offensive |
| 99 | `variant-analysis` | T1-core | normal |
| 99 | `yara-rule-authoring` | T1-core | normal |
| 96 | `differential-review` | T1-core | normal |
| 96 | `zeroize-audit` | T1-core | normal |
| 91 | `dimensional-analysis` | T1-core | normal |

### crypto_blockchain

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 68 | `implementing-rsa-key-pair-management` | T2-operational | normal |
| 66 | `auditing-tls-certificate-transparency-logs` | T3-specialist | normal |
| 63 | `analyzing-ethereum-smart-contract-vulnerabilities` | T3-specialist | normal |
| 61 | `analyzing-certificate-transparency-for-phishing` | T3-specialist | sensitive-offensive |
| 61 | `analyzing-ransomware-payment-wallets` | T3-specialist | normal |
| 61 | `analyzing-tls-certificate-transparency-logs` | T3-specialist | normal |
| 60 | `performing-ssl-certificate-lifecycle-management` | T3-specialist | normal |
| 58 | `implementing-vulnerability-remediation-sla` | T3-specialist | normal |
| 58 | `validating-backup-integrity-for-recovery` | T3-specialist | normal |
| 56 | `implementing-aes-encryption-for-data-at-rest` | T3-specialist | normal |

### ctf_bounty

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 91 | `ctf-rev` | T1-core | normal |
| 88 | `bounty-recon` | T1-core | sensitive-offensive |
| 83 | `bounty-api` | T2-operational | sensitive-offensive |
| 83 | `bounty-mobile` | T2-operational | sensitive-offensive |
| 83 | `ctf-crypto` | T2-operational | sensitive-offensive |
| 83 | `ctf-forensics` | T2-operational | normal |
| 83 | `ctf-pwn` | T2-operational | normal |
| 83 | `ctf-stego` | T2-operational | normal |
| 83 | `ctf-web` | T2-operational | sensitive-offensive |
| 80 | `bounty-web` | T2-operational | sensitive-offensive |

### detection_soc_hunting

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 69 | `hunting-for-persistence-via-wmi-subscriptions` | T2-operational | normal |
| 63 | `detecting-modbus-protocol-anomalies` | T3-specialist | normal |
| 63 | `hunting-for-anomalous-powershell-execution` | T3-specialist | normal |
| 63 | `hunting-for-data-exfiltration-indicators` | T3-specialist | normal |
| 63 | `hunting-for-defense-evasion-via-timestomping` | T3-specialist | normal |
| 61 | `analyzing-windows-event-logs-in-splunk` | T3-specialist | normal |
| 61 | `detecting-anomalies-in-industrial-control-systems` | T3-specialist | requires-environment-check |
| 61 | `detecting-anomalous-authentication-patterns` | T3-specialist | normal |
| 61 | `detecting-arp-poisoning-in-network-traffic` | T3-specialist | sensitive-offensive |
| 61 | `detecting-attacks-on-scada-systems` | T3-specialist | sensitive-offensive |

### dfir_malware

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 87 | `dfir` | T1-core | sensitive-offensive |
| 69 | `analyzing-powershell-empire-artifacts` | T2-operational | normal |
| 69 | `analyzing-ransomware-encryption-mechanisms` | T2-operational | normal |
| 68 | `conducting-malware-incident-response` | T2-operational | normal |
| 67 | `analyzing-memory-dumps-with-volatility` | T3-specialist | normal |
| 66 | `building-incident-response-dashboard` | T3-specialist | normal |
| 66 | `building-incident-response-playbook` | T3-specialist | normal |
| 66 | `building-soc-playbook-for-ransomware` | T3-specialist | sensitive-offensive |
| 66 | `conducting-phishing-incident-response` | T3-specialist | sensitive-offensive |
| 66 | `conducting-post-incident-lessons-learned` | T3-specialist | normal |

### general_security

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 74 | `cve-poc-generator` | T2-operational | normal |
| 69 | `analyzing-prefetch-files-for-execution-history` | T2-operational | normal |
| 69 | `securing-github-actions-workflows` | T2-operational | normal |
| 69 | `securing-serverless-functions` | T2-operational | normal |
| 66 | `building-phishing-reporting-button-workflow` | T3-specialist | sensitive-offensive |
| 66 | `building-threat-hunt-hypothesis-framework` | T3-specialist | normal |
| 66 | `building-vulnerability-scanning-workflow` | T3-specialist | normal |
| 66 | `implementing-anti-phishing-training-program` | T3-specialist | sensitive-offensive |
| 66 | `implementing-google-workspace-admin-security` | T3-specialist | normal |
| 66 | `implementing-patch-management-workflow` | T3-specialist | requires-environment-check |

### grc_privacy

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `grc-compliance-privacy-program` | T1-coverage-anchor | advisory-verify-current-sources |
| 69 | `analyzing-kubernetes-audit-logs` | T2-operational | normal |
| 69 | `analyzing-linux-audit-logs-for-intrusion` | T2-operational | normal |
| 69 | `analyzing-office365-audit-logs-for-compromise` | T2-operational | normal |
| 69 | `detecting-azure-storage-account-misconfigurations` | T2-operational | normal |
| 68 | `implementing-iso-27001-information-security-management` | T2-operational | normal |
| 66 | `auditing-kubernetes-cluster-rbac` | T3-specialist | normal |
| 66 | `auditing-terraform-infrastructure-for-security` | T3-specialist | normal |
| 66 | `building-identity-governance-lifecycle-process` | T3-specialist | normal |
| 66 | `implementing-gdpr-data-subject-access-request` | T3-specialist | normal |

### identity_access

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 93 | `offensive-active-directory` | T1-core | sensitive-offensive |
| 93 | `offensive-jwt` | T1-core | sensitive-offensive |
| 93 | `offensive-oauth` | T1-core | sensitive-offensive |
| 68 | `implementing-azure-ad-privileged-identity-management` | T2-operational | normal |
| 66 | `auditing-azure-active-directory-configuration` | T3-specialist | normal |
| 66 | `implementing-delinea-secret-server-for-pam` | T3-specialist | normal |
| 66 | `implementing-pam-for-database-access` | T3-specialist | normal |
| 62 | `building-vulnerability-dashboard-with-defectdojo` | T3-specialist | normal |
| 62 | `implementing-privileged-access-management-with-cyberark` | T3-specialist | normal |
| 62 | `implementing-secrets-management-with-vault` | T3-specialist | requires-environment-check |

### iot_embedded_hardware

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `iot-embedded-hardware-security-assessment` | T1-coverage-anchor | normal |
| 90 | `offensive-iot` | T1-core | sensitive-offensive |
| 63 | `analyzing-macro-malware-in-office-documents` | T3-specialist | normal |
| 61 | `analyzing-uefi-bootkit-persistence` | T3-specialist | normal |
| 61 | `detecting-bluetooth-low-energy-attacks` | T3-specialist | sensitive-offensive |
| 60 | `performing-bluetooth-security-assessment` | T3-specialist | normal |
| 60 | `performing-iot-security-assessment` | T3-specialist | normal |
| 60 | `performing-plc-firmware-security-analysis` | T3-specialist | normal |
| 59 | `analyzing-malicious-pdf-with-peepdf` | T3-specialist | normal |
| 58 | `implementing-hardware-security-key-authentication` | T3-specialist | normal |

### mobile_security

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 90 | `offensive-mobile` | T1-core | sensitive-offensive |
| 66 | `implementing-mobile-application-management` | T3-specialist | normal |
| 60 | `performing-ios-app-security-assessment` | T3-specialist | normal |
| 59 | `analyzing-android-malware-with-apktool` | T3-specialist | normal |
| 59 | `analyzing-ios-app-security-with-objection` | T3-specialist | normal |
| 58 | `conducting-mobile-app-penetration-test` | T3-specialist | sensitive-offensive |
| 58 | `testing-android-intents-for-vulnerabilities` | T3-specialist | normal |
| 54 | `intercepting-mobile-traffic-with-burpsuite` | T3-specialist | normal |
| 54 | `reverse-engineering-android-malware-with-jadx` | T3-specialist | normal |
| 54 | `reverse-engineering-ios-app-with-frida` | T3-specialist | normal |

### network_wireless

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 93 | `offensive-bluetooth-classic` | T1-core | sensitive-offensive |
| 93 | `offensive-krack-fragattacks` | T1-core | sensitive-offensive |
| 93 | `offensive-wifi` | T1-core | sensitive-offensive |
| 93 | `offensive-wpa2-psk` | T1-core | sensitive-offensive |
| 93 | `offensive-wpa3-sae` | T1-core | sensitive-offensive |
| 93 | `offensive-wps` | T1-core | sensitive-offensive |
| 93 | `offensive-z-wave` | T1-core | sensitive-offensive |
| 93 | `offensive-zigbee-thread-matter` | T1-core | sensitive-offensive |
| 90 | `offensive-bluetooth-ble` | T1-core | sensitive-offensive |
| 90 | `offensive-deauth-disassoc` | T1-core | sensitive-offensive |

### ot_ics_security

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 69 | `securing-historian-server-in-ot-environment` | T2-operational | normal |
| 66 | `implementing-patch-management-for-ot-systems` | T3-specialist | normal |
| 61 | `detecting-attacks-on-historian-servers` | T3-specialist | sensitive-offensive |
| 61 | `securing-remote-access-to-ot-environment` | T3-specialist | normal |
| 60 | `performing-ot-network-security-assessment` | T3-specialist | normal |
| 60 | `performing-ot-vulnerability-assessment-with-claroty` | T3-specialist | normal |
| 60 | `performing-scada-hmi-security-assessment` | T3-specialist | normal |
| 58 | `implementing-dragos-platform-for-ot-monitoring` | T3-specialist | normal |
| 58 | `implementing-network-segmentation-for-ot` | T3-specialist | normal |
| 58 | `monitoring-scada-modbus-traffic-anomalies` | T3-specialist | normal |

### project_tooling

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `skill-dependency-audit` | T0-router-and-project | normal |
| 100 | `writeup-template` | T0-router-and-project | normal |
| 99 | `add-tool` | T0-router-and-project | normal |
| 99 | `mcp-sync-check` | T0-router-and-project | normal |
| 99 | `module-scaffold` | T0-router-and-project | normal |
| 99 | `security-payloads` | T0-router-and-project | sensitive-offensive |
| 99 | `security-wordlists` | T0-router-and-project | normal |
| 99 | `skill-curation-router` | T0-router-and-project | normal |
| 96 | `validate-all` | T0-router-and-project | normal |

### redteam_pentest

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 93 | `offensive-basic-exploitation` | T1-core | sensitive-offensive |
| 93 | `offensive-crash-analysis` | T1-core | normal |
| 93 | `offensive-edr-evasion` | T1-core | sensitive-offensive |
| 93 | `offensive-exploit-development` | T1-core | normal |
| 93 | `offensive-fuzzing` | T1-core | normal |
| 93 | `offensive-fuzzing-course` | T1-core | normal |
| 93 | `offensive-initial-access` | T1-core | sensitive-offensive |
| 93 | `offensive-mitigations` | T1-core | sensitive-offensive |
| 93 | `offensive-osint` | T1-core | sensitive-offensive |
| 93 | `offensive-shellcode` | T1-core | normal |

### security_coordination

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `authorization-gate` | T0-router-and-project | sensitive-offensive |
| 100 | `finding-triage` | T0-router-and-project | normal |
| 100 | `security-comms` | T0-router-and-project | advisory-verify-current-sources |

### supply_chain_prodsec

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `supply-chain-prodsec-hardening` | T1-coverage-anchor | normal |
| 67 | `detecting-supply-chain-attacks-in-ci-cd` | T3-specialist | sensitive-offensive |
| 61 | `analyzing-sbom-for-supply-chain-vulnerabilities` | T3-specialist | normal |
| 61 | `detecting-typosquatting-packages-in-npm-pypi` | T3-specialist | sensitive-offensive |
| 61 | `hunting-for-supply-chain-compromise` | T3-specialist | normal |
| 61 | `securing-container-registry-images` | T3-specialist | normal |
| 58 | `implementing-devsecops-security-scanning` | T3-specialist | normal |
| 58 | `implementing-secrets-scanning-in-ci-cd` | T3-specialist | normal |
| 58 | `implementing-semgrep-for-custom-sast-rules` | T3-specialist | normal |
| 58 | `implementing-sigstore-for-software-signing` | T3-specialist | normal |

### telecom_mainframe_sap

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `mainframe-security-assessment` | T1-coverage-anchor | normal |
| 100 | `sap-erp-security-assessment` | T1-coverage-anchor | normal |
| 100 | `telecom-5g-security-assessment` | T1-coverage-anchor | normal |

## Query helper

Use the script when the prompt is broad or many skills look similar:

```bash
python3 scripts/curate_claude_skills.py --query "cloud incident response" --top 10
```
