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
| T0-router-and-project | 14 |
| T1-core | 83 |
| T1-coverage-anchor | 7 |
| T2-operational | 148 |
| T3-specialist | 620 |

## Domain Counts

| Domain | Skills |
| --- | ---: |
| agent_workflow | 8 |
| ai_llm_security | 18 |
| appsec_web_api | 81 |
| cloud_security | 89 |
| code_audit | 14 |
| crypto_blockchain | 17 |
| ctf_bounty | 16 |
| detection_soc_hunting | 131 |
| dfir_malware | 115 |
| general_security | 34 |
| grc_privacy | 89 |
| identity_access | 45 |
| iot_embedded_hardware | 14 |
| mobile_security | 9 |
| network_wireless | 37 |
| ot_ics_security | 16 |
| project_tooling | 10 |
| redteam_pentest | 100 |
| security_coordination | 4 |
| supply_chain_prodsec | 22 |
| telecom_mainframe_sap | 3 |

## Highest Priority Skills

| Priority | Skill | Domain | Tier |
| ---: | --- | --- | --- |
| 100 | `ai-llm-security-review` | ai_llm_security | T1-coverage-anchor |
| 100 | `grc-compliance-privacy-program` | grc_privacy | T1-coverage-anchor |
| 100 | `iot-embedded-hardware-security-assessment` | iot_embedded_hardware | T1-coverage-anchor |
| 100 | `guided-assessment` | project_tooling | T0-router-and-project |
| 100 | `skill-dependency-audit` | project_tooling | T0-router-and-project |
| 100 | `writeup-template` | project_tooling | T0-router-and-project |
| 100 | `authorization-gate` | security_coordination | T0-router-and-project |
| 100 | `evidence-hygiene` | security_coordination | T0-router-and-project |
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

## Domain Anchors

Top skills per domain. Use these as the first candidates before searching the long tail.

### agent_workflow

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 97 | `karpathy-guidelines` | T1-core | normal |
| 71 | `analyzing-powershell-empire-artifacts` | T2-operational | normal |
| 63 | `implementing-endpoint-dlp-controls` | T3-specialist | requires-environment-check |
| 60 | `deploying-palo-alto-prisma-access-zero-trust` | T3-specialist | requires-environment-check |
| 60 | `extracting-config-from-agent-tesla-rat` | T3-specialist | sensitive-offensive |
| 60 | `implementing-runtime-application-self-protection` | T3-specialist | sensitive-offensive |
| 54 | `implementing-policy-as-code-with-open-policy-agent` | T3-specialist | requires-environment-check |
| 54 | `performing-agentless-vulnerability-scanning` | T3-specialist | requires-environment-check |

### ai_llm_security

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `ai-llm-security-review` | T1-coverage-anchor | normal |
| 93 | `offensive-ai-security` | T1-core | sensitive-offensive |
| 92 | `ai-threat-testing` | T1-core | sensitive-offensive |
| 68 | `implementing-diamond-model-analysis` | T2-operational | normal |
| 68 | `implementing-llm-guardrails-for-security` | T2-operational | advisory-verify-current-sources |
| 66 | `implementing-conduit-security-for-ot-remote-access` | T3-specialist | requires-environment-check |
| 63 | `detecting-ai-model-prompt-injection-attacks` | T3-specialist | sensitive-offensive |
| 63 | `detecting-deepfake-audio-in-vishing-attacks` | T3-specialist | sensitive-offensive |
| 63 | `profiling-threat-actor-groups` | T3-specialist | normal |
| 60 | `executing-red-team-engagement-planning` | T3-specialist | sensitive-offensive |

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
| 91 | `web2-vuln-classes` | T1-core | sensitive-offensive |
| 90 | `offensive-file-upload` | T1-core | sensitive-offensive |

### cloud_security

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 93 | `offensive-cloud` | T1-core | sensitive-offensive |
| 71 | `analyzing-cloud-storage-access-patterns` | T2-operational | normal |
| 71 | `analyzing-linux-elf-malware` | T2-operational | normal |
| 71 | `detecting-aws-guardduty-findings-automation` | T2-operational | normal |
| 71 | `detecting-serverless-function-injection` | T2-operational | sensitive-offensive |
| 71 | `hardening-docker-containers-for-production` | T2-operational | sensitive-offensive |
| 71 | `hardening-docker-daemon-configuration` | T2-operational | normal |
| 71 | `implementing-mobile-application-management` | T2-operational | normal |
| 71 | `securing-aws-iam-permissions` | T2-operational | sensitive-offensive |
| 71 | `securing-kubernetes-on-cloud` | T2-operational | normal |

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
| 88 | `meme-coin-audit` | T1-core | sensitive-offensive |
| 88 | `web3-audit` | T1-core | normal |
| 71 | `analyzing-ransomware-encryption-mechanisms` | T2-operational | normal |
| 71 | `implementing-mtls-for-zero-trust-services` | T2-operational | normal |
| 71 | `managing-intelligence-lifecycle` | T2-operational | normal |
| 68 | `auditing-tls-certificate-transparency-logs` | T2-operational | sensitive-offensive |
| 68 | `implementing-rsa-key-pair-management` | T2-operational | normal |
| 65 | `performing-post-quantum-cryptography-migration` | T3-specialist | normal |
| 63 | `analyzing-certificate-transparency-for-phishing` | T3-specialist | sensitive-offensive |
| 63 | `analyzing-ethereum-smart-contract-vulnerabilities` | T3-specialist | normal |

### ctf_bounty

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 91 | `bb-methodology` | T1-core | normal |
| 91 | `ctf-rev` | T1-core | normal |
| 88 | `bounty-recon` | T1-core | sensitive-offensive |
| 88 | `bug-bounty` | T1-core | sensitive-offensive |
| 83 | `bounty-api` | T2-operational | sensitive-offensive |
| 83 | `bounty-mobile` | T2-operational | sensitive-offensive |
| 83 | `credential-attack` | T2-operational | sensitive-offensive |
| 83 | `ctf-crypto` | T2-operational | sensitive-offensive |
| 83 | `ctf-forensics` | T2-operational | normal |
| 83 | `ctf-pwn` | T2-operational | normal |

### detection_soc_hunting

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 74 | `analyzing-kubernetes-audit-logs` | T2-operational | normal |
| 74 | `hunting-advanced-persistent-threats` | T2-operational | normal |
| 74 | `triaging-security-alerts-in-splunk` | T2-operational | normal |
| 71 | `analyzing-linux-audit-logs-for-intrusion` | T2-operational | normal |
| 71 | `automating-ioc-enrichment` | T2-operational | normal |
| 71 | `building-soc-playbook-for-ransomware` | T2-operational | sensitive-offensive |
| 71 | `building-vulnerability-scanning-workflow` | T2-operational | normal |
| 71 | `correlating-security-events-in-qradar` | T2-operational | sensitive-offensive |
| 71 | `detecting-azure-lateral-movement` | T2-operational | normal |
| 71 | `hunting-for-persistence-via-wmi-subscriptions` | T2-operational | requires-environment-check |

### dfir_malware

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 87 | `dfir` | T1-core | sensitive-offensive |
| 74 | `analyzing-cyber-kill-chain` | T2-operational | sensitive-offensive |
| 71 | `analyzing-prefetch-files-for-execution-history` | T2-operational | normal |
| 71 | `analyzing-uefi-bootkit-persistence` | T2-operational | sensitive-offensive |
| 71 | `analyzing-windows-amcache-artifacts` | T2-operational | normal |
| 71 | `building-incident-response-dashboard` | T2-operational | normal |
| 71 | `generating-threat-intelligence-reports` | T2-operational | normal |
| 69 | `analyzing-lnk-file-and-jump-list-artifacts` | T2-operational | normal |
| 68 | `analyzing-memory-forensics-with-lime-and-volatility` | T2-operational | normal |
| 68 | `conducting-malware-incident-response` | T2-operational | normal |

### general_security

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 74 | `cve-poc-generator` | T2-operational | normal |
| 71 | `evaluating-threat-intelligence-platforms` | T2-operational | normal |
| 68 | `building-phishing-reporting-button-workflow` | T2-operational | sensitive-offensive |
| 68 | `implementing-anti-phishing-training-program` | T2-operational | sensitive-offensive |
| 68 | `implementing-patch-management-workflow` | T2-operational | requires-environment-check |
| 68 | `implementing-threat-intelligence-lifecycle-management` | T2-operational | normal |
| 68 | `testing-for-business-logic-vulnerabilities` | T2-operational | sensitive-offensive |
| 67 | `analyzing-windows-prefetch-with-python` | T3-specialist | normal |
| 67 | `triaging-vulnerabilities-with-ssvc-framework` | T3-specialist | normal |
| 66 | `analyzing-threat-intelligence-feeds` | T3-specialist | normal |

### grc_privacy

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `grc-compliance-privacy-program` | T1-coverage-anchor | advisory-verify-current-sources |
| 71 | `analyzing-office365-audit-logs-for-compromise` | T2-operational | normal |
| 71 | `analyzing-persistence-mechanisms-in-linux` | T2-operational | normal |
| 71 | `detecting-azure-storage-account-misconfigurations` | T2-operational | normal |
| 71 | `detecting-email-account-compromise` | T2-operational | normal |
| 71 | `detecting-suspicious-oauth-application-consent` | T2-operational | sensitive-offensive |
| 71 | `hunting-for-dns-based-persistence` | T2-operational | normal |
| 71 | `implementing-attack-surface-management` | T2-operational | sensitive-offensive |
| 71 | `implementing-browser-isolation-for-zero-trust` | T2-operational | sensitive-offensive |
| 71 | `implementing-ebpf-security-monitoring` | T2-operational | normal |

### identity_access

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 93 | `offensive-active-directory` | T1-core | sensitive-offensive |
| 93 | `offensive-jwt` | T1-core | sensitive-offensive |
| 93 | `offensive-oauth` | T1-core | sensitive-offensive |
| 68 | `executing-active-directory-attack-simulation` | T2-operational | sensitive-offensive |
| 68 | `implementing-azure-ad-privileged-identity-management` | T2-operational | normal |
| 68 | `implementing-delinea-secret-server-for-pam` | T2-operational | sensitive-offensive |
| 68 | `implementing-google-workspace-admin-security` | T2-operational | sensitive-offensive |
| 68 | `implementing-pam-for-database-access` | T2-operational | sensitive-offensive |
| 68 | `testing-oauth2-implementation-flaws` | T2-operational | sensitive-offensive |
| 64 | `building-threat-feed-aggregation-with-misp` | T3-specialist | normal |

### iot_embedded_hardware

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `iot-embedded-hardware-security-assessment` | T1-coverage-anchor | normal |
| 90 | `offensive-iot` | T1-core | sensitive-offensive |
| 74 | `detecting-bluetooth-low-energy-attacks` | T2-operational | sensitive-offensive |
| 68 | `implementing-hardware-security-key-authentication` | T2-operational | sensitive-offensive |
| 63 | `analyzing-bootkit-and-rootkit-samples` | T3-specialist | normal |
| 63 | `analyzing-macro-malware-in-office-documents` | T3-specialist | sensitive-offensive |
| 62 | `performing-bluetooth-security-assessment` | T3-specialist | normal |
| 62 | `performing-firmware-extraction-with-binwalk` | T3-specialist | sensitive-offensive |
| 62 | `performing-firmware-malware-analysis` | T3-specialist | normal |
| 62 | `performing-iot-security-assessment` | T3-specialist | sensitive-offensive |

### mobile_security

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 90 | `offensive-mobile` | T1-core | sensitive-offensive |
| 70 | `analyzing-ios-app-security-with-objection` | T2-operational | sensitive-offensive |
| 65 | `performing-ios-app-security-assessment` | T3-specialist | sensitive-offensive |
| 63 | `performing-android-app-static-analysis-with-mobsf` | T3-specialist | sensitive-offensive |
| 62 | `performing-mobile-app-certificate-pinning-bypass` | T3-specialist | sensitive-offensive |
| 59 | `analyzing-android-malware-with-apktool` | T3-specialist | normal |
| 59 | `reverse-engineering-ios-app-with-frida` | T3-specialist | sensitive-offensive |
| 57 | `performing-dynamic-analysis-of-android-app` | T3-specialist | sensitive-offensive |
| 56 | `reverse-engineering-android-malware-with-jadx` | T3-specialist | sensitive-offensive |

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
| 71 | `securing-historian-server-in-ot-environment` | T2-operational | advisory-verify-current-sources |
| 68 | `implementing-ot-incident-response-playbook` | T2-operational | normal |
| 68 | `implementing-patch-management-for-ot-systems` | T2-operational | normal |
| 63 | `detecting-anomalies-in-industrial-control-systems` | T3-specialist | requires-environment-check |
| 63 | `detecting-attacks-on-historian-servers` | T3-specialist | sensitive-offensive |
| 63 | `detecting-attacks-on-scada-systems` | T3-specialist | sensitive-offensive |
| 63 | `detecting-dnp3-protocol-anomalies` | T3-specialist | normal |
| 63 | `detecting-modbus-command-injection-attacks` | T3-specialist | sensitive-offensive |
| 62 | `performing-ot-network-security-assessment` | T3-specialist | sensitive-offensive |
| 62 | `performing-ot-vulnerability-assessment-with-claroty` | T3-specialist | normal |

### project_tooling

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `guided-assessment` | T0-router-and-project | sensitive-offensive |
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
| 100 | `evidence-hygiene` | T0-router-and-project | sensitive-offensive |
| 100 | `finding-triage` | T0-router-and-project | normal |
| 100 | `security-comms` | T0-router-and-project | advisory-verify-current-sources |

### supply_chain_prodsec

| Priority | Skill | Tier | Sensitivity |
| ---: | --- | --- | --- |
| 100 | `supply-chain-prodsec-hardening` | T1-coverage-anchor | normal |
| 72 | `detecting-supply-chain-attacks-in-ci-cd` | T2-operational | sensitive-offensive |
| 71 | `analyzing-sbom-for-supply-chain-vulnerabilities` | T2-operational | advisory-verify-current-sources |
| 68 | `implementing-sigstore-for-software-signing` | T2-operational | normal |
| 63 | `hunting-for-supply-chain-compromise` | T3-specialist | normal |
| 63 | `securing-container-registry-images` | T3-specialist | requires-environment-check |
| 62 | `implementing-supply-chain-security-with-in-toto` | T3-specialist | normal |
| 62 | `performing-supply-chain-attack-simulation` | T3-specialist | sensitive-offensive |
| 60 | `implementing-code-signing-for-artifacts` | T3-specialist | normal |
| 60 | `implementing-devsecops-security-scanning` | T3-specialist | normal |

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
