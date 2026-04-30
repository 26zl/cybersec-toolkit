# MITRE ATT&CK Quick Reference for Attack Path Architect

## Tactics Chain (Typical Kill Chain Order)

1. **Reconnaissance** (TA0043) - Covered by recon-dominator
2. **Initial Access** (TA0001) - Exploiting public-facing services
3. **Execution** (TA0002) - Running malicious code
4. **Persistence** (TA0003) - Maintaining access
5. **Privilege Escalation** (TA0004) - Getting higher permissions
6. **Defense Evasion** (TA0005) - Avoiding detection
7. **Credential Access** (TA0006) - Stealing credentials
8. **Lateral Movement** (TA0008) - Moving through the network
9. **Collection** (TA0009) - Gathering target data
10. **Exfiltration** (TA0010) - Stealing data out
11. **Impact** (TA0040) - Disrupting availability

## Most Common Web TTPs

| TTP | Name | Typical Scenario |
|-----|------|------------------|
| T1190 | Exploit Public-Facing App | SQLi, XSS, SSRF, RCE |
| T1133 | External Remote Services | Exposed SSH, RDP, VPN |
| T1078 | Valid Accounts | Default creds, stolen creds |
| T1059 | Command Interpreter | Post-exploitation command exec |
| T1552 | Unsecured Credentials | Config files, metadata, env vars |
| T1539 | Steal Web Session Cookie | XSS cookie theft |
| T1530 | Data from Cloud Storage | Public S3/GCS buckets |
| T1110 | Brute Force | Password spray, credential stuff |

## Reference
- Full matrix: https://attack.mitre.org/
- Navigator: https://mitre-attack.github.io/attack-navigator/
