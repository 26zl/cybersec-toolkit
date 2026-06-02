---
name: security-wordlists
description: Use when you need wordlists for fuzzing, password cracking, content discovery, username enumeration, or pattern matching. Points to SecLists, PayloadsAllTheThings, and seclists-rolling that are already cloned by this installer. Triggers on "wordlist", "rockyou", "fuzz list", "common passwords", "directory wordlist", "subdomain wordlist".
---

# SecLists & wordlist locations

This installer clones SecLists and PayloadsAllTheThings during install via `git clone` into `$GITHUB_TOOL_DIR` — **`/opt` on Linux (root/sudo install), `~/tools` on Termux**. Use these paths instead of downloading new wordlists.

## Where things live

`$GITHUB_TOOL_DIR` is the install root: `/opt` on a standard Linux install, `~/tools` on Termux. The paths below use `/opt`; swap in `~/tools` on Termux.

| Resource | Path (installer-provided) |
| --- | --- |
| SecLists root | `/opt/SecLists/` (or `~/tools/SecLists/` on Termux) |
| PayloadsAllTheThings | `/opt/PayloadsAllTheThings/` (or `~/tools/...` on Termux) |
| rockyou.txt | `/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz` (untar to use) |
| Crackstation | `/opt/crackstation-human-only.txt` (if `crackstation` profile) |

> Kali ships `/usr/share/seclists/` and `/usr/share/wordlists/rockyou.txt` pre-baked, but **this installer does not create those** — it clones to `$GITHUB_TOOL_DIR`. Only fall back to the Kali paths if you are on Kali and they already exist.

```bash
# Find your install root (Linux clone first, then Termux, then Kali pre-baked)
ls /opt/SecLists/ 2>/dev/null || ls ~/tools/SecLists/ 2>/dev/null || ls /usr/share/seclists/
```

## Common picks per task

### Web content discovery (ffuf / gobuster)

```bash
SECLISTS="${GITHUB_TOOL_DIR:-/opt}/SecLists"  # /opt on Linux, ~/tools on Termux

# Quick pass
$SECLISTS/Discovery/Web-Content/common.txt

# Heavier
$SECLISTS/Discovery/Web-Content/raft-large-directories.txt
$SECLISTS/Discovery/Web-Content/big.txt

# API paths
$SECLISTS/Discovery/Web-Content/api/api-endpoints.txt
$SECLISTS/Discovery/Web-Content/api/objects.txt

# Backups / leftover files
$SECLISTS/Discovery/Web-Content/Common-PHP-Filenames.txt
$SECLISTS/Discovery/Web-Content/quickhits.txt

# Tech-specific
$SECLISTS/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt
$SECLISTS/Discovery/Web-Content/Apache.fuzz.txt
$SECLISTS/Discovery/Web-Content/Tomcat.fuzz.txt
```

### Subdomain enum

```bash
$SECLISTS/Discovery/DNS/subdomains-top1million-5000.txt
$SECLISTS/Discovery/DNS/subdomains-top1million-110000.txt
$SECLISTS/Discovery/DNS/dns-Jhaddix.txt
```

### Username enum

```bash
$SECLISTS/Usernames/top-usernames-shortlist.txt
$SECLISTS/Usernames/Names/names.txt
$SECLISTS/Usernames/cirt-default-usernames.txt
```

### Password cracking (hashcat / john / hydra)

```bash
$SECLISTS/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
$SECLISTS/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
$SECLISTS/Passwords/Common-Credentials/10-million-password-list-top-100000.txt
$SECLISTS/Passwords/Leaked-Databases/rockyou.txt.tar.gz
$SECLISTS/Passwords/Default-Credentials/default-passwords.csv
```

### Fuzzing payloads

```bash
$SECLISTS/Fuzzing/SQLi/Generic-SQLi.txt
$SECLISTS/Fuzzing/XSS/XSS-Jhaddix.txt
$SECLISTS/Fuzzing/LFI/LFI-Jhaddix.txt
$SECLISTS/Fuzzing/SSRF.txt
$SECLISTS/Fuzzing/big-list-of-naughty-strings.txt   # input validation
$SECLISTS/Fuzzing/special-chars.txt
$SECLISTS/Fuzzing/User-Agents/UserAgents.fuzz.txt
```

### PayloadsAllTheThings

Categorised by vulnerability class — read the README for each folder. Paths below use `/opt` (swap in `~/tools` on Termux); set `PATT="${GITHUB_TOOL_DIR:-/opt}/PayloadsAllTheThings"`. Highlights:

```text
/opt/PayloadsAllTheThings/SQL Injection/                 # SQLi cheatsheets + bypasses
/opt/PayloadsAllTheThings/XSS Injection/                 # XSS variants + WAF bypass
/opt/PayloadsAllTheThings/Server Side Template Injection/
/opt/PayloadsAllTheThings/Server Side Request Forgery/
/opt/PayloadsAllTheThings/Insecure Deserialization/
/opt/PayloadsAllTheThings/CSV Injection/
/opt/PayloadsAllTheThings/JSON Web Token/
/opt/PayloadsAllTheThings/Methodology and Resources/     # cheatsheets per topic
```

## Pattern-matching (regex catalogs)

For grep'ing logs/source for secrets:

```bash
$SECLISTS/Pattern-Matching/api-keys.txt              # API key shapes
$SECLISTS/Pattern-Matching/keywords.txt              # secret/token keywords
```

Or use purpose-built tools: `trufflehog`, `gitleaks`, `detect-secrets`.

## Web shells

`$SECLISTS/Web-Shells/` for testing upload bypasses on a CTF — never use these on real targets without authorization.

## Don't

- Download wordlists from random gists when SecLists already has the canonical version
- Use rockyou.txt for hashcat without first knowing the hash type — pick a smaller list and graduate up
- Forget to untar rockyou from SecLists (`/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz`); on Kali it is pre-baked at `/usr/share/wordlists/rockyou.txt.gz`
