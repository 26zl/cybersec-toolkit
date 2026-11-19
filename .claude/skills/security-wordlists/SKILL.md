---
name: security-wordlists
description: Use when you need wordlists for fuzzing, password cracking, content discovery, username enumeration, or pattern matching. Points to SecLists and PayloadsAllTheThings, which this installer clones. Triggers on "wordlist", "rockyou", "fuzz list", "common passwords", "directory wordlist", "subdomain wordlist".
---

# SecLists & wordlist locations

This installer clones SecLists and PayloadsAllTheThings during install via `git clone` into `$GITHUB_TOOL_DIR` — **`/opt` on Linux (root/sudo install), `~/tools` on Termux**. Use these paths instead of downloading new wordlists.

## Where things live

`$GITHUB_TOOL_DIR` is the install root: `/opt` on a standard Linux install, `~/tools` on Termux. The paths below use `/opt`; swap in `~/tools` on Termux.

| Resource | Path (installer-provided) |
| --- | --- |
| SecLists root | `/opt/SecLists/` (or `~/tools/SecLists/` on Termux) |
| PayloadsAllTheThings | `/opt/PayloadsAllTheThings/` (or `~/tools/...` on Termux) |
| rockyou.txt | `/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt` (the misc module unpacks the tarball next to it; untar `rockyou.txt.tar.gz` by hand if it is missing) |
| Wordlist extras | Not installed. Crackstation and other large lists are not fetched by any module; download them only when the task needs one |

> Kali ships `/usr/share/seclists/` and `/usr/share/wordlists/rockyou.txt` pre-baked, but **this installer does not create those** — it clones to `$GITHUB_TOOL_DIR`. Only fall back to the Kali paths if you are on Kali and they already exist.

```bash
# Find your install root (Linux clone first, then Termux, then Kali pre-baked)
ls /opt/SecLists/ 2>/dev/null || ls ~/tools/SecLists/ 2>/dev/null || ls /usr/share/seclists/
```

## Common picks per task

### Web content discovery (ffuf / gobuster)

```bash
# GITHUB_TOOL_DIR is only exported by the installer, so probe the usual roots
for d in "${GITHUB_TOOL_DIR:-}" /opt "$HOME/tools" /usr/share; do
  for n in SecLists seclists; do
    [ -d "$d/$n" ] && SECLISTS="$d/$n" && break 2
  done
done

# Quick pass
$SECLISTS/Discovery/Web-Content/common.txt

# Heavier
$SECLISTS/Discovery/Web-Content/raft-large-directories.txt
$SECLISTS/Discovery/Web-Content/big.txt

# API paths
$SECLISTS/Discovery/Web-Content/api/api-endpoints.txt
$SECLISTS/Discovery/Web-Content/api/objects.txt

# Backups / leftover files
$SECLISTS/Discovery/Web-Content/Programming-Language-Specific/Common-PHP-Filenames.txt
$SECLISTS/Discovery/Web-Content/quickhits.txt

# Tech-specific
$SECLISTS/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt
$SECLISTS/Discovery/Web-Content/Web-Servers/Apache.txt
$SECLISTS/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt
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
$SECLISTS/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt
$SECLISTS/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt
$SECLISTS/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt
$SECLISTS/Passwords/Leaked-Databases/rockyou.txt.tar.gz
$SECLISTS/Passwords/Default-Credentials/default-passwords.csv
```

### Fuzzing payloads

```bash
$SECLISTS/Fuzzing/Databases/SQLi/Generic-SQLi.txt
$SECLISTS/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt
$SECLISTS/Fuzzing/LFI/LFI-Jhaddix.txt
$SECLISTS/Fuzzing/big-list-of-naughty-strings.txt   # input validation
$SECLISTS/Fuzzing/special-chars.txt
$SECLISTS/Fuzzing/User-Agents/UserAgents.fuzz.txt
```

### PayloadsAllTheThings

Categorised by vulnerability class — read the README for each folder. Paths below use `/opt` (swap in `~/tools` on Termux); set `PATT` by probing the same roots (`${GITHUB_TOOL_DIR:-}`, `/opt`, `$HOME/tools`) for `PayloadsAllTheThings`. Highlights:

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
$SECLISTS/Pattern-Matching/grepstrings-basic.txt     # generic grep strings
$SECLISTS/Pattern-Matching/repo-scan.txt             # repository secret/keyword scan
$SECLISTS/Discovery/Variables/secret-keywords.txt    # secret/token keywords
```

Or use purpose-built tools: `trufflehog`, `gitleaks`, `detect-secrets`.

## Web shells

`$SECLISTS/Web-Shells/` (FuzzDB, JSP, CFM and others) for testing upload bypasses on a CTF — never use these on real targets without authorization.

## Don't

- Download wordlists from random gists when SecLists already has the canonical version
- Use rockyou.txt for hashcat without first knowing the hash type — pick a smaller list and graduate up
- Forget to untar rockyou from SecLists (`/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz`); on Kali it is pre-baked at `/usr/share/wordlists/rockyou.txt.gz`
