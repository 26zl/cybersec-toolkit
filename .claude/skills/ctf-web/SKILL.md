---
name: ctf-web
description: Use when solving a CTF web challenge — SQLi, XSS, SSRF, SSTI, IDOR, auth bypass, file upload, deserialization, prototype pollution, race conditions, JWT attacks. Provides a decision tree and tool stack from this installer's web module. Triggers on "ctf web", "web challenge", "sqli", "xss", "ssti", "ssrf", "jwt".
---

# CTF web methodology

> **Pre-flight.** Confirm the event rules allow AI assistance (`authorization-gate`). Start with `suggest_for_ctf` or `guided_assessment`. Commands below are CLI notation: run them with `run_tool`/`run_pipeline` using registry names (`list_tools`), and `run_script` only for real logic. If policy blocks a command, tell the operator; do not fall back to the client shell. A tool that is not in the registry is a recommendation to the user (approval-gated install), not a bare command.

## 1. Recon (always)

```text
# Always start with these — in parallel (wordlist paths: see security-wordlists)
run_tool("curl", "-sI http://target/")                   # headers
run_tool("ffuf", "-w /opt/SecLists/Discovery/Web-Content/common.txt -u http://target/FUZZ")
run_tool("gobuster", "dir -u http://target -w /opt/SecLists/Discovery/Web-Content/common.txt")
run_tool("whatweb", "http://target")                     # tech stack
```

`nikto`, `jwt_tool`, `XSStrike`, `tplmap`, `Gopherus` and `phpggc` have supported Git CLI routes through `run_tool`. Check `get_tool_info` for executable readiness and argument restrictions; a repository clone alone does not prove the CLI is installed.

Source view:

- `view-source:` — comments, hidden inputs, JS files
- `/robots.txt`, `/sitemap.xml`, `/.git/`, `/.env`, `/.DS_Store`
- `wappalyzer` / `whatweb` for stack — frameworks dictate attack class

## 2. Map the attack surface

For each endpoint:

- Method (GET/POST/PUT/PATCH)
- Parameters (URL, body, headers, cookies)
- Auth requirements
- Reflection points (does input echo back?)
- Storage points (does input persist?)

## 3. Decision tree by symptom

| Symptom | Likely class | Tool |
| --- | --- | --- |
| Input echoed in HTML | XSS | manual + `XSStrike` |
| Error contains SQL | SQLi | `sqlmap` (registry) |
| URL parameter triggers fetch | SSRF | manual + `gopherus` for protocols |
| Template syntax `{{7*7}}` → `49` | SSTI | `tplmap`, manual jinja2/twig payloads |
| Numeric ID in URL/body | IDOR | manual enum + Burp Repeater |
| Login form, error tells "user not found" vs "wrong pass" | User enum | manual |
| File upload | Upload bypass | `BurpSuite`, manual extension/MIME tricks |
| `Cookie:` with base64/JSON | Cookie tampering | manual |
| `Authorization: Bearer eyJ...` | JWT | `jwt_tool`, `jwt-cracker` |
| `__proto__` or `constructor` accepted | Prototype pollution | manual JS payloads |
| Race-prone action (claim, vote) | Race condition | `turbo-intruder` Burp ext |
| Java/PHP/Ruby with unsafe deserialize | Deserialization | `ysoserial`, `phpggc` |

## 4. Specific attack notes

### SQLi

```text
# Boolean-based, time-based, UNION
run_tool("sqlmap", "-u http://target/page?id=1 --batch --level=5 --risk=3 --dbs")
# level 5 / risk 3 is for lab and CTF targets only; use bounty-web's lower values on bounty or production targets

# Cookie/header injection
run_tool("sqlmap", "-u http://target/ --cookie=session=* --level=5 --batch")

# POST data
run_tool("sqlmap", "-u http://target/login --data=user=*&pass=* --batch")
```

Policy blocks `-r`, `-m`, `-c`, `-l`, `-g`, `--tamper`, `--eval`, `--os-shell`, `--file-read` and `--file-write`; pass the request with `-u` plus `--data`/`--cookie`/`-H`.

### SSTI

Identify engine first: `{{7*7}}` works in Jinja/Twig, `${7*7}` in FreeMarker, `<%= 7*7 %>` in ERB.

Jinja2 RCE: `{{ ''.__class__.__mro__[1].__subclasses__() }}` — find subprocess/Popen.

### SSRF

- Cloud metadata: `http://169.254.169.254/latest/meta-data/`
- Localhost services: `http://127.0.0.1:port/`
- Gopher for raw TCP: `gopher://localhost:6379/_FLUSHALL` for redis
- DNS rebinding for filter bypass

### File upload

Try in order: rename extension (.php → .phtml/.php5/.phar), MIME spoofing, double extension (file.jpg.php), null byte (file.php%00.jpg), magic byte prefix, .htaccess upload, polyglot (PHP-in-JPG).

### JWT

```text
# Decode and test through the registered CLI; substitute the actual token.
run_pipeline([{"tool": "echo", "args": "<token>"}, {"tool": "cut", "args": "-d. -f1,2"}])   # base64url parts
run_tool("jwt_tool", "<token> -X a")                     # alg=none
run_tool("jwt_tool", "<token> -X i")                     # weak HMAC
run_tool("jwt_tool", "<token> -X k -pk public.pem")      # key confusion (RS→HS)
# crack an HMAC secret: hashcat mode 16500 (registry tool hashcat) with a wordlist
```

## 5. Don't waste time on

- DDOS, brute-forcing rate-limited endpoints (CTF won't gate solves on that)
- Server fingerprinting beyond initial `whatweb` (move on)
- Custom HTTP clients — use `curl` or Burp Repeater

## After solve

Use the `writeup-template` skill.
