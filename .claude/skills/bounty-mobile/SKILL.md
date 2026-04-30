---
name: bounty-mobile
description: Use when bug-bountying an Android (APK) or iOS (IPA) app. Covers static + dynamic analysis, Frida hooking, certificate pinning bypass, deep link / intent abuse, IPC, secrets in bundles. Triggers on "bounty mobile", "android app", "ios app", "apk analysis", "frida".
---

# Mobile bug bounty methodology

## 1. Get the artifact

Android APK:

```bash
# From device
adb shell pm path com.target.app
adb pull /data/app/.../base.apk

# From APKMirror / APKPure (be sure of version match)
```

iOS IPA: requires jailbroken device or developer build (`frida-ios-dump`, `flexdecrypt`).

## 2. Static analysis (Android)

```bash
# Decompile to source
jadx-gui base.apk          # GUI
jadx -d ./out base.apk     # CLI

# Disassemble to smali
apktool d base.apk -o ./out

# Manifest
aapt2 dump badging base.apk
aapt2 dump xmltree base.apk AndroidManifest.xml | head -100

# Quick wins
grep -rE "https?://" ./out/sources/ | sort -u                  # endpoints
grep -rE "(api[_-]?key|secret|token|password)" ./out/sources/   # hardcoded creds
trufflehog filesystem ./out/
```

Specifically check `AndroidManifest.xml` for:

- `android:exported="true"` activities/services/receivers (callable from other apps)
- `android:debuggable="true"` (massive vuln if shipped)
- Custom URL schemes (`<data android:scheme="...">`) — deep link attack surface
- Permissions declared (over-privilege?)
- `android:allowBackup="true"` (backup leakage)
- `networkSecurityConfig` (cleartext allowed?)

Look at `assets/` and `res/raw/` for embedded files (often contain SDK keys, dev URLs).

## 3. Static analysis (iOS)

```bash
# IPA is just a ZIP
unzip app.ipa -d app

# Class-dump from binary (if not encrypted)
class-dump-z Payload/MyApp.app/MyApp

# If encrypted (FairPlay) — need decrypted dump from jailbroken device:
# frida-ios-dump or bagbak

# Strings & secrets
strings Payload/MyApp.app/MyApp | grep -E "https?://|api[_-]?key"
trufflehog filesystem Payload/
```

Inspect `Info.plist` for:

- `LSApplicationQueriesSchemes` (URL schemes the app calls)
- `CFBundleURLTypes` (URL schemes the app accepts) — deep link surface
- `NSAppTransportSecurity` exceptions (cleartext allowed?)

## 4. Dynamic — Frida + Objection

```bash
# List apps on device
frida-ps -Uai

# Spawn with hook
frida -U -f com.target.app -l hook.js --no-pause

# Objection — high-level wrapper
objection -g com.target.app explore
# Inside objection:
android sslpinning disable
android hooking watch class_method com.target.app.AuthManager.login
android root disable
ios sslpinning disable
ios jailbreak disable
```

`objection` covers ~80% of routine instrumentation. Use Frida directly only when you need custom hooks.

## 5. Cert pinning bypass

| Approach | When |
| --- | --- |
| `objection ... ssl-pinning disable` | First try, works on most apps |
| Custom Frida script (apk-mitm, frida-ssl-bypass) | When objection fails |
| Patching the APK with `apk-mitm` | Non-rooted devices, or for permanent test build |
| `Magisk + LSPosed + JustTrustMe` | Rooted device, app-side bypass |

After bypass, route traffic through Burp / mitmproxy and replay/edit.

## 6. IPC / deep-link / intent abuse

For each `exported=true` activity / service / receiver:

```bash
# Trigger directly from adb
adb shell am start -n com.target.app/.SomeActivity --es param "value"
adb shell am broadcast -a com.target.app.ACTION_FOO --es key val
```

Look for:

- Privilege bypass (activity that should require auth but doesn't check)
- WebView with `addJavascriptInterface` exposing native methods to JS (XSS → RCE chain)
- File:// URL handling in WebView (read local files)
- Custom URL scheme triggers — e.g. `myapp://?action=delete&id=123`

ContentProviders: `adb shell content query --uri content://com.target.app/...` — many leak data.

## 7. Storage

Check what the app writes to disk (rooted device or post-frida pull):

- `/data/data/com.target.app/shared_prefs/` — often plaintext SharedPreferences with tokens
- `/data/data/com.target.app/databases/` — SQLite DBs, sometimes with secrets
- External storage (`/sdcard/Android/data/com.target.app/`) — accessible without root
- iOS: `~/Containers/Data/Application/<UUID>/Library/Preferences/` (plist)

## 8. Network traffic

```bash
# Setup mitmproxy / burp on host, route phone via WiFi proxy
# Install Burp/mitmproxy CA cert as system cert (rooted) or via apk-mitm patch

mitmproxy -p 8080 --mode regular
# or
burpsuite (Pro)

# Capture, intercept, replay, fuzz API calls just like web
```

After bypass + proxy, the target reduces to a normal API target → use `bounty-api` skill.

## 9. Tool stack from this installer (mobile module)

`jadx`, `apktool`, `aapt2`, `frida`, `frida-tools`, `objection`, `mobsf`, `androguard`, `mitmproxy`, `apkleaks`, `apk-mitm`.

iOS-specific (less common): `class-dump`, `bagbak`, `frida-ios-dump`, `iproxy`.

## 10. Reporting

Show the chain end-to-end: app → exposed component → impact. Include the exact `adb` command or Frida hook used. Note device + Android version + app version.
