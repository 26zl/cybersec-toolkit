#!/usr/bin/env bash
# Enforce MCP-first target work for clients with pre-execution hooks.
# Modes (hook JSON on stdin):
#   session-start  emit the contract as session context
#   pre-bash       deny a security-tool invocation until the MCP server has been
#                  consulted this session
# Escape hatch: CYBERSEC_AGENT_GUARD=0.
set -uo pipefail

MODE="${1:-}"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/cybersec-tools-mcp"
AUDIT_LOG="${CYBERSEC_MCP_AUDIT_LOG:-$STATE_DIR/audit.log}"

# Dual-use development tools are deliberately excluded.
GOVERNED=(
    nmap masscan rustscan zmap unicornscan
    sqlmap ffuf gobuster feroxbuster dirb dirsearch nikto wpscan whatweb
    nuclei amass subfinder httpx katana dalfox arjun paramspider xsstrike
    hydra medusa patator ncrack crackmapexec nxc netexec responder
    john hashcat hashid name-that-hash
    aircrack-ng airodump-ng aireplay-ng bettercap kismet
    msfconsole msfvenom searchsploit
    volatility3 vol.py binwalk foremost bulk_extractor
    stegseek zsteg steghide stegsolve
    radare2 rizin ropper ROPgadget pwninit one_gadget
    tshark bloodhound-python impacket-secretsdump impacket-psexec
)

emit() { printf '%s\n' "$1"; }

allow() { exit 0; }

# The interpolated value is restricted to GOVERNED, so it is JSON-safe.
deny() {
    printf '%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" \
        >> "$STATE_DIR/guard-denials.log" 2>/dev/null || true
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' \
        "This project routes target work through its MCP server, and '$1' is target work.\\nStart with guided_assessment (or suggest_for_ctf / suggest_for_bounty if you already know the workflow) — it returns the relevant skills, which tools are installed, and any prior writeup.\\nAfter that advisor call this guard stays out of the way for the rest of the session. Repository maintenance is unaffected; only security tooling is gated.\\nOverride for this shell with CYBERSEC_AGENT_GUARD=0."
    exit 0
}

# Print the executable token from each pipeline segment.
_first_words() {
    tr ';|&\n' '\n' <<< "$1" | while IFS= read -r seg; do
        local in_q=""   # quote char opened inside an assignment value, still unclosed
        for tok in $seg; do
            if [[ -n "$in_q" ]]; then
                # inside a quoted assignment value; the words here are data, not a
                # command — resume only after the closing quote.
                [[ "$tok" == *"$in_q"* ]] && in_q=""
                continue
            fi
            case "$tok" in
                sudo|env|command|exec|time|nohup|maybe_sudo) continue ;;
                *=[\"\']*)
                    # VAR="value with spaces" — if the quote does not close within
                    # this token, the value continues in following words. Skip them
                    # so a governed name inside the value is not read as a command.
                    local _v="${tok#*=}" _q="${tok#*=}"; _q="${_q:0:1}"
                    [[ "${_v:1}" == *"$_q"* ]] || in_q="$_q"
                    continue ;;
                *=*)  continue ;;
                -*)   continue ;;
                # ${tok##*/} not basename: no subprocess per token, and BSD/macOS
                # basename argument handling differs from GNU.
                *)    printf '%s\n' "${tok##*/}"; break ;;
            esac
        done
    done
}

_advised_since() {
    local since="$1"
    if command -v jq >/dev/null 2>&1; then
        jq -e --arg since "$since" '
            select(
                .event == "tool_call"
                and (
                    .tool == "guided_assessment"
                    or .tool == "suggest_for_ctf"
                    or .tool == "suggest_for_bounty"
                )
                and ((.ts // "") > $since)
            )
        ' "$AUDIT_LOG" >/dev/null 2>&1
        return
    fi

    python3 - "$AUDIT_LOG" "$since" <<'PY' >/dev/null 2>&1
import json
import sys

allowed = {"guided_assessment", "suggest_for_ctf", "suggest_for_bounty"}
path, since = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as audit:
        for line in audit:
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if (
                event.get("event") == "tool_call"
                and event.get("tool") in allowed
                and event.get("ts", "") > since
            ):
                raise SystemExit(0)
except OSError:
    pass
raise SystemExit(1)
PY
}

case "$MODE" in
session-start)
    marker="$STATE_DIR/guard-session"
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    date -u '+%Y-%m-%dT%H:%M:%S.000Z' > "$marker" 2>/dev/null || true
    emit '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"cybersec-toolkit contract — touching a TARGET (host, URL, sample, capture, a binary or file you did not write) starts with the cybersec-tools MCP server: guided_assessment, or suggest_for_ctf / suggest_for_bounty when the workflow is known. Then run_tool > run_pipeline > run_script. Editing THIS repository is ordinary work — use normal tools. Substantive security workflows end with a writeup under writeups/."}}'
    exit 0
    ;;
pre-bash)
    [[ "${CYBERSEC_AGENT_GUARD:-1}" == "0" ]] && allow
    [[ -f "$AUDIT_LOG" ]] || allow              # no MCP server configured; nothing to enforce

    # jq first (fast, and the toolkit installs it); python3 covers a bare macOS.
    if command -v jq >/dev/null 2>&1; then
        cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null)
    elif command -v python3 >/dev/null 2>&1; then
        cmd=$(python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("tool_input",{}).get("command",""))
except Exception: pass' 2>/dev/null)
    else
        allow                                   # no JSON reader; never block blindly
    fi
    [[ -n "$cmd" ]] || allow

    hit=""
    while IFS= read -r word; do
        for g in "${GOVERNED[@]}"; do
            [[ "$word" == "$g" ]] && { hit="$word"; break 2; }
        done
    done < <(_first_words "$cmd")
    [[ -n "$hit" ]] || allow

    # Has the server been called since this session started?
    since=$(cat "$STATE_DIR/guard-session" 2>/dev/null) || since=""
    [[ -n "$since" ]] || allow                  # no marker (first session after install)
    _advised_since "$since" && allow

    deny "$hit"
    ;;
*)
    echo "usage: $0 {session-start|pre-bash}   (hook JSON on stdin)" >&2
    exit 2
    ;;
esac
