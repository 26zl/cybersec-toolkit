#!/usr/bin/env bash
# Enforce MCP-first target work for clients with pre-execution hooks.
# Modes (hook JSON on stdin):
#   session-start  emit the contract as session context
#   pre-bash       deny a security-tool invocation until the MCP server has been
#                  consulted this session, and again once that is hours old
# Escape hatch: CYBERSEC_AGENT_GUARD=0.
set -uo pipefail

MODE="${1:-}"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/cybersec-tools-mcp"
AUDIT_LOG="${CYBERSEC_MCP_AUDIT_LOG:-$STATE_DIR/audit.log}"

# An advisor call clears the shell for this long. A session can run for days through
# compaction and resume, and one call must not cover whatever it later turns to.
CLEARANCE_SECONDS=14400

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
    setoolkit
)

# Read only registry metadata; importing the server would initialize operator state.
_registry_commands() {
    local root
    root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd) || return 1
    python3 -B - "$root" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from mcp_server.tools_db import GIT_BIN_NAMES, PACKAGE_EXTRA_BINARIES, binary_candidates

# These remain ordinary repository-development commands, including the shell builtin set.
development = {
    "ar", "as", "awk", "base64", "bash", "binutils", "bun", "cargo", "cat", "cc",
    "clang", "clang++", "cmake", "cp", "curl", "cut", "date", "dd", "diff", "du", "env",
    "file", "find", "gcc", "g++", "gdb", "git", "go", "grep", "gzip", "head", "jq",
    "ld", "ltrace", "ls", "make", "nasm", "nm", "node", "npm", "objcopy", "objdump",
    "openssl", "perl", "php", "pip", "pip3", "pipx", "pnpm", "python", "python2", "python3",
    "readelf", "rg", "ruby", "sed", "set", "sh", "sort", "stat", "strace", "strings",
    "strip", "tail", "tar", "tee", "test", "touch", "tr", "uniq", "unzip", "uv", "valgrind",
    "wc", "wget", "xxd", "yarn", "zip", "zsh",
}
names = set()
for tool in json.loads((root / "tools_config.json").read_text(encoding="utf-8")):
    name, method = tool["name"], tool["method"]
    if method == "docker" or name == "ctf-crypto-venv":
        continue
    if method == "git" and name not in GIT_BIN_NAMES:
        continue
    names.add(name)
    names.update(binary_candidates(method, name))
    names.update(PACKAGE_EXTRA_BINARIES.get(name, ()))
for name in sorted(names):
    if name.casefold() not in development and re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", name):
        print(name)
PY
}

emit() { printf '%s\n' "$1"; }

allow() { exit 0; }

# The interpolated value is restricted to GOVERNED, so it is JSON-safe.
deny() {
    local log="$STATE_DIR/guard-denials.log"
    # Bounded: keep one previous generation once the log passes 1 MiB.
    if [[ -f "$log" ]] && (( $(wc -c < "$log" 2>/dev/null || echo 0) > 1048576 )); then
        mv -f "$log" "$log.1" 2>/dev/null || true
    fi
    printf '%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" \
        >> "$log" 2>/dev/null || true
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' \
        "This project routes target work through its MCP server, and '$1' is target work.\\nStart with guided_assessment (or suggest_for_ctf / suggest_for_bounty if you already know the workflow): it returns the relevant skills and which tools are installed.\\nThen run the tool with run_tool or run_pipeline, where the sandbox, the scope policy and the audit log apply; a direct shell invocation gets none of them.\\nRepository maintenance is unaffected; only security tooling is gated."
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
                sudo|env|command|exec|time|nohup|maybe_sudo|*/sudo|*/env) continue ;;
                if|then|else|elif|do|while|until|\!|\{|doas|watch|strace|ltrace|eval|builtin|coproc) continue ;;
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

# Quote- and heredoc-aware variant of _first_words: quoted text and heredoc bodies are data.
read -r -d '' _PY_COMMAND_WORDS <<'PY' || true
import re
import shlex
import sys

SKIP = {
    "sudo", "env", "exec", "time", "nohup", "maybe_sudo", "nice", "ionice", "stdbuf", "xargs", "timeout",
    "setsid", "doas", "watch", "strace", "ltrace", "builtin", "eval",
}
# Shell keywords that precede a command: the command after them is the one to inspect.
KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "coproc"}
INTERPRETERS = re.compile(r"python[0-9.]*|perl|ruby|node|php")
SHELL_C = re.compile(r"-[A-Za-z]*c")
TAKES_ARG = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U"},
    "env": {"-u", "-C"},
    "nice": {"-n"},
    "ionice": {"-c", "-n", "-p"},
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "doas": {"-u", "-C"},
    "watch": {"-n", "-d"},
    "strace": {"-o", "-e", "-p", "-s", "-u"},
    "xargs": {"-n", "-I", "-P", "-d", "-a", "-L", "-s", "-E"},
}
SHELLS = {"bash", "sh", "dash", "zsh"}
DURATION = re.compile(r"\d+(\.\d+)?[smhd]?")
OPS = set(";&|()\n")
HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
SUBST = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def drop_heredoc_bodies(text):
    lines = text.split("\n")
    kept = []
    i, n = 0, len(lines)
    while i < n:
        kept.append(lines[i])
        m = HEREDOC.search(lines[i])
        i += 1
        if not m:
            continue
        strip_tabs, delim = m.group(1) == "-", m.group(3)
        j = i
        while j < n and (lines[j].lstrip("\t") if strip_tabs else lines[j]) != delim:
            j += 1
        # Drop the body only when the delimiter is actually reached; an unclosed
        # heredoc (a `<<` in a quote or arithmetic) leaves its lines to be scanned.
        if j < n:
            i = j + 1
    return "\n".join(kept)


def command_words(text):
    lex = shlex.shlex(drop_heredoc_bodies(text), posix=True, punctuation_chars=";&|()\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    words, expect, wrapper, skip_next, shell_c, interp = [], True, None, False, None, None
    for tok in lex:
        if tok and set(tok) <= OPS:
            expect, wrapper, skip_next, shell_c, interp = True, None, False, None, None
            continue
        # `bash -c '<script>'`: the script is a command line of its own.
        if shell_c == "arg":
            words.extend(command_words(tok))
            shell_c = None
            continue
        if shell_c == "shell":
            if SHELL_C.fullmatch(tok):
                shell_c = "arg"
                continue
            if tok.startswith("-"):
                continue
        shell_c = None
        # Command substitution runs even inside double quotes.
        for m in SUBST.finditer(tok):
            words.extend(command_words(m.group(1) if m.group(1) is not None else m.group(2)))
        if not expect:
            # `python3 /opt/tool/tool.py`, `python3 -m tool`: the script is the command.
            if interp and tok:
                if tok == "-m" and interp == "script":
                    interp = "module"
                elif not tok.startswith("-"):
                    if interp == "script":
                        name = tok.rsplit("/", 1)[-1]
                        words.append(name)
                        name = re.sub(r"\.(py|pl|rb|js|php)$", "", name)
                    else:
                        name = tok
                    words.append(name)
                    interp = None
            continue
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("#"):
            expect = False
            continue
        if wrapper == "command" and tok in ("-v", "-V"):
            expect = False
            continue
        base = tok.rsplit("/", 1)[-1]
        if base in KEYWORDS and wrapper is None:
            continue
        if base in SKIP or base == "command":
            wrapper = base
            continue
        if wrapper == "eval" and not tok.startswith("-"):
            words.extend(command_words(tok))
            expect = False
            continue
        if tok.startswith("-"):
            skip_next = tok in TAKES_ARG.get(wrapper, ())
            continue
        if ASSIGN.match(tok):
            continue
        if wrapper == "timeout" and DURATION.fullmatch(tok):
            continue
        word = base
        words.append(word)
        expect = False
        if word in SHELLS:
            shell_c = "shell"
        elif INTERPRETERS.fullmatch(word):
            interp = "script"
    return words


print("\n".join(command_words(sys.stdin.read())))
PY

_command_words() {
    local out
    if command -v python3 >/dev/null 2>&1 \
        && out=$(printf '%s' "$1" | python3 -c "$_PY_COMMAND_WORDS" 2>/dev/null); then
        [[ -z "$out" ]] || printf '%s\n' "$out"
        return 0
    fi
    _first_words "$1"
}

# _clearance_floor — the UTC time before which an advisor call no longer clears.
# CYBERSEC_AGENT_GUARD_NOW (epoch seconds) lets the tests fix the clock.
_clearance_floor() {
    local now="${CYBERSEC_AGENT_GUARD_NOW:-}" cutoff
    [[ "$now" =~ ^[0-9]+$ ]] || now=$(date +%s)
    cutoff=$((now - CLEARANCE_SECONDS))
    # GNU date, then BSD date.
    date -u -d "@$cutoff" '+%Y-%m-%dT%H:%M:%S.000Z' 2>/dev/null \
        || date -u -r "$cutoff" '+%Y-%m-%dT%H:%M:%S.000Z' 2>/dev/null
}

_advised_since() {
    local since="$1" logs=("$AUDIT_LOG")
    # audit.py rotates at 5 MB; a clearance may already sit in the newest backup.
    [[ -f "$AUDIT_LOG.1" ]] && logs+=("$AUDIT_LOG.1")
    if command -v jq >/dev/null 2>&1; then
        # -R + fromjson?: a torn line from a killed server is skipped, as in the
        # python3 fallback, instead of failing the whole scan.
        jq -R -e --arg since "$since" '
            fromjson? | select(
                .event == "tool_call"
                and (
                    .tool == "guided_assessment"
                    or .tool == "suggest_for_ctf"
                    or .tool == "suggest_for_bounty"
                )
                and ((.ts // "") > $since)
            )
        ' "${logs[@]}" >/dev/null 2>&1
        return
    fi

    python3 - "$since" "${logs[@]}" <<'PY' >/dev/null 2>&1
import json
import sys

allowed = {"guided_assessment", "suggest_for_ctf", "suggest_for_bounty"}
since, *paths = sys.argv[1:]
for path in paths:
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
        continue
raise SystemExit(1)
PY
}

# _hook_field <json> <.dotted.path> — print a string field of the hook JSON.
# jq first (fast, and the toolkit installs it); python3 covers a bare macOS.
_hook_field() {
    if command -v jq >/dev/null 2>&1; then
        jq -r "$2 // empty" <<< "$1" 2>/dev/null
    else
        python3 -c 'import json, sys
try:
    v = json.loads(sys.stdin.read())
    for k in sys.argv[1].lstrip(".").split("."):
        v = v.get(k, "") if isinstance(v, dict) else ""
    print(v if isinstance(v, str) else "")
except Exception:
    pass' "$2" <<< "$1" 2>/dev/null
    fi
}

# _session_id <json> — the client's session id when it sends one, restricted to a
# safe filename component (it names a per-session marker file).
_session_id() {
    local sid
    sid=$(_hook_field "$1" .session_id)
    [[ "$sid" =~ ^[A-Za-z0-9._-]{1,128}$ ]] && printf '%s\n' "$sid"
}

case "$MODE" in
session-start)
    input=""
    [[ -t 0 ]] || input=$(cat)
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    now=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
    # The shared marker serves clients that send no session id. A per-session
    # marker keeps a second concurrent session from resetting this one's window.
    sid=$(_session_id "$input")
    source=$(_hook_field "$input" .source)
    # Compaction and resume continue a session; its clearance must survive them.
    continuing=false
    [[ -n "$sid" && -f "$STATE_DIR/guard-session.$sid" && ( "$source" == compact || "$source" == resume ) ]] \
        && continuing=true
    [[ "$continuing" == true ]] || printf '%s\n' "$now" > "$STATE_DIR/guard-session" 2>/dev/null || true
    if [[ -n "$sid" && "$continuing" != true ]]; then
        printf '%s\n' "$now" > "$STATE_DIR/guard-session.$sid" 2>/dev/null || true
        find "$STATE_DIR" -maxdepth 1 -name 'guard-session.*' -mtime +7 -delete 2>/dev/null || true
    fi
    emit '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"cybersec-toolkit contract — touching a TARGET (host, URL, sample, capture, a binary or file you did not write) starts with the cybersec-tools MCP server: guided_assessment, or suggest_for_ctf / suggest_for_bounty when the workflow is known. Then run_tool > run_pipeline > run_script. Editing THIS repository is ordinary work — use normal tools. Substantive security workflows end with a writeup under writeups/."}}'
    exit 0
    ;;
pre-bash)
    [[ "${CYBERSEC_AGENT_GUARD:-1}" == "0" ]] && allow
    [[ -f "$AUDIT_LOG" ]] || allow              # no MCP server configured; nothing to enforce

    if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
        allow                                   # no JSON reader; never block blindly
    fi
    input=""
    [[ -t 0 ]] || input=$(cat)
    cmd=$(_hook_field "$input" .tool_input.command)
    [[ -n "$cmd" ]] || allow

    # Retain the static baseline if Python or the repository metadata is unavailable.
    if command -v python3 >/dev/null 2>&1; then
        while IFS= read -r name; do
            [[ -n "$name" ]] && GOVERNED+=("$name")
        done < <(_registry_commands 2>/dev/null)
    fi

    # Fast path: no governed name anywhere in the command.
    hit=""
    # A de-quoted copy catches names split by quotes or escapes (nm""ap).
    plain=${cmd//[\"\'\\]/}
    for g in "${GOVERNED[@]}"; do
        [[ "$cmd" == *"$g"* || "$plain" == *"$g"* ]] && { hit="$g"; break; }
    done
    [[ -n "$hit" ]] || allow

    hit=""
    while IFS= read -r word; do
        for g in "${GOVERNED[@]}"; do
            [[ "$word" == "$g" ]] && { hit="$word"; break 2; }
        done
    done < <(_command_words "$cmd")
    [[ -n "$hit" ]] || allow

    # Has the server been called since this session started?
    marker="$STATE_DIR/guard-session"
    sid=$(_session_id "$input")
    [[ -n "$sid" && -f "$marker.$sid" ]] && marker="$marker.$sid"
    since=$(cat "$marker" 2>/dev/null) || since=""
    [[ -n "$since" ]] || allow                  # no marker (first session after install)
    floor=$(_clearance_floor)
    [[ -n "$floor" && "$floor" > "$since" ]] && since="$floor"
    _advised_since "$since" && allow

    deny "$hit"
    ;;
*)
    echo "usage: $0 {session-start|pre-bash}   (hook JSON on stdin)" >&2
    exit 2
    ;;
esac
