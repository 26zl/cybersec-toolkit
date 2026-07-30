#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# CyberSec Tools — Config Backup/Restore Script
# Backs up and restores tool configurations with ChaCha20 encryption (PBKDF2 key derivation).
# Supports scheduling via cron. Linux and Termux only.

set -uo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Remove registered plaintext files on interruption.
trap '_global_cleanup; exit 130' INT TERM

# Resolve the invoking user's home when running under sudo.
if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER:-}" != "root" ]]; then
    HOME_DIR="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)"
    [[ -z "$HOME_DIR" ]] && HOME_DIR="$(awk -F: -v u="$SUDO_USER" '$1==u{print $6; exit}' /etc/passwd 2>/dev/null)"
else
    HOME_DIR="$HOME"
fi
# Validate: must be a non-empty absolute path or every backup/restore path is bogus.
if [[ -z "$HOME_DIR" || "$HOME_DIR" != /* ]]; then
    log_error "Could not resolve a valid home directory (got: '${HOME_DIR}')"
    exit 1
fi

# Configuration
PBKDF2_ITERATIONS=600000
BACKUP_DIR="$HOME_DIR/cybersec_tools_backup"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup_$TIMESTAMP"

_chown_backup_dir() {
    if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER:-}" != "root" ]]; then
        if [[ -L "$BACKUP_DIR" || ! -d "$BACKUP_DIR" ]]; then
            log_error "Refusing to change ownership of unsafe backup path: $BACKUP_DIR"
            return 1
        fi
        if ! chown -R -- "$SUDO_USER" "$BACKUP_DIR" 2>/dev/null; then
            log_error "Failed to return backup ownership to $SUDO_USER"
            return 1
        fi
    fi
}

# Helpers
ensure_dir() {
    [[ -d "$1" ]] || mkdir -p -- "$1"
}

_BACKUP_STORAGE_READY=false
_init_backup_storage() {
    [[ "$_BACKUP_STORAGE_READY" == "true" ]] && return 0
    if [[ -L "$BACKUP_DIR" || ( -e "$BACKUP_DIR" && ! -d "$BACKUP_DIR" ) ]]; then
        log_error "Refusing unsafe backup path: $BACKUP_DIR"
        return 1
    fi
    if [[ ! -e "$BACKUP_DIR" ]] && ! mkdir -m 700 -- "$BACKUP_DIR"; then
        log_error "Failed to create private backup directory: $BACKUP_DIR"
        return 1
    fi
    if [[ -L "$BACKUP_DIR" || ! -d "$BACKUP_DIR" ]] || ! chmod 700 "$BACKUP_DIR"; then
        log_error "Failed to initialize private backup directory: $BACKUP_DIR"
        return 1
    fi
    _chown_backup_dir || return 1
    _init_log_file "$BACKUP_DIR/backup.log"
    _BACKUP_STORAGE_READY=true
}

_prompt_passphrase() {
    # Non-interactive mode: use BACKUP_PASSPHRASE env var (for cron/scripted backups)
    if [[ -n "${BACKUP_PASSPHRASE:-}" ]]; then
        if [[ ${#BACKUP_PASSPHRASE} -lt 8 ]]; then
            log_error "BACKUP_PASSPHRASE must be at least 8 characters"
            return 1
        fi
        _PASSPHRASE="$BACKUP_PASSPHRASE"
        return 0
    fi

    # Interactive mode requires a terminal
    if [[ ! -t 0 ]]; then
        log_error "No terminal available for passphrase input"
        log_error "Set BACKUP_PASSPHRASE env var for non-interactive/cron use"
        return 1
    fi

    local passphrase passphrase_confirm
    read -rsp "Enter encryption passphrase: " passphrase
    echo ""
    read -rsp "Confirm passphrase: " passphrase_confirm
    echo ""

    if [[ "$passphrase" != "$passphrase_confirm" ]]; then
        log_error "Passphrases do not match — aborting encryption"
        return 1
    fi
    if [[ ${#passphrase} -lt 8 ]]; then
        log_error "Passphrase must be at least 8 characters"
        return 1
    fi

    # Return passphrase via global (subshell would lose it)
    _PASSPHRASE="$passphrase"
}

# _read_passphrase_to_file — read a decryption passphrase interactively and
# write it to a secure temp file.  Sets _PASS_FILE to the temp file path.
# Caller must rm -f "$_PASS_FILE" when done.
_read_passphrase_to_file() {
    local passphrase
    if [[ ! -t 0 ]]; then
        log_error "No terminal available for decryption passphrase input"
        return 1
    fi
    read -rsp "Enter decryption passphrase: " passphrase || return 1
    echo ""
    if ! _PASS_FILE=$(mktemp) || ! chmod 600 "$_PASS_FILE"; then
        log_error "Failed to create secure passphrase file"
        [[ -n "${_PASS_FILE:-}" ]] && rm -f -- "$_PASS_FILE"
        unset passphrase
        return 1
    fi
    _register_cleanup "$_PASS_FILE"
    printf '%s' "$passphrase" > "$_PASS_FILE"
    unset passphrase
}

encrypt_archive() {
    local archive_path="$1"

    _prompt_passphrase || return 1

    local pass_file=""
    if ! pass_file=$(mktemp) || ! chmod 600 "$pass_file"; then
        [[ -n "$pass_file" ]] && rm -f -- "$pass_file"
        unset _PASSPHRASE
        log_error "Failed to create secure passphrase file"
        return 1
    fi
    _register_cleanup "$pass_file"
    printf '%s' "$_PASSPHRASE" > "$pass_file"
    unset _PASSPHRASE

    # Encrypt-then-MAC. ChaCha20 is an unauthenticated stream cipher, so the
    # ciphertext is malleable and corruption/tampering would silently decrypt
    # into garbage. We authenticate the ciphertext with HMAC-SHA256 (key
    # derived from the passphrase via salted PBKDF2) and store the tag alongside;
    # decryption verifies it first and fails closed on any mismatch.
    #
    # A per-backup random salt makes the .hmac sidecar useless as a cheap
    # offline brute-force oracle: without an expensive salted KDF the tag would
    # be ~PBKDF2_ITERATIONS× cheaper to attack than the ciphertext.
    local mac_salt
    mac_salt=$(openssl rand -hex 16)
    if [[ -z "$mac_salt" ]]; then
        rm -f "$pass_file"
        log_error "Failed to generate MAC salt"
        return 1
    fi
    local mac_tag=""
    if openssl enc -chacha20 -salt -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$archive_path" -out "${archive_path}.enc" -pass file:"$pass_file" 2>/dev/null; then
        mac_tag=$(_backup_hmac_tag "$pass_file" "${archive_path}.enc" "$mac_salt" v2)
    fi

    # Sidecar format (v2): two prefixed lines — "salt:<hexsalt>" then "mac:<hexmac>".
    # The legacy v1 format was a single bare hex line (no prefix).
    if [[ -n "$mac_tag" ]] \
        && { printf 'salt:%s\n' "$mac_salt"; printf 'mac:%s\n' "$mac_tag"; } > "${archive_path}.enc.hmac" \
        && [[ -s "${archive_path}.enc.hmac" ]]; then
        rm -f "$pass_file" "$archive_path"
        chmod 600 "${archive_path}.enc" "${archive_path}.enc.hmac" 2>/dev/null || true
        log_success "Archive encrypted: ${archive_path}.enc (+ HMAC integrity tag)"
        log_info "Remember your passphrase (it is NOT stored)"
        return 0
    else
        rm -f "$pass_file" "${archive_path}.enc" "${archive_path}.enc.hmac"
        log_error "Encryption failed"
        return 1
    fi
}

# Compute the public HMAC tag without exposing passphrase-derived material in argv.
_backup_hmac_tag() {
    local pass_file="$1"
    local encrypted_path="$2"
    local hexsalt="$3"
    local format="$4"

    python3 - "$pass_file" "$encrypted_path" "$hexsalt" "$format" \
        "$PBKDF2_ITERATIONS" 2>/dev/null <<'PY'
import hashlib
import hmac
import sys

pass_file, encrypted_path, hexsalt, tag_format, iterations = sys.argv[1:]
with open(pass_file, "rb") as handle:
    password = handle.read()

if tag_format == "v2":
    key = hashlib.pbkdf2_hmac(
        "sha256", password, bytes.fromhex(hexsalt), int(iterations), dklen=32
    )
elif tag_format == "v1":
    key = hashlib.sha256(b"cybersec-backup-hmac:" + password).digest()
else:
    raise ValueError("unsupported backup tag format")

digest = hmac.new(key, digestmod=hashlib.sha256)
with open(encrypted_path, "rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

# _ct_equal — constant-time hex-string equality. Compares SHA256(nonce||a) vs
# SHA256(nonce||b) with a fresh random nonce so wall-clock comparison time does
# not leak how many leading bytes matched (avoids timing oracles on the tag).
# Returns 0 if equal, 1 otherwise.
_ct_equal() {
    local a="$1" b="$2"
    local nonce ha hb
    nonce=$(openssl rand -hex 32)
    [[ -n "$nonce" ]] || return 1
    ha=$(printf '%s' "$nonce$a" | openssl dgst -sha256 -r 2>/dev/null | awk '{print $1}')
    hb=$(printf '%s' "$nonce$b" | openssl dgst -sha256 -r 2>/dev/null | awk '{print $1}')
    [[ -n "$ha" && "$ha" == "$hb" ]]
}

decrypt_archive() {
    local encrypted_path="$1"
    local output_path="${2:-${encrypted_path%.enc}}"

    [[ ! -e "$output_path" ]] || {
        log_error "Refusing to overwrite decrypted output: $output_path"
        return 1
    }
    _read_passphrase_to_file || return 1

    # Verify the HMAC integrity tag before decrypting (fail closed on tamper).
    # Backups written before integrity tags have no .hmac — warn and proceed so
    # old archives still restore, but flag that integrity can't be guaranteed.
    local hmac_file="${encrypted_path}.hmac"
    if [[ -f "$hmac_file" ]]; then
        local expected actual mac_salt mac_format
        # Detect sidecar format. v2 = prefixed lines ("salt:<hex>" / "mac:<hex>")
        # using salted PBKDF2; v1 (legacy) = single bare hex line, weak unsalted
        # derivation. Parse v2 first; fall back to v1 for old backups.
        mac_salt=$(awk -F: '/^salt:/{print $2; exit}' "$hmac_file" 2>/dev/null | tr -d '[:space:]')
        expected=$(awk -F: '/^mac:/{print $2; exit}' "$hmac_file" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "$mac_salt" && -n "$expected" ]]; then
            mac_format=v2
        else
            # v1 legacy: single bare hex line, weak unsalted derivation
            log_warn "Legacy (unsalted) integrity tag detected — weak integrity, re-create this backup to upgrade"
            expected=$(tr -d '[:space:]' < "$hmac_file")
            mac_salt=""
            mac_format=v1
        fi
        actual=$(_backup_hmac_tag "$_PASS_FILE" "$encrypted_path" "$mac_salt" "$mac_format")
        if [[ -z "$actual" ]] || ! _ct_equal "$expected" "$actual"; then
            rm -f "$_PASS_FILE"
            log_error "Integrity check FAILED — archive is corrupt, tampered, or passphrase is wrong. Refusing to decrypt."
            return 1
        fi
    else
        log_warn "No HMAC tag found ($hmac_file) — legacy backup, integrity cannot be verified"
    fi

    if openssl enc -chacha20 -d -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$encrypted_path" -out "$output_path" -pass file:"$_PASS_FILE" 2>/dev/null; then
        rm -f "$_PASS_FILE"
        log_success "Archive decrypted: $output_path"
        return 0
    else
        rm -f "$_PASS_FILE" "$output_path"
        log_error "Decryption failed (wrong passphrase?)"
        return 1
    fi
}

# Legacy: decrypt individual .enc files from old-format backups
decrypt_files_legacy() {
    local source_dir="$1"
    local target_dir="$2"

    _read_passphrase_to_file || return 1

    local failed=0
    while IFS= read -r -d '' file; do
        local relative_path="${file#"$source_dir"/}"
        local decrypted_path="$target_dir/${relative_path%.enc}"
        ensure_dir "$(dirname "$decrypted_path")"
        if openssl enc -aes-256-cbc -d -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
            -in "$file" -out "$decrypted_path" -pass file:"$_PASS_FILE" 2>/dev/null; then
            log_success "Decrypted: $relative_path"
        else
            log_warn "Failed to decrypt: $relative_path"
            failed=$((failed + 1))
        fi
    done < <(find "$source_dir" -type f -name "*.enc" -print0)

    rm -f "$_PASS_FILE"
    [[ "$failed" -eq 0 ]]
}

# Backup config dirs (silently skip missing ones)
backup_configs() {
    local dest="$1"
    local failed=0

    # Category → paths mapping (one cp per path to avoid quoting issues)
    # Only existing paths are copied — missing ones are silently skipped.
    local -a _backup_map=(
        # Network
        "network|$HOME_DIR/.nmap"
        "network|$HOME_DIR/.wireshark"
        # Web
        "web|$HOME_DIR/.ZAP"
        "web|$HOME_DIR/.sqlmap"
        "web|$HOME_DIR/.config/nuclei"
        "web|$HOME_DIR/.wpscan"
        "web|$HOME_DIR/.mitmproxy"
        # Recon / OSINT
        "osint|$GITHUB_TOOL_DIR/recon-ng"
        "osint|$HOME_DIR/.config/subfinder"
        "osint|$HOME_DIR/.config/amass"
        # Wireless
        "wireless|$HOME_DIR/.aircrack-ng"
        "wireless|$HOME_DIR/.kismet"
        # Cracking
        "cracking|$HOME_DIR/.john"
        "cracking|$HOME_DIR/.hashcat"
        # Exploitation
        "exploitation|$HOME_DIR/.msf4"
        "exploitation|$GITHUB_TOOL_DIR/exploitdb"
        # Enterprise / AD
        "enterprise|$HOME_DIR/.netexec"
        # Forensics
        "forensics|$HOME_DIR/.autopsy"
        "forensics|$HOME_DIR/.volatility3"
        # Cloud
        "cloud|$HOME_DIR/.steampipe"
        "cloud|$HOME_DIR/.pacu"
        # Reversing
        "reversing|$HOME_DIR/.radare2"
        # Blockchain
        "blockchain|$HOME_DIR/.foundry"
        # LLM
        "llm|$HOME_DIR/.promptfoo"
    )

    for _entry in "${_backup_map[@]}"; do
        local category="${_entry%%|*}"
        local src="${_entry#*|}"
        if [[ -e "$src" ]]; then
            if ! ensure_dir "$dest/$category" \
                || ! cp -r -- "$src" "$dest/$category/" 2>/dev/null; then
                log_warn "Failed to back up: $src"
                failed=$((failed + 1))
            fi
        fi
    done
    [[ "$failed" -eq 0 ]]
}

# Restore one tree atomically per target: copy into a staging sibling first, then
# swap it in, so a failed or short copy never leaves a half-overwritten
# destination. The old tree is kept until the swap succeeds and put back if it
# fails. The symlink recheck shrinks — but cannot fully close — a same-privilege
# TOCTOU race; the staging + swap files live beside the target on the same
# filesystem so the moves are atomic renames.
_restore_tree() {
    local source="$1"
    local parent="$2"
    local label="$3"
    local base="${source##*/}"
    local target="$parent/$base"

    ensure_dir "$parent" || return 1
    if [[ -L "$parent" || -L "$target" ]]; then
        log_warn "Refusing to restore through a symlinked destination: $target"
        return 1
    fi

    local staged="$parent/.cybersec-restore.$$.new.$base"
    local backup="$parent/.cybersec-restore.$$.bak.$base"
    rm -rf -- "$staged" "$backup" 2>/dev/null || true

    if ! cp -r -- "$source" "$staged" 2>/dev/null; then
        log_warn "Failed to restore: $label"
        rm -rf -- "$staged" 2>/dev/null || true
        return 1
    fi

    local had_target=false
    if [[ -e "$target" ]]; then
        had_target=true
        if ! mv -- "$target" "$backup" 2>/dev/null; then
            log_warn "Failed to stage existing $label aside — leaving it untouched"
            rm -rf -- "$staged" 2>/dev/null || true
            return 1
        fi
    fi
    if ! mv -- "$staged" "$target" 2>/dev/null; then
        log_warn "Failed to move restored $label into place — rolling back"
        [[ "$had_target" == true ]] && mv -- "$backup" "$target" 2>/dev/null || true
        rm -rf -- "$staged" 2>/dev/null || true
        return 1
    fi
    [[ "$had_target" == true ]] && rm -rf -- "$backup" 2>/dev/null || true

    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]] \
        && ! chown -R -- "$SUDO_USER" "$target" 2>/dev/null; then
        log_warn "Restored $label, but failed to return its ownership to $SUDO_USER"
        return 1
    fi
    return 0
}

# Restore config directories to their fixed destinations.
restore_configs() {
    local src="$1"
    local failed=0

    # Home dir configs — restore to $HOME_DIR/
    local -a _home_dirs=(
        .nmap .wireshark .ZAP .sqlmap .aircrack-ng .kismet
        .john .hashcat .msf4 .autopsy .wpscan .mitmproxy
        .netexec .volatility3 .steampipe .pacu .radare2
        .foundry .promptfoo
    )
    for dir in "${_home_dirs[@]}"; do
        local found
        found=$(find "$src" -maxdepth 2 -name "$dir" -type d 2>/dev/null | head -1)
        if [[ -n "$found" ]] && ! _restore_tree "$found" "$HOME_DIR" "$dir"; then
            failed=$((failed + 1))
        fi
    done

    # ~/.config/ subdirs — restore to $HOME_DIR/.config/
    local -a _xdg_dirs=(nuclei subfinder amass)
    for dir in "${_xdg_dirs[@]}"; do
        local found
        found=$(find "$src" -maxdepth 2 -name "$dir" -type d 2>/dev/null | head -1)
        if [[ -n "$found" ]] \
            && ! _restore_tree "$found" "$HOME_DIR/.config" ".config/$dir"; then
            failed=$((failed + 1))
        fi
    done

    # /opt tool dirs — restore to $GITHUB_TOOL_DIR/
    for dir in exploitdb recon-ng; do
        local found
        found=$(find "$src" -maxdepth 2 -name "$dir" -type d 2>/dev/null | head -1)
        if [[ -n "$found" ]] && ! _restore_tree "$found" "$GITHUB_TOOL_DIR" "$dir"; then
            failed=$((failed + 1))
        fi
    done
    [[ "$failed" -eq 0 ]]
}

# Commands
cmd_backup() {
    _init_backup_storage || exit 1
    log_info "Creating backup..."
    if [[ -e "$BACKUP_PATH" || -e "$BACKUP_PATH.tar.gz" || -e "$BACKUP_PATH.tar.gz.enc" ]]; then
        log_error "Backup destination already exists for timestamp $TIMESTAMP"
        exit 1
    fi
    if ! ensure_dir "$BACKUP_PATH"; then
        log_error "Failed to create backup staging directory"
        exit 1
    fi
    _register_cleanup "$BACKUP_PATH"
    _register_cleanup "$BACKUP_PATH.tar.gz"

    if ! backup_configs "$BACKUP_PATH"; then
        log_error "Backup is incomplete; no archive was created"
        rm -rf "$BACKUP_PATH"
        exit 1
    fi

    log_info "Creating archive..."
    if ! tar -czf "$BACKUP_PATH.tar.gz" -C "$BACKUP_DIR" "backup_$TIMESTAMP"; then
        log_error "Failed to create archive"
        rm -rf "$BACKUP_PATH"
        exit 1
    fi
    chmod 600 "$BACKUP_PATH.tar.gz" 2>/dev/null || true
    rm -rf "$BACKUP_PATH"

    log_info "Encrypting archive..."
    if ! encrypt_archive "$BACKUP_PATH.tar.gz"; then
        log_error "Encryption failed — aborting (no backup created)"
        rm -f "$BACKUP_PATH.tar.gz"
        exit 1
    fi

    _chown_backup_dir || exit 1

    log_success "Backup created: $BACKUP_PATH.tar.gz.enc"
}

cmd_restore() {
    local backup_file="$1"

    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi
    if [[ "$backup_file" != *.tar.gz.enc && "$backup_file" != *.tar.gz ]]; then
        log_error "Unrecognized backup format: $backup_file"
        log_info "Expected .tar.gz.enc (encrypted) or .tar.gz (legacy)"
        exit 1
    fi
    # restore_configs locates config trees in the archive with find; without it the
    # restore would silently place nothing and still report success. Fail closed.
    command -v find >/dev/null 2>&1 || {
        log_error "find (findutils) is required for restore but was not found"
        exit 1
    }

    _init_backup_storage || exit 1

    local tar_file="$backup_file"
    local restore_tmpdir
    if ! restore_tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/cybersec-restore.XXXXXX"); then
        log_error "Failed to create restore staging directory"
        exit 1
    fi
    chmod 700 "$restore_tmpdir"
    _register_cleanup "$restore_tmpdir"
    local extract_dir="$restore_tmpdir/extracted"
    ensure_dir "$extract_dir" || {
        log_error "Failed to create restore extraction directory"
        exit 1
    }

    # New format: .tar.gz.enc — decrypt first
    if [[ "$backup_file" == *.tar.gz.enc ]]; then
        log_info "Encrypted backup detected — decrypting..."
        tar_file="$restore_tmpdir/archive.tar.gz"
        if ! decrypt_archive "$backup_file" "$tar_file"; then
            exit 1
        fi
    fi

    local member_list="$restore_tmpdir/members"
    if ! tar -tzf "$tar_file" > "$member_list"; then
        log_error "Could not read backup archive"
        exit 1
    fi

    local backup_name=""
    local member top
    while IFS= read -r member; do
        while [[ "$member" == ./* ]]; do member="${member#./}"; done
        [[ -n "$member" ]] || continue
        if [[ "$member" == /* || "/$member/" == */../* ]]; then
            log_error "Archive contains an unsafe path — aborting"
            exit 1
        fi
        top="${member%%/*}"
        if [[ -z "$top" || ( -n "$backup_name" && "$top" != "$backup_name" ) ]]; then
            log_error "Archive must contain exactly one top-level directory"
            exit 1
        fi
        backup_name="$top"
    done < "$member_list"
    if [[ -z "$backup_name" ]]; then
        log_error "Could not determine backup directory name from archive"
        exit 1
    fi

    # Backups contain only regular files and directories.
    local verbose_list="$restore_tmpdir/members.verbose"
    if ! tar -tvzf "$tar_file" > "$verbose_list" 2>/dev/null; then
        log_error "Could not inspect backup archive"
        exit 1
    fi
    if grep -qEv '^[-d]' "$verbose_list"; then
        log_error "Archive contains links or special members — refusing to restore (untrusted or malformed backup)"
        exit 1
    fi

    # Archive-bomb guard: bound member count and total uncompressed size, and
    # require the payload to fit the staging filesystem, before extracting. The
    # verbose listing already carries per-member sizes (field 3), so this is free.
    local _member_count _total_bytes
    _member_count=$(wc -l < "$verbose_list")
    _total_bytes=$(awk '{ s += $3 } END { printf "%.0f", s + 0 }' "$verbose_list")
    local _max_members=200000
    local _max_bytes=$((10 * 1024 * 1024 * 1024))   # 10 GiB uncompressed
    if [[ "$_member_count" -gt "$_max_members" ]]; then
        log_error "Archive has $_member_count members (limit $_max_members) — refusing to restore"
        exit 1
    fi
    if [[ "$_total_bytes" -gt "$_max_bytes" ]]; then
        log_error "Archive expands to $_total_bytes bytes (limit $_max_bytes) — refusing to restore"
        exit 1
    fi
    local _avail_kb
    _avail_kb=$(df -Pk "$extract_dir" 2>/dev/null | awk 'NR==2 { print $4 }')
    if [[ "$_avail_kb" =~ ^[0-9]+$ ]]; then
        local _need_kb=$(( (_total_bytes / 1024) + 65536 ))   # +64 MiB margin
        if [[ "$_need_kb" -gt "$_avail_kb" ]]; then
            log_error "Not enough free space to extract: need ~${_need_kb} KB, have ${_avail_kb} KB"
            exit 1
        fi
    fi

    log_info "Extracting backup..."
    if ! tar -xzf "$tar_file" -C "$extract_dir"; then
        log_error "Failed to extract backup archive"
        exit 1
    fi

    local restore_root="$extract_dir/$backup_name"
    if [[ ! -d "$restore_root" ]]; then
        log_error "Archive root is not a directory: $backup_name"
        exit 1
    fi

    # Legacy format: check for individually encrypted files inside the archive.
    # Scan from the backup root, not a fixed encrypted/ subdir — old backups may
    # store the *.enc files elsewhere, and decrypt_files_legacy must search the
    # same directory that actually contains them or it silently decrypts nothing.
    if find "$restore_root" -name "*.enc" -print -quit 2>/dev/null | grep -q .; then
        log_info "Legacy encrypted files found — decrypting..."
        decrypt_files_legacy "$restore_root" "$restore_root" || {
            log_error "One or more legacy files could not be decrypted"
            exit 1
        }
    fi

    log_info "Restoring configurations..."
    if ! restore_configs "$restore_root"; then
        log_error "Restore was incomplete; review warnings above"
        exit 1
    fi

    rm -rf "$restore_tmpdir"
    log_success "Backup restored successfully"
}

cmd_list() {
    log_info "Available backups:"
    local found=false
    for f in "$BACKUP_DIR"/*.tar.gz.enc "$BACKUP_DIR"/*.tar.gz; do
        [[ -f "$f" ]] || continue
        echo "  $f"
        found=true
    done
    [[ "$found" == "false" ]] && echo "  No backups found"
}

cmd_delete() {
    local target="${1:-}"

    if [[ "$target" == "--all" ]]; then
        local count=0
        for f in "$BACKUP_DIR"/*.tar.gz.enc "$BACKUP_DIR"/*.tar.gz; do
            [[ -f "$f" ]] || continue
            count=$((count + 1))
        done
        if [[ "$count" -eq 0 ]]; then
            log_info "No backups to delete"
            return 0
        fi
        read -rp "Delete all $count backup(s) in $BACKUP_DIR? (y/N) " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log_warn "Cancelled"
            return 0
        fi
        for f in "$BACKUP_DIR"/*.tar.gz.enc "$BACKUP_DIR"/*.tar.gz; do
            [[ -f "$f" ]] || continue
            rm -f -- "$f" "${f}.hmac"
            log_success "Deleted: $f"
        done
        # Remove log and empty dir if nothing left
        rm -f "$BACKUP_DIR/backup.log" 2>/dev/null
        rmdir "$BACKUP_DIR" 2>/dev/null || true
    else
        if [[ ! -f "$target" ]]; then
            log_error "File not found: $target"
            return 1
        fi
        # Restrict delete to files under BACKUP_DIR (prevent path traversal)
        local _canon_target _canon_backup
        if command -v realpath &>/dev/null; then
            _canon_target=$(realpath "$target" 2>/dev/null) || true
            _canon_backup=$(realpath "$BACKUP_DIR" 2>/dev/null) || true
            if [[ -z "$_canon_target" || -z "$_canon_backup" || "$_canon_target" != "$_canon_backup"/* ]]; then
                log_error "Can only delete files under $BACKUP_DIR (got: $target)"
                return 1
            fi
        else
            if [[ "$target" != "$BACKUP_DIR"/* ]] || [[ "$target" == *"/../"* ]] || [[ "$target" == *"/.." ]]; then
                log_error "Can only delete files under $BACKUP_DIR (got: $target)"
                return 1
            fi
        fi
        read -rp "Delete $target? (y/N) " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log_warn "Cancelled"
            return 0
        fi
        rm -f -- "$target" "${target}.hmac"
        log_success "Deleted: $target"
    fi
}

cmd_schedule() {
    local frequency="$1"
    local time="$2"

    # Validate HH:MM format
    if [[ ! "$time" =~ ^[0-9]{1,2}:[0-9]{2}$ ]]; then
        log_error "Invalid time format. Use HH:MM (e.g., 02:00)"
        exit 1
    fi

    # Parse HH:MM
    local hour minute
    hour=$(echo "$time" | cut -d: -f1)
    minute=$(echo "$time" | cut -d: -f2)

    if [[ "$hour" -gt 23 || "$minute" -gt 59 ]]; then
        log_error "Invalid time: hour must be 0-23, minute must be 0-59"
        exit 1
    fi

    local cron_schedule
    case "$frequency" in
        daily)   cron_schedule="$minute $hour * * *" ;;
        weekly)  cron_schedule="$minute $hour * * 0" ;;
        monthly) cron_schedule="$minute $hour 1 * *" ;;
        *)
            log_error "Invalid frequency. Use: daily, weekly, monthly"
            exit 1
            ;;
    esac

    if [[ -z "${BACKUP_PASSPHRASE:-}" ]]; then
        log_error "BACKUP_PASSPHRASE env var must be set for scheduled backups"
        log_info "Set it in the environment without placing the value in shell history"
        exit 1
    fi
    if [[ ${#BACKUP_PASSPHRASE} -lt 8 ]]; then
        log_error "BACKUP_PASSPHRASE must be at least 8 characters"
        exit 1
    fi

    # /etc writes and system crontab changes both need root. Fail fast instead
    # of letting the user discover a broken half-configured schedule later.
    if [[ $EUID -ne 0 ]]; then
        log_error "Scheduling requires root and a preserved BACKUP_PASSPHRASE environment"
        exit 1
    fi
    if ! command_exists crontab; then
        log_error "crontab is not installed"
        exit 1
    fi

    # Write passphrase to a root-only env file instead of embedding in crontab
    # (avoids single-quote injection and keeps secrets out of crontab -l)
    local env_file="/etc/cybersec-backup.env"
    # Escape single quotes in passphrase to prevent shell injection when sourced
    local _escaped="${BACKUP_PASSPHRASE//\'/\'\\\'\'}"

    # Atomic install: write to temp file in same dir, chmod, then mv. If any
    # step fails we clean up and abort instead of logging a false success.
    local tmp_env
    if ! tmp_env="$(mktemp "${env_file}.XXXXXX")"; then
        log_error "Failed to create temp file in $(dirname "$env_file") (is it writable as root?)"
        exit 1
    fi

    if ! printf "BACKUP_PASSPHRASE='%s'\n" "$_escaped" > "$tmp_env"; then
        log_error "Failed to write passphrase to $tmp_env"
        rm -f "$tmp_env"
        exit 1
    fi

    if ! chmod 600 "$tmp_env"; then
        log_error "Failed to set mode 600 on $tmp_env"
        rm -f "$tmp_env"
        exit 1
    fi

    if ! mv "$tmp_env" "$env_file"; then
        log_error "Failed to install $env_file"
        rm -f "$tmp_env"
        exit 1
    fi

    local _home_escaped; _home_escaped="$(_escape_single_quoted "$HOME_DIR")"
    local _script_escaped; _script_escaped="$(_escape_single_quoted "$SCRIPT_DIR/scripts/backup.sh")"
    local _sudo_export=""
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
        local _sudo_user_escaped; _sudo_user_escaped="$(_escape_single_quoted "$SUDO_USER")"
        _sudo_export=" SUDO_USER='$_sudo_user_escaped'"
    fi
    local cron_cmd="export HOME='$_home_escaped'${_sudo_export} && . '$env_file' && '$_script_escaped' backup"
    local new_crontab
    new_crontab="$(crontab -l 2>/dev/null | grep -vF "$SCRIPT_DIR/scripts/backup.sh"; echo "$cron_schedule $cron_cmd")"

    if ! printf '%s\n' "$new_crontab" | crontab -; then
        log_error "Failed to install crontab entry (crontab - returned non-zero)"
        log_info "Passphrase file $env_file remains on disk — remove manually if you want to abort"
        exit 1
    fi

    log_success "Backup scheduled: $frequency at $time"
    log_info "Passphrase stored in $env_file (mode 600)"
}

cmd_unschedule() {
    local env_file="/etc/cybersec-backup.env"
    if [[ $EUID -ne 0 ]]; then
        log_error "Unscheduling requires root"
        return 1
    fi
    if ! command_exists crontab; then
        log_error "crontab is not installed"
        return 1
    fi

    local current=""
    local filtered=""
    if current=$(crontab -l 2>/dev/null); then
        filtered=$(printf '%s\n' "$current" \
            | grep -vF "$SCRIPT_DIR/scripts/backup.sh" || true)
        if [[ "$filtered" != "$current" ]] \
            && ! printf '%s\n' "$filtered" | crontab -; then
            log_error "Failed to remove backup entry from crontab"
            return 1
        fi
    fi

    if [[ ( -e "$env_file" || -L "$env_file" ) ]] && ! rm -f -- "$env_file"; then
        log_error "Schedule removed, but failed to delete passphrase file: $env_file"
        return 1
    fi
    log_success "Backup schedule removed"
}

show_usage() {
    cat << 'EOF'
CyberSec Tools — Config Backup/Restore Script

Usage: ./scripts/backup.sh <command> [args]

Commands:
  backup                           Create encrypted backup
  restore <backup_file>            Restore from backup (.tar.gz.enc or .tar.gz)
  list                             List available backups
  delete <backup_file>             Delete a specific backup
  delete --all                     Delete all backups
  schedule <daily|weekly|monthly> <HH:MM>
                                   Schedule automatic backups via cron
  unschedule                       Remove scheduled backup

Environment:
  BACKUP_PASSPHRASE                Passphrase for non-interactive/cron encryption
                                   (must be at least 8 characters)

Options:
  -h, --help                       Show this help and exit
EOF
}

case "${1:-}" in
    backup)      cmd_backup ;;
    restore)
        [[ -z "${2:-}" ]] && { log_error "Specify backup file"; show_usage; exit 1; }
        cmd_restore "$2"
        ;;
    list)        cmd_list ;;
    delete)
        [[ -z "${2:-}" ]] && { log_error "Specify backup file or --all"; show_usage; exit 1; }
        cmd_delete "$2"
        ;;
    schedule)
        [[ -z "${2:-}" || -z "${3:-}" ]] && { log_error "Specify frequency and time"; show_usage; exit 1; }
        cmd_schedule "$2" "$3"
        ;;
    unschedule)  cmd_unschedule ;;
    --help|-h)   show_usage ;;
    "")          cmd_backup ;;
    *)           log_error "Unknown command: ${1:-}"; show_usage; exit 1 ;;
esac
