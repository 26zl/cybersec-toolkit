#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# CyberSec Tools — Config Backup/Restore Script
# Backs up and restores tool configurations with ChaCha20 encryption (PBKDF2 key derivation).
# Supports scheduling via cron. Linux and Termux only.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

HOME_DIR="$HOME"

# Configuration
PBKDF2_ITERATIONS=600000
BACKUP_DIR="$HOME_DIR/cybersec_tools_backup"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup_$TIMESTAMP"
[[ -d "$BACKUP_DIR" ]] || mkdir -p "$BACKUP_DIR"
_init_log_file "$BACKUP_DIR/backup.log"

# Helpers
ensure_dir() {
    [[ -d "$1" ]] || mkdir -p "$1"
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
    read -rsp "Enter decryption passphrase: " passphrase
    echo ""
    _PASS_FILE=$(mktemp)
    chmod 600 "$_PASS_FILE"
    printf '%s' "$passphrase" > "$_PASS_FILE"
    unset passphrase
}

encrypt_archive() {
    local archive_path="$1"

    _prompt_passphrase || return 1

    local pass_file
    pass_file=$(mktemp)
    chmod 600 "$pass_file"
    printf '%s' "$_PASSPHRASE" > "$pass_file"
    unset _PASSPHRASE

    if openssl enc -chacha20 -salt -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$archive_path" -out "${archive_path}.enc" -pass file:"$pass_file" 2>/dev/null; then
        rm -f "$pass_file" "$archive_path"
        log_success "Archive encrypted: ${archive_path}.enc"
        log_info "Remember your passphrase (it is NOT stored)"
        return 0
    else
        rm -f "$pass_file" "${archive_path}.enc"
        log_error "Encryption failed"
        return 1
    fi
}

decrypt_archive() {
    local encrypted_path="$1"
    local output_path="${encrypted_path%.enc}"

    _read_passphrase_to_file

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

    _read_passphrase_to_file

    while IFS= read -r -d '' file; do
        local relative_path="${file#"$source_dir"/}"
        local decrypted_path="$target_dir/${relative_path%.enc}"
        ensure_dir "$(dirname "$decrypted_path")"
        openssl enc -aes-256-cbc -d -pbkdf2 -iter "$PBKDF2_ITERATIONS" -in "$file" -out "$decrypted_path" -pass file:"$_PASS_FILE" 2>/dev/null && \
            log_success "Decrypted: $relative_path" || \
            log_warn "Failed to decrypt: $relative_path"
    done < <(find "$source_dir" -type f -name "*.enc" -print0)

    rm -f "$_PASS_FILE"
}

# Backup config dirs (silently skip missing ones)
backup_configs() {
    local dest="$1"

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
            ensure_dir "$dest/$category"
            cp -r "$src" "$dest/$category/" 2>/dev/null
        fi
    done
}

# Restore config dirs
# Walks the category subdirectories created by backup_configs and copies
# each item back to its original location (derived from the directory name).
restore_configs() {
    local src="$1"

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
        [[ -n "$found" ]] && cp -r "$found" "$HOME_DIR/" 2>/dev/null
    done

    # ~/.config/ subdirs — restore to $HOME_DIR/.config/
    local -a _xdg_dirs=(nuclei subfinder amass)
    for dir in "${_xdg_dirs[@]}"; do
        local found
        found=$(find "$src" -maxdepth 2 -name "$dir" -type d 2>/dev/null | head -1)
        if [[ -n "$found" ]]; then
            ensure_dir "$HOME_DIR/.config"
            cp -r "$found" "$HOME_DIR/.config/" 2>/dev/null
        fi
    done

    # /opt tool dirs — restore to $GITHUB_TOOL_DIR/
    for dir in exploitdb recon-ng; do
        local found
        found=$(find "$src" -maxdepth 2 -name "$dir" -type d 2>/dev/null | head -1)
        [[ -n "$found" ]] && cp -r "$found" "$GITHUB_TOOL_DIR/" 2>/dev/null
    done
}

# Commands
cmd_backup() {
    log_info "Creating backup..."
    ensure_dir "$BACKUP_PATH"

    backup_configs "$BACKUP_PATH"

    log_info "Creating archive..."
    if ! tar -czf "$BACKUP_PATH.tar.gz" -C "$BACKUP_DIR" "backup_$TIMESTAMP"; then
        log_error "Failed to create archive"
        rm -rf "$BACKUP_PATH"
        exit 1
    fi
    rm -rf "$BACKUP_PATH"

    log_info "Encrypting archive..."
    if ! encrypt_archive "$BACKUP_PATH.tar.gz"; then
        log_error "Encryption failed — aborting (no backup created)"
        rm -f "$BACKUP_PATH.tar.gz"
        exit 1
    fi

    log_success "Backup created: $BACKUP_PATH.tar.gz.enc"
}

cmd_restore() {
    local backup_file="$1"

    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi

    local tar_file="$backup_file"

    # New format: .tar.gz.enc — decrypt first
    if [[ "$backup_file" == *.tar.gz.enc ]]; then
        log_info "Encrypted backup detected — decrypting..."
        if ! decrypt_archive "$backup_file"; then
            exit 1
        fi
        tar_file="${backup_file%.enc}"
    elif [[ "$backup_file" != *.tar.gz ]]; then
        log_error "Unrecognized backup format: $backup_file"
        log_info "Expected .tar.gz.enc (encrypted) or .tar.gz (legacy)"
        exit 1
    fi

    # Validate archive contents before extracting (block path traversal)
    local backup_name
    backup_name=$(tar -tzf "$tar_file" | head -1 | cut -f1 -d"/")

    if [[ -z "$backup_name" ]]; then
        log_error "Could not determine backup directory name from archive"
        [[ "$backup_file" == *.tar.gz.enc ]] && rm -f "$tar_file"
        exit 1
    fi

    # Reject archives containing path traversal or absolute paths
    if tar -tzf "$tar_file" | grep -qE '(^/|\.\.)'; then
        log_error "Archive contains unsafe paths (absolute or ../) — aborting"
        [[ "$backup_file" == *.tar.gz.enc ]] && rm -f "$tar_file"
        exit 1
    fi

    log_info "Extracting backup..."
    if ! tar -xzf "$tar_file" -C "$BACKUP_DIR"; then
        log_error "Failed to extract backup archive"
        [[ "$backup_file" == *.tar.gz.enc ]] && rm -f "$tar_file"
        exit 1
    fi

    # Clean up decrypted tar if we created it
    [[ "$backup_file" == *.tar.gz.enc ]] && rm -f "$tar_file"

    # Legacy format: check for individually encrypted files inside the archive
    if find "$BACKUP_DIR/$backup_name" -name "*.enc" -print -quit 2>/dev/null | grep -q .; then
        log_info "Legacy encrypted files found — decrypting..."
        decrypt_files_legacy "$BACKUP_DIR/$backup_name/encrypted" "$BACKUP_DIR/$backup_name"
    fi

    log_info "Restoring configurations..."
    restore_configs "$BACKUP_DIR/$backup_name"

    rm -rf "${BACKUP_DIR:?}/$backup_name"
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
            rm -f "$f"
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
        rm -f "$target"
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
        log_info "Example: export BACKUP_PASSPHRASE='your-passphrase-here'"
        log_info "Store it in a root-only file: echo 'BACKUP_PASSPHRASE=...' > /etc/cybersec-backup.env && chmod 600 /etc/cybersec-backup.env"
        exit 1
    fi

    # Write passphrase to a root-only env file instead of embedding in crontab
    # (avoids single-quote injection and keeps secrets out of crontab -l)
    local env_file="/etc/cybersec-backup.env"
    # Escape single quotes in passphrase to prevent shell injection when sourced
    local _escaped="${BACKUP_PASSPHRASE//\'/\'\\\'\'}"
    printf "BACKUP_PASSPHRASE='%s'\n" "$_escaped" > "$env_file"
    chmod 600 "$env_file"
    local cron_cmd=". $env_file && $SCRIPT_DIR/scripts/backup.sh backup"
    (crontab -l 2>/dev/null | grep -vF "$SCRIPT_DIR/scripts/backup.sh"; echo "$cron_schedule $cron_cmd") | crontab -
    log_success "Backup scheduled: $frequency at $time"
    log_info "Passphrase stored in $env_file (mode 600)"
}

cmd_unschedule() {
    crontab -l 2>/dev/null | grep -vF "$SCRIPT_DIR/scripts/backup.sh" | crontab -
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

# Main
ensure_dir "$BACKUP_DIR"

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
