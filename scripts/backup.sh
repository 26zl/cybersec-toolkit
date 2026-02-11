#!/bin/bash
# =============================================================================
# CyberSec Tools — Config Backup/Restore Script
# Backs up and restores tool configurations with AES-256-CBC encryption.
# Supports scheduling via cron (Linux/macOS).
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# ----- Platform paths --------------------------------------------------------
case "$(uname -s)" in
    Linux*)
        HOME_DIR="$HOME"
        ;;
    Darwin*)
        HOME_DIR="$HOME"
        ;;
    CYGWIN*|MINGW*|MSYS*)
        HOME_DIR="${USERPROFILE:-$HOME}"
        ;;
    *)
        echo "Unsupported operating system"
        exit 1
        ;;
esac

# ----- Configuration --------------------------------------------------------
BACKUP_DIR="$HOME_DIR/cybersec_tools_backup"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup_$TIMESTAMP"
LOG_FILE="$BACKUP_DIR/backup.log"

# ----- Helpers ---------------------------------------------------------------
ensure_dir() {
    [[ -d "$1" ]] || mkdir -p "$1"
}

_prompt_passphrase() {
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

encrypt_archive() {
    local archive_path="$1"

    _prompt_passphrase || return 1

    local pass_file
    pass_file=$(mktemp)
    chmod 600 "$pass_file"
    printf '%s' "$_PASSPHRASE" > "$pass_file"
    unset _PASSPHRASE

    if openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 \
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

    local passphrase
    read -rsp "Enter decryption passphrase: " passphrase
    echo ""

    local pass_file
    pass_file=$(mktemp)
    chmod 600 "$pass_file"
    printf '%s' "$passphrase" > "$pass_file"

    if openssl enc -aes-256-cbc -d -pbkdf2 -iter 600000 \
        -in "$encrypted_path" -out "$output_path" -pass file:"$pass_file" 2>/dev/null; then
        rm -f "$pass_file"
        log_success "Archive decrypted: $output_path"
        return 0
    else
        rm -f "$pass_file" "$output_path"
        log_error "Decryption failed (wrong passphrase?)"
        return 1
    fi
}

# Legacy: decrypt individual .enc files from old-format backups
decrypt_files_legacy() {
    local source_dir="$1"
    local target_dir="$2"

    local passphrase
    read -rsp "Enter decryption passphrase: " passphrase
    echo ""

    local pass_file
    pass_file=$(mktemp)
    chmod 600 "$pass_file"
    printf '%s' "$passphrase" > "$pass_file"

    while IFS= read -r -d '' file; do
        local relative_path="${file#"$source_dir"/}"
        local decrypted_path="$target_dir/${relative_path%.enc}"
        ensure_dir "$(dirname "$decrypted_path")"
        openssl enc -aes-256-cbc -d -pbkdf2 -iter 600000 -in "$file" -out "$decrypted_path" -pass file:"$pass_file" 2>/dev/null && \
            log_success "Decrypted: $relative_path" || \
            log_warn "Failed to decrypt: $relative_path"
    done < <(find "$source_dir" -type f -name "*.enc" -print0)

    rm -f "$pass_file"
}

# ----- Backup config dirs (silently skip missing ones) -----------------------
backup_configs() {
    local dest="$1"

    # Map: backup_subdir -> list of source paths
    local -A CONFIG_PATHS=(
        ["network"]="$HOME_DIR/.nmap $HOME_DIR/.wireshark"
        ["web"]="$HOME_DIR/.burpsuite $HOME_DIR/.ZAP $HOME_DIR/.sqlmap"
        ["wireless"]="$HOME_DIR/.aircrack-ng $HOME_DIR/.kismet"
        ["password"]="$HOME_DIR/.john $HOME_DIR/.hashcat"
        ["exploitation"]="$HOME_DIR/.msf4 $GITHUB_TOOL_DIR/exploitdb"
        ["forensics"]="$HOME_DIR/.autopsy"
        ["osint"]="$GITHUB_TOOL_DIR/theHarvester $GITHUB_TOOL_DIR/recon-ng"
        ["phishing"]="$GITHUB_TOOL_DIR/gophish $GITHUB_TOOL_DIR/evilginx2"
    )

    for category in "${!CONFIG_PATHS[@]}"; do
        ensure_dir "$dest/$category"
        for src in ${CONFIG_PATHS[$category]}; do
            [[ -e "$src" ]] && cp -r "$src" "$dest/$category/" 2>/dev/null
        done
    done
}

# ----- Restore config dirs ---------------------------------------------------
restore_configs() {
    local src="$1"

    # Home dir configs
    for dir in .nmap .wireshark .burpsuite .ZAP .sqlmap .aircrack-ng .kismet \
               .john .hashcat .msf4 .autopsy; do
        local found
        found=$(find "$src" -maxdepth 2 -name "$dir" -type d 2>/dev/null | head -1)
        [[ -n "$found" ]] && cp -r "$found" "$HOME_DIR/" 2>/dev/null
    done

    # /opt tool dirs
    for dir in exploitdb theHarvester recon-ng gophish evilginx2; do
        local found
        found=$(find "$src" -maxdepth 2 -name "$dir" -type d 2>/dev/null | head -1)
        [[ -n "$found" ]] && cp -r "$found" "$GITHUB_TOOL_DIR/" 2>/dev/null
    done
}

# ----- Commands --------------------------------------------------------------
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

    log_info "Extracting backup..."
    tar -xzf "$tar_file" -C "$BACKUP_DIR"
    local backup_name
    backup_name=$(tar -tzf "$tar_file" | head -1 | cut -f1 -d"/")

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

cmd_schedule() {
    local frequency="$1"
    local time="$2"

    # Parse HH:MM
    local hour minute
    hour=$(echo "$time" | cut -d: -f1)
    minute=$(echo "$time" | cut -d: -f2)

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

    (crontab -l 2>/dev/null | grep -v "$SCRIPT_DIR/scripts/backup.sh"; echo "$cron_schedule $SCRIPT_DIR/scripts/backup.sh backup") | crontab -
    log_success "Backup scheduled: $frequency at $time"
}

cmd_unschedule() {
    crontab -l 2>/dev/null | grep -v "$SCRIPT_DIR/scripts/backup.sh" | crontab -
    log_success "Backup schedule removed"
}

show_usage() {
    echo "Usage: ./scripts/backup.sh <command> [args]"
    echo ""
    echo "Commands:"
    echo "  backup                           Create encrypted backup"
    echo "  restore <backup_file>            Restore from backup (.tar.gz.enc or .tar.gz)"
    echo "  list                             List available backups"
    echo "  schedule <daily|weekly|monthly> <HH:MM>"
    echo "  unschedule                       Remove scheduled backup"
}

# ----- Main ------------------------------------------------------------------
ensure_dir "$BACKUP_DIR"

case "${1:-}" in
    backup)      cmd_backup ;;
    restore)
        [[ -z "${2:-}" ]] && { log_error "Specify backup file"; show_usage; exit 1; }
        cmd_restore "$2"
        ;;
    list)        cmd_list ;;
    schedule)
        [[ -z "${2:-}" || -z "${3:-}" ]] && { log_error "Specify frequency and time"; show_usage; exit 1; }
        cmd_schedule "$2" "$3"
        ;;
    unschedule)  cmd_unschedule ;;
    --help|-h)   show_usage ;;
    *)           show_usage; exit 1 ;;
esac
