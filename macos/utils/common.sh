#!/usr/bin/env bash

# ==============================================================================
# Common utility functions for macOS hardening script
# ==============================================================================

# Load configuration
load_config() {
    local config_dir="$(dirname "${BASH_SOURCE[0]}")/../config"
    
    if [[ -f "$config_dir/settings.conf" ]]; then
        source "$config_dir/settings.conf"
    else
        error "Configuration file not found: $config_dir/settings.conf"
        exit 1
    fi
}

# Check prerequisites
check_prereqs() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run with sudo privileges"
        exit 1
    fi
    
    # Check macOS version
    local os_version="$(sw_vers -productVersion)"
    local major_version="$(echo "$os_version" | cut -d. -f1)"
    
    if [[ $major_version -lt 13 ]]; then
        warn "This script is optimized for macOS 13+ (current: $os_version)"
        if [[ "$FORCE_YES" != true ]]; then
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
        fi
    fi
    
    # Check required commands
    local required_commands=("defaults" "systemsetup" "networksetup" "spctl" "fdesetup")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    success "Prerequisites check passed"
}

# Execute command with backup and dry-run support
execute() {
    local cmd="$1"
    debug "Execute: $cmd"
    
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would execute: $cmd"
        return 0
    fi
    
    if eval "$cmd" 2>&1 | tee -a "$LOGFILE" > /dev/null; then
        success "Command succeeded : $cmd"
        return 0
    else
        warn "Command failed: $cmd"
        return 1
    fi
}

# --------------------------------------------------------------------------
# Per-user context
#
# The script runs as root (sudo). Under sudo, $HOME, `~`, and a bare
# `defaults`/`security` call resolve to root, so any per-user setting would be
# written to /var/root instead of the person actually logged in. That is why
# screen lock, Finder, Safari, AirDrop and similar settings appeared to "not
# change". Resolve the real console user once and route per-user changes
# through user_execute / user_defaults so they land in the right account.
# --------------------------------------------------------------------------

# Populated by detect_target_user. Declared here so `set -u` never trips on
# them before detection runs.
TARGET_USER="${TARGET_USER:-}"
TARGET_UID="${TARGET_UID:-}"
TARGET_HOME="${TARGET_HOME:-}"

detect_target_user() {
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        TARGET_USER="$SUDO_USER"
    else
        TARGET_USER="$(/usr/bin/stat -f%Su /dev/console 2>/dev/null || true)"
    fi

    if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" || "$TARGET_USER" == "loginwindow" ]]; then
        TARGET_USER=""
        TARGET_UID=""
        TARGET_HOME=""
        warn "Could not determine a non-root login user. Per-user settings (screen lock, Finder, Safari, AirDrop) will be skipped."
        return 0
    fi

    TARGET_UID="$(id -u "$TARGET_USER" 2>/dev/null || true)"
    TARGET_HOME="$(/usr/bin/dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    [[ -z "$TARGET_HOME" ]] && TARGET_HOME="/Users/$TARGET_USER"
    info "Applying per-user settings as: $TARGET_USER (uid $TARGET_UID, home $TARGET_HOME)"
}

# Run a command as the target login user, inside their per-user launchd
# context, so `defaults`/`security` write to that account and cfprefsd picks
# the change up. Honors DRY_RUN. Returns non-zero (but never aborts) on
# failure so an unsupported per-user tweak does not sink the whole run.
user_execute() {
    local cmd="$1"
    debug "User execute ($TARGET_USER): $cmd"

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would execute as ${TARGET_USER:-<no user>}: $cmd"
        return 0
    fi

    if [[ -z "$TARGET_USER" || -z "$TARGET_UID" ]]; then
        warn "No login user resolved, skipping per-user command: $cmd"
        return 1
    fi

    if launchctl asuser "$TARGET_UID" sudo -u "$TARGET_USER" /bin/bash -c "$cmd" 2>&1 | tee -a "$LOGFILE" > /dev/null; then
        success "Command succeeded (user $TARGET_USER): $cmd"
        return 0
    else
        warn "Command failed (user $TARGET_USER): $cmd"
        return 1
    fi
}

# Convenience wrapper for a per-user `defaults` invocation.
user_defaults() {
    user_execute "defaults $*"
}

# Read a value from the target user's defaults domain (for the audit/checks).
# Prints the value on stdout and returns the underlying status. Returns 1 with
# no output when no login user was resolved.
user_defaults_read() {
    [[ -z "$TARGET_USER" ]] && return 1
    sudo -u "$TARGET_USER" defaults read "$@" 2>/dev/null
}

# Same, for a per-user ByHost (-currentHost) value.
user_defaults_read_currenthost() {
    [[ -z "$TARGET_USER" ]] && return 1
    sudo -u "$TARGET_USER" defaults -currentHost read "$@" 2>/dev/null
}

# Read the login user's real screen-lock state via sysadminctl (the inert
# com.apple.screensaver keys do not reflect it on macOS 13+). Runs in the
# user's launchd context; sysadminctl prints to stderr, hence the 2>&1.
user_screenlock_status() {
    [[ -z "$TARGET_USER" || -z "$TARGET_UID" ]] && return 1
    launchctl asuser "$TARGET_UID" sudo -u "$TARGET_USER" sysadminctl -screenLock status 2>&1
}

# Backup a file that lives in the target user's home, reading it from the real
# account rather than /var/root. No-op when no login user was resolved.
user_backup_file() {
    local rel="$1"   # path relative to the user home, e.g. Library/Preferences/x.plist
    [[ -z "$TARGET_HOME" ]] && return 0
    backup_file "$TARGET_HOME/$rel"
}

# Backup file before modification
backup_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        debug "File does not exist, skipping backup: $file"
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        debug "[DRY-RUN] Would backup: $file"
        return 0
    fi

    local backup_path="$CURRENT_BACKUP$(dirname "$file")"
    local backup_file="$backup_path/$(basename "$file")"

    execute "mkdir -p '$backup_path'"

    # 🔐 Preserve original backup if it already exists
    if [[ -f "$backup_file" ]]; then
        debug "Backup already exists, preserving original: $backup_file"
        return 0
    fi

    execute "cp -p '$file' '$backup_file'"
    debug "Backed up: $file -> $backup_file"
}

# Deprecated: use cleanup_old_backups_in_dir from utils/backup.sh for custom roots

# Check if a function exists
function_exists() {
    local func_name="$1"
    declare -f "$func_name" > /dev/null 2>&1
}

# Load a module
load_module() {
    local module_path="$1"
    
    if [[ -f "$module_path" ]]; then
        debug "Loading module: $module_path"
        source "$module_path"
        return 0
    else
        warn "Module not found: $module_path"
        return 1
    fi
}

# Load all modules from a directory
load_modules() {
    local module_dir="$1"
    
    if [[ ! -d "$module_dir" ]]; then
        warn "Module directory not found: $module_dir"
        return 1
    fi
    
    for module_file in "$module_dir"/*.sh; do
        if [[ -f "$module_file" ]]; then
            load_module "$module_file"
        fi
    done
}

# Validate a profile
validate_profile() {
    local profile="$1"
    local profile_functions
    
    # Load profile functions
    case "$profile" in
        basic) profile_functions="$PROFILE_BASIC" ;;
        moderate) profile_functions="$PROFILE_MODERATE" ;;
        strict) profile_functions="$PROFILE_STRICT" ;;
        paranoid) profile_functions="$PROFILE_PARANOID" ;;
        recommended) profile_functions="$PROFILE_RECOMMENDED" ;;
        *) error "Unknown profile: $profile"; return 1 ;;
    esac

    # Normalize profile function list into an array (split on newlines, trim whitespace)
    local -a profile_array=()
    while IFS= read -r line; do
        profile_array+=("$line")
    done <<< "$profile_functions"

    # helper to trim whitespace
    _trim() {
        local var="$1"
        # remove leading whitespace
        var="${var#${var%%[![:space:]]*}}"
        # remove trailing whitespace
        var="${var%${var##*[![:space:]]}}"
        printf '%s' "$var"
    }

    # Check which functions exist (treat missing ones as warnings)
    local missing_count=0
    local missing_list=""
    for rawfunc in "${profile_array[@]}"; do
        func="$(_trim "$rawfunc")"
        # skip empty lines
        [[ -z "$func" ]] && continue

        if ! function_exists "$func"; then
            warn "Function not found: $func"
            missing_count=$((missing_count + 1))
            missing_list="$missing_list $func"
        fi
    done

    if [[ $missing_count -gt 0 ]]; then
        warn "Profile validation completed with $missing_count missing function(s):$missing_list"
    else
        success "Profile validation passed: $profile"
    fi

    # Return success to allow partial application of profiles (missing functions will be skipped)
    return 0
}

# Apply a profile
apply_profile() {
    local profile="$1"
    local profile_functions
    
    info "Applying profile: $profile"
    
    # Load profile functions
    case "$profile" in
        basic) profile_functions="$PROFILE_BASIC" ;;
        moderate) profile_functions="$PROFILE_MODERATE" ;;
        strict) profile_functions="$PROFILE_STRICT" ;;
        paranoid) profile_functions="$PROFILE_PARANOID" ;;
        recommended) profile_functions="$PROFILE_RECOMMENDED" ;;
        *) error "Unknown profile: $profile"; return 1 ;;
    esac
    
    # Capture the pre-Apply state of system toggles into the revert journal
    # before any hardening runs, so Restore can put them back. No-op in dry-run.
    snapshot_system_state "$profile"

    # Execute each function from normalized array
    while IFS= read -r line; do
        profile_array+=("$line")
    done <<< "$profile_functions"
    
    local apply_failures=0
    for rawfunc in "${profile_array[@]}"; do
        func="$(_trim "$rawfunc")"
        [[ -z "$func" ]] && continue

        if function_exists "$func"; then
            info "Executing: $func"
            if "$func"; then
                success "✓ $func completed"
            else
                warn "✗ $func failed"
                apply_failures=$((apply_failures + 1))
            fi
        else
            warn "Function not found: $func - skipping"
        fi
    done

    success "Profile applied: $profile"

    # Machine-checkable outcome the GUI gates on, so a half-applied run is never
    # reported as a clean success. Per-function failures are warnings above (a
    # control unsupported on this macOS build is expected), but the count is
    # surfaced here so the Swift side can tell clean from partial.
    if [[ "$apply_failures" -eq 0 ]]; then
        echo "OPSEK_APPLY_OK"
    else
        echo "OPSEK_APPLY_FAILED failures=$apply_failures"
    fi
}

# Clean up old backups
cleanup_old_backups() {
    if [[ -d "$BACKUP_ROOT" ]]; then
        find "$BACKUP_ROOT" -type d -name "backup_*" -mtime +$BACKUP_RETENTION_DAYS -exec rm -rf {} \; 2>/dev/null || true
        info "Old backups cleaned up (older than $BACKUP_RETENTION_DAYS days)"
    fi
}

# Initialize environment
init_environment() {
    # Load configuration
    load_config

    # Resolve the real login user so per-user settings are applied to them and
    # not to root. Safe to call before the log file exists (uses warn/info).
    detect_target_user

    # Initialize global variables
    readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
    readonly HOSTNAME="$(hostname -s)"
    readonly CURRENT_BACKUP="$BACKUP_ROOT/backup_$TIMESTAMP"
    readonly REVERT_JOURNAL="$CURRENT_BACKUP/revert_state.sh"
    readonly LOGFILE="$LOG_ROOT/macos_hardening_$TIMESTAMP.log"
    
    # Create necessary directories
    if [[ "$DRY_RUN" == false ]]; then
        execute "mkdir -p '$CURRENT_BACKUP'"
        execute "mkdir -p '$(dirname "$LOGFILE")'"

        # Let the non-root GUI list the snapshot tree: /var/backups ships 700
        # root:wheel. 711 on the parent is traverse-only, 755 on our root lists
        # the snapshot names; each backup_<ts> dir stays 700 (contents private).
        execute "chmod 711 '$(dirname "$BACKUP_ROOT")'"
        execute "chmod 755 '$BACKUP_ROOT'"

        execute "chmod 700 '$CURRENT_BACKUP'"
        execute "chmod 600 '$LOGFILE'"

        # Start the revert journal inside the snapshot dir so toggle captures
        # have somewhere to record (see snapshot_system_state in utils/backup.sh).
        init_revert_journal
    fi
    
    # Load modules
    local script_dir="$(dirname "${BASH_SOURCE[0]}")"
    load_modules "$script_dir/../modules/cis"
    load_modules "$script_dir/../modules/internals"
    load_modules "$script_dir/../checks"
    
    # Load profiles
    if [[ -f "$script_dir/../config/profiles.conf" ]]; then
        source "$script_dir/../config/profiles.conf"
        # Backwards compatibility and safety:
        # Some configs use PROFILE_RECOMMENDED; map it to the 'moderate' profile
        # if specific PROFILE_MODERATE is not defined. Use parameter expansion
        # to avoid unbound variable errors when 'set -u' is enabled.
        : "${PROFILE_MODERATE:=${PROFILE_RECOMMENDED:-}}"
        : "${PROFILE_BASIC:=${PROFILE_MODERATE:-}}"
        : "${PROFILE_STRICT:=${PROFILE_PARANOID:-}}"
    fi
}
