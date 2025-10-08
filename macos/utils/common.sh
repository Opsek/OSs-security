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
        return 0
    else
        warn "Command failed: $cmd"
        return 1
    fi
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
    execute "mkdir -p '$backup_path'"
    execute "cp -p '$file' '$backup_path/'"
    debug "Backed up: $file"
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
    
    # Execute each function from normalized array
    mapfile -t profile_array <<<"$profile_functions"
    for rawfunc in "${profile_array[@]}"; do
        func="$(_trim "$rawfunc")"
        [[ -z "$func" ]] && continue

        if function_exists "$func"; then
            info "Executing: $func"
            if "$func"; then
                success "✓ $func completed"
            else
                warn "✗ $func failed"
            fi
        else
            warn "Function not found: $func - skipping"
        fi
    done
    
    success "Profile applied: $profile"
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
    
    # Initialize global variables
    readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
    readonly HOSTNAME="$(hostname -s)"
    readonly CURRENT_BACKUP="$BACKUP_ROOT/backup_$TIMESTAMP"
    readonly LOGFILE="$LOG_ROOT/macos_hardening_$TIMESTAMP.log"
    
    # Create necessary directories
    if [[ "$DRY_RUN" == false ]]; then
        execute "mkdir -p '$CURRENT_BACKUP'"
        execute "mkdir -p '$(dirname "$LOGFILE")'"
        execute "chmod 700 '$CURRENT_BACKUP'"
        execute "chmod 600 '$LOGFILE'"
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
