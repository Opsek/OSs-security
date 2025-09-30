#!/usr/bin/env bash

# ==============================================================================
# Logging system for macOS hardening script
# ==============================================================================

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Logging variables
LOG_LEVEL="INFO"
VERBOSE=false

# Generic logging function
log_message() {
    local level="$1"
    local message="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local log_entry="[$timestamp] [$level] $message"
    
    # Display according to level
    case "$level" in
        DEBUG)
            if [[ "$VERBOSE" == true ]]; then
                echo -e "${BLUE}$log_entry${NC}"
            fi
            ;;
        INFO)
            echo -e "${CYAN}$log_entry${NC}"
            ;;
        SUCCESS)
            echo -e "${GREEN}✓ $log_entry${NC}"
            ;;
        WARNING)
            echo -e "${YELLOW}⚠ $log_entry${NC}"
            ;;
        ERROR)
            echo -e "${RED}✗ $log_entry${NC}"
            ;;
    esac
    
    # Write to log file
    if [[ -n "${LOGFILE:-}" ]]; then
        echo "$log_entry" >> "$LOGFILE"
    fi
}

# Specialized logging functions
info() {
    log_message "INFO" "$*"
}

success() {
    log_message "SUCCESS" "$*"
}

warn() {
    log_message "WARNING" "$*"
}

error() {
    log_message "ERROR" "$*"
}

debug() {
    if [[ "$VERBOSE" == true ]]; then
        log_message "DEBUG" "$*"
    fi
}

# Function to display banner
show_banner() {
    echo
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║                    macOS Security Hardening Script                          ║"
    echo "║                         OPSEK Integration                                 ║"
    echo "║                              v${SCRIPT_VERSION:-0.1.0}                                      ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo
}

# Function to display help
show_help() {
    cat <<USAGE
macOS Security Hardening Script v${SCRIPT_VERSION:-0.1.0}

Usage: sudo $0 [OPTIONS]

OPTIONS:
    --profile PROFILE    Choose hardening profile: basic|moderate|strict|paranoid (default: moderate)
    --lockdown          Enable Lockdown Mode compatible settings (macOS 13+ only)
    --checks            Run compliance checks after hardening
    --dry-run           Show changes that would be made without applying them
    --yes               Assume yes to all prompts (non-interactive mode)
    --verbose           Show debug output in log
    --help, -h          Show this help

PROFILES:
    basic      - Essential security with minimal impact
    moderate   - Balanced security for most environments (recommended)
    strict     - High security for sensitive environments
    paranoid   - Maximum restrictions; may break some services

EXAMPLES:
    sudo $0 --profile moderate --verbose
    sudo $0 --dry-run --profile strict
    sudo $0 --yes --profile paranoid --lockdown
    sudo $0 --profile basic --lockdown
    sudo $0 --profile moderate --checks

NOTES:
    - Lockdown Mode requires macOS 13 (Ventura) or later
    - Lockdown Mode settings may significantly impact web browsing experience
    - Use --lockdown flag to explicitly enable Lockdown Mode compatible settings
    - Use --checks flag to run compliance checks after hardening

USAGE
}

# Function to display summary
show_summary() {
    local profile="$1"
    local total_issues="$2"
    
    echo
    success "=== macOS hardening complete ==="
    info "Profile applied: $profile"
    info "Log file: ${LOGFILE:-N/A}"
    
    if [[ "$DRY_RUN" == false ]]; then
        info "Backup directory: ${CURRENT_BACKUP:-N/A}"
        if [[ -n "${CURRENT_BACKUP:-}" ]]; then
            info "Rollback script: $CURRENT_BACKUP/rollback_hardening_${TIMESTAMP:-}.sh"
        fi
        echo
        warn "RECOMMENDATION: Restart your system to ensure all changes take effect."
        
        if [[ "$FORCE_YES" != true ]]; then
            read -p "Restart now? (y/N): " -n 1 -r
            echo
            [[ $REPLY =~ ^[Yy]$ ]] && shutdown -r now
        fi
    fi
    
    if [[ $total_issues -gt 0 ]]; then
        warn "$total_issues compliance issues found"
    else
        success "All compliance checks passed"
    fi
}

# Function to configure logging
setup_logging() {
    local log_file="$1"
    local verbose="$2"
    
    LOGFILE="$log_file"
    VERBOSE="$verbose"
    
    # Create log directory if necessary
    if [[ -n "$log_file" ]]; then
        local log_dir="$(dirname "$log_file")"
        mkdir -p "$log_dir" 2>/dev/null || true
        touch "$log_file" 2>/dev/null || true
        chmod 600 "$log_file" 2>/dev/null || true
    fi
}
