#!/usr/bin/env bash

# ==============================================================================
# macOS Security Hardening Script - OPSEK (Modular Version)
# ==============================================================================
# Version: 0.1.0
# Compatible with: macOS 13+ (Ventura, Sonoma, Sequoia)
# 
# FEATURES:
#   - CIS Benchmark compliance
#   - NIST 800-53 controls
#   - OPSEK project recommendations
#   - Multi-profile hardening (basic, moderate, strict, paranoid)
#   - Automated backup and rollback capabilities
#   - Comprehensive logging and audit trail
#   - Modular architecture for collaborative development
# ==============================================================================


set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# GLOBAL VARIABLES AND CONSTANTS
# ==============================================================================

readonly SCRIPT_VERSION="0.1.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
PROFILE="recommended"
DRY_RUN=false
FORCE_YES=false
VERBOSE=false
ENABLE_LOCKDOWN=false
ENABLE_CHECKS=false

# ==============================================================================
# INITIALIZATION
# ==============================================================================

# Load utilities
source "$SCRIPT_DIR/utils/common.sh"
source "$SCRIPT_DIR/utils/logging.sh"
source "$SCRIPT_DIR/utils/backup.sh"

# Initialize environment
init_environment

# ==============================================================================
# COMPLIANCE CHECKING FUNCTIONS
# ==============================================================================

# Run CIS compliance checks
run_cis_checks() {
    info "=== Running CIS Compliance Checks ==="
    
    local total_issues=0
    
    # CIS compliance checks
    cis_check_filevault || ((total_issues++))
    cis_check_firewall || ((total_issues++))
    cis_check_gatekeeper || ((total_issues++))
    
    local remote_issues
    cis_check_remote_services
    remote_issues=$?
    total_issues=$((total_issues + remote_issues))
    
    local user_issues
    cis_check_user_settings
    user_issues=$?
    total_issues=$((total_issues + user_issues))
    
    if [[ $total_issues -eq 0 ]]; then
        success "All CIS compliance checks passed"
    else
        warn "$total_issues CIS compliance issues found"
    fi
    
    return $total_issues
}

# Run OPSEK compliance checks
run_opsek_checks() {
    info "=== Running OPSEK Compliance Checks ==="
    
    local total_issues=0
    
    # OPSEK specific checks
    if function_exists "opsek_check_bluetooth"; then
        opsek_check_bluetooth || ((total_issues++))
    fi
    
    if function_exists "opsek_check_wifi"; then
        opsek_check_wifi || ((total_issues++))
    fi
    
    if function_exists "opsek_check_lockdown_mode"; then
        opsek_check_lockdown_mode || ((total_issues++))
    fi
    
    if function_exists "opsek_check_keyboard_security"; then
        opsek_check_keyboard_security || ((total_issues++))
    fi
    
    if [[ $total_issues -eq 0 ]]; then
        success "All OPSEK compliance checks passed"
    else
        warn "$total_issues OPSEK compliance issues found"
    fi
    
    return $total_issues
}

# ==============================================================================
# COMMAND LINE PARSING
# ==============================================================================

while [[ ${#} -gt 0 ]]; do
    case "$1" in
    --paranoid) PROFILE="paranoid"; shift ;;
        --lockdown) ENABLE_LOCKDOWN=true; shift ;;
        --checks) ENABLE_CHECKS=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --yes) FORCE_YES=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        --help) show_help; exit 0 ;;
        -h) show_help; exit 0 ;;
        *) error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# Validate profile
case "$PROFILE" in
    basic|moderate|strict|paranoid|recommended) ;;
    *) error "Unknown profile: $PROFILE"; show_help; exit 1 ;;
esac

# ==============================================================================
# MAIN FUNCTION
# ==============================================================================

main() {
    # Display the banner    
    show_banner
    
    # Get macOS major version
    OS_VERSION=$(sw_vers -productVersion)
    OS_MAJOR=$(echo "$OS_VERSION" | cut -d. -f1)

    info "macOS Hardening Script started (profile: $PROFILE)"
    info "Hostname: $HOSTNAME"
    info "macOS Version: $(sw_vers -productVersion)"
    info "Dry Run: $DRY_RUN"
    info "Force Yes: $FORCE_YES"
    info "Lockdown Mode: $ENABLE_LOCKDOWN"
    echo

    # List of EOL macOS versions
    # macOS Ventura (13) is no longer supported
    EOL_VERSIONS=("13")

    # Check if current version is EOL
    if [[ " ${EOL_VERSIONS[@]} " =~ " ${OS_MAJOR} " ]]; then
        echo "⚠️ WARNING: Your macOS version ($OS_VERSION) is no longer receiving security updates from Apple."
        echo "⚠️ Consider upgrading to a supported version (macOS 14 or newer) for continued security."
    fi
    
    # Check prerequisites
    check_prereqs
    
    # Backup directory is prepared during init_environment
    if [[ "$DRY_RUN" == true ]]; then
        info "Dry-run mode: no backups will be written"
    else
        info "Backup directory: $CURRENT_BACKUP"
    fi
    
    # Display warning and get confirmation if interactive
    if [[ "$FORCE_YES" != true ]] && [[ "$DRY_RUN" != true ]]; then
        echo
        warn "WARNING: This script will modify system security settings."
        warn "Profile: $PROFILE"
        if [[ "$ENABLE_LOCKDOWN" == true ]]; then
            warn "Lockdown Mode: ENABLED (may impact web browsing)"
        fi
        warn "A backup will be created at: $CURRENT_BACKUP"
        echo
        read -p "Continue with hardening? (y/N): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && { info "Hardening cancelled by user"; exit 0; }
    fi
    
    # Validate profile
    if ! validate_profile "$PROFILE"; then
        error "Profile validation failed"
        exit 1
    fi
    
    # Apply selected profile
    echo
    if ! apply_profile "$PROFILE"; then
        error "Failed to apply profile: $PROFILE"
        exit 1
    fi
    
    # Create rollback script if not dry-run
    if [[ "$DRY_RUN" == false ]]; then
        generate_rollback_script "$CURRENT_BACKUP" "$TIMESTAMP"
        success "Hardening applied and backup stored in: $CURRENT_BACKUP"
    else
        info "Dry-run finished. No changes were applied."
    fi
    
    # Run compliance checks if requested
    local compliance_issues=0
    
    if [[ "$ENABLE_CHECKS" == true ]]; then
        echo
        run_cis_checks
        compliance_issues=$?

        echo
        local opsek_issues
        run_opsek_checks
        opsek_issues=$?
        compliance_issues=$((compliance_issues + opsek_issues))
        show_summary "$PROFILE" "$compliance_issues"
    fi

}

# Run main script
main "$@"
