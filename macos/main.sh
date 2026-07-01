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
#   - Multi-profile hardening (recommended paranoid)
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
CHECKS_ONLY=false
SNAPSHOT_ONLY=false
GENERATE_MDM=false
MDM_PROFILE="recommended"
MDM_OUTPUT_DIR="$SCRIPT_DIR/mdm_profiles"

# ==============================================================================
# INITIALIZATION
# ==============================================================================

# Load utilities
source "$SCRIPT_DIR/utils/common.sh"
source "$SCRIPT_DIR/utils/logging.sh"
source "$SCRIPT_DIR/utils/backup.sh"
source "$SCRIPT_DIR/modules/mdm/profile_generator.sh"



# ==============================================================================
# COMPLIANCE CHECKING FUNCTIONS
# ==============================================================================

# Run CIS compliance checks
run_cis_checks() {
    info "=== Running CIS Compliance Checks ==="
    
    local total_issues=0
    
    # CIS compliance checks
    cis_check_filevault || total_issues=$((total_issues+1))
    cis_check_firewall || total_issues=$((total_issues+1))
    cis_check_gatekeeper || total_issues=$((total_issues+1))
    cis_check_software_updates || total_issues=$((total_issues+1))
    cis_check_admin_required || total_issues=$((total_issues+1))
    cis_check_file_extensions || total_issues=$((total_issues+1))

    # Capture multi-issue counts with `|| var=$?` so a non-zero return (issues
    # found) does not trip `set -e` and abort the audit mid-run.
    local fw_issues=0
    cis_check_firewall_hardening || fw_issues=$?
    total_issues=$((total_issues + fw_issues))

    local lock_issues=0
    cis_check_lockscreen || lock_issues=$?
    total_issues=$((total_issues + lock_issues))

    local remote_issues=0
    cis_check_remote_services || remote_issues=$?
    total_issues=$((total_issues + remote_issues))

    local user_issues=0
    cis_check_user_settings || user_issues=$?
    total_issues=$((total_issues + user_issues))
    
    # Aggregate summary line. Emitted as info, not success/warn, so the GUI
    # parser does not count it as an extra passed/failed check on top of the
    # individual cis_check_* results above.
    if [[ $total_issues -eq 0 ]]; then
        info "All CIS compliance checks passed"
    else
        info "$total_issues CIS compliance issues found"
    fi

    return $total_issues
}

# Run OPSEK compliance checks
run_opsek_checks() {
    info "=== Running OPSEK Compliance Checks ==="
    
    local total_issues=0
    
    # OPSEK specific checks
    if function_exists "opsek_check_bluetooth"; then
        opsek_check_bluetooth || total_issues=$((total_issues+1))
    fi
    
    if function_exists "opsek_check_wifi"; then
        opsek_check_wifi || total_issues=$((total_issues+1))
    fi
    
    if function_exists "opsek_check_lockdown_mode"; then
        opsek_check_lockdown_mode || total_issues=$((total_issues+1))
    fi
    
    if function_exists "opsek_check_keyboard_security"; then
        opsek_check_keyboard_security || total_issues=$((total_issues+1))
    fi

    if function_exists "opsek_check_airdrop_handoff"; then
        local airdrop_issues=0
        opsek_check_airdrop_handoff || airdrop_issues=$?
        total_issues=$((total_issues + airdrop_issues))
    fi

    # Aggregate summary line, emitted as info for the same reason as the CIS
    # summary above (avoid double-counting in the GUI score).
    if [[ $total_issues -eq 0 ]]; then
        info "All OPSEK compliance checks passed"
    else
        info "$total_issues OPSEK compliance issues found"
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
        --checks-only) CHECKS_ONLY=true; ENABLE_CHECKS=true; shift ;;
        --snapshot-only) SNAPSHOT_ONLY=true; FORCE_YES=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --yes) FORCE_YES=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        --generate-mdm) GENERATE_MDM=true; shift ;;
        --mdm-profile) MDM_PROFILE="$2"; shift 2 ;;
        --help) show_help; exit 0 ;;
        -h) show_help; exit 0 ;;
        *) error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# Validate profile
case "$PROFILE" in
    paranoid|recommended) ;;
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
    
    # Handle MDM profile generation
    if [[ "$GENERATE_MDM" == true ]]; then
        info "Generating MDM hardening profiles..."
        echo

        # Validate MDM profile
        case "$MDM_PROFILE" in
            recommended|paranoid) ;;
            *) error "Invalid MDM profile: $MDM_PROFILE (use: recommended, paranoid)"; exit 1 ;;
        esac
        
        generate_mdm_profile "$MDM_PROFILE"
        
        exit 1
    fi
    

    # List of EOL macOS versions
    # macOS Ventura (13) is no longer supported
    EOL_VERSIONS=("13")

    # Check if current version is EOL
    if [[ " ${EOL_VERSIONS[@]} " =~ " ${OS_MAJOR} " ]]; then
        echo "⚠️ WARNING: Your macOS version ($OS_VERSION) is no longer receiving security updates from Apple."
        echo "⚠️ Consider upgrading to a supported version (macOS 14 or newer) for continued security."
    fi
    
    # Initialize environment
    init_environment

    # Check prerequisites
    check_prereqs
    
    # Backup directory is prepared during init_environment
    if [[ "$DRY_RUN" == true ]]; then
        info "Dry-run mode: no backups will be written"
    else
        info "Backup directory: $CURRENT_BACKUP"
    fi

    # Standalone restore point: capture the current system state (so it can be
    # rolled back to) without applying any hardening, then exit. Used by the GUI
    # "Create snapshot" button so users can save a checkpoint on demand.
    if [[ "$SNAPSHOT_ONLY" == true ]]; then
        if [[ "$DRY_RUN" == false ]]; then
            snapshot_system_state paranoid
            generate_rollback_script "$CURRENT_BACKUP" "$TIMESTAMP"
            write_snapshot_metadata "$CURRENT_BACKUP" "$TIMESTAMP"
            success "Restore point saved in: $CURRENT_BACKUP"
        else
            info "Dry-run: no restore point created."
        fi
        exit 0
    fi

    # Apply the hardening profile, unless we were asked to only run the
    # read-only compliance checks. --checks-only is used by the GUI audit so
    # the score reflects the real system state and is not mixed with a profile
    # dry-run that would otherwise be applied here first.
    if [[ "$CHECKS_ONLY" != true ]]; then
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
            write_snapshot_metadata "$CURRENT_BACKUP" "$TIMESTAMP"
            success "Hardening applied and backup stored in: $CURRENT_BACKUP"
        else
            info "Dry-run finished. No changes were applied."
        fi
    fi

    # Run compliance checks if requested
    local compliance_issues=0

    if [[ "$ENABLE_CHECKS" == true ]]; then
        echo
        # Capture each with `|| var=$?`: the functions return the issue count,
        # and a bare non-zero return would trip set -e and abort main() before
        # run_opsek_checks ran.
        # Markers so a combined apply+checks run (GUI Apply uses --checks) can
        # isolate the check rows from the apply log noise when parsing the score.
        echo "OPSEK_CHECKS_BEGIN"
        local cis_issues=0
        run_cis_checks || cis_issues=$?

        echo
        local opsek_issues=0
        run_opsek_checks || opsek_issues=$?
        echo "OPSEK_CHECKS_END"

        compliance_issues=$((cis_issues + opsek_issues))

        # The hardening summary banner only makes sense when a profile was
        # actually applied. In checks-only mode the checks are the output.
        if [[ "$CHECKS_ONLY" != true ]]; then
            show_summary "$PROFILE" "$compliance_issues"
        fi
    fi

}

# Run main script
main "$@"
