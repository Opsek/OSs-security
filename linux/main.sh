#!/usr/bin/env bash
set -euo pipefail
# Default values
VERBOSE=false

# Load common helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
COMMON_SH="$MODULES_DIR/core/common.sh"

# ==============================================================================
# USAGE AND HELP
# ==============================================================================

usage() {
    cat << EOF
Linux System Hardening Script

Usage: $0 [options]

Options:
    -h, --help              Show this help message
    --profile <name>        Select hardening profile (recommended, paranoid)
                           recommended: Standard secure configuration
                           paranoid: Maximum security, may impact usability
    --dry-run              Show what would be done without making changes
    -y, --yes              Don't ask for confirmation
    -v, --verbose          Show more detailed output

Examples:
    $0 --profile recommended
    $0 --profile paranoid --dry-run
    $0 --profile recommended --yes

Note: This script must be run as root.
EOF
    exit 0
}

if [[ ! -f "$COMMON_SH" ]]; then
    echo "[FATAL] Missing $COMMON_SH. Did you copy the full project?" >&2
    exit 1
fi

# shellcheck source=/dev/null
source "$COMMON_SH"

# Execute system info collection
system_info() {
    source "$MODULES_DIR/system/info.sh"
    get_hostname_info
    get_kernel_info
    get_os_info
    get_uptime_info
    get_cpu_info
    get_memory_info
    get_disk_info
    get_network_interfaces
    get_listening_ports
    get_logged_users
}

# Update system packages
system_updates() {
    source "$MODULES_DIR/system/updates.sh"
    case "$PLATFORM_FAMILY" in
        debian)
            update_debian_system
            ;;
        rhel|fedora)
            update_rhel_system
            ;;
        *)
            log_warn "Unknown family $PLATFORM_FAMILY; skipping updates"
            ;;
    esac
}

# Configure users and groups
users_groups() {
    source "$MODULES_DIR/access/users.sh"
    lock_system_accounts
    configure_password_aging
    secure_login_defs
}

# Harden SSH configuration if installed
ssh_hardening() {
    source "$MODULES_DIR/access/ssh.sh"
    # Only configure and restart if SSH is installed
    if is_ssh_installed; then
        configure_ssh_security
        restart_ssh_service
    fi
}

# Configure firewall
firewall_setup() {
    source "$MODULES_DIR/network/firewall.sh"
    case "$PLATFORM_FAMILY" in
        debian)
            configure_ufw_firewall
            ;;
        rhel|fedora)
            configure_firewalld
            ;;
        *)
            log_warn "Unknown platform family; skipping firewall"
            ;;
    esac
}

# Harden system services
services_hardening() {
    source "$MODULES_DIR/services/services.sh"
    disable_unnecessary_services
    ensure_time_synchronization
}

# Configure filesystem security
filesystem_hardening() {
    source "$MODULES_DIR/filesystem/filesystem.sh"
    secure_temp_directories
    check_partition_entries
}

# Apply sysctl kernel parameters
sysctl_hardening() {
    source "$MODULES_DIR/system/kernel.sh"
    harden_ipv4_settings
    harden_ipv6_settings
    harden_kernel_settings
}


# Setup fail2ban
fail2ban_setup() {
    source "$MODULES_DIR/network/fail2ban.sh"
    install_fail2ban
    configure_fail2ban
    enable_fail2ban_service
}

# Configure cron and at
cron_at_hardening() {
    source "$MODULES_DIR/services/cron.sh"
    remove_deny_files
    configure_allow_files
}

# Setup system banners
banners_setup() {
    source "$MODULES_DIR/access/banners.sh"
    configure_all_banners
}

# Configure system logging
logging_setup() {
    source "$MODULES_DIR/system/logging.sh"
    configure_system_logging
}

# Set secure permissions
permissions_hardening() {
    source "$MODULES_DIR/filesystem/permissions.sh"
    secure_authentication_files
    secure_sudo_configuration
    secure_critical_directories
}

# Configure network security
network_hardening() {
    source "$MODULES_DIR/network/network.sh"
    configure_module_blacklist
}

# Setup sudo configuration
sudo_hardening() {
    source "$MODULES_DIR/access/sudo.sh"
    install_sudo
    configure_sudo_defaults
}

# Run all hardening modules
run_all_modules() {
    log_section "Starting system hardening with profile: $PROFILE"
    log_info "Using security profile: $PROFILE"
    
    system_info
    system_updates
    users_groups
    ssh_hardening
    firewall_setup
    services_hardening
    filesystem_hardening
    sysctl_hardening
    fail2ban_setup
    cron_at_hardening
    banners_setup
    logging_setup
    permissions_hardening
    network_hardening
    sudo_hardening
    
    log_section "System hardening completed"
}

# Main execution
main() {
    require_root || exit 1
    detect_platform
    init_runtime
    
    SELECTED_MODULES=()
    EXCLUDED_MODULES=()
    DRY_RUN=false
    PROFILE="recommended"
    FORCE_YES=false
    VERBOSE=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            --profile)
                if [[ -n "${2:-}" ]]; then
                    case "$2" in
                        recommended|paranoid)
                            PROFILE="$2"
                            ;;
                        *)
                            log_error "Invalid profile: $2"
                            usage
                            exit 1
                            ;;
                    esac
                    shift 2
                else
                    log_error "Missing profile value"
                    usage
                    exit 1
                fi
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -y|--yes)
                FORCE_YES=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Set profile-specific variables
    export HARDEN_PROFILE="$PROFILE"
    export HARDEN_DRY_RUN="$DRY_RUN"
    export HARDEN_FORCE_YES="$FORCE_YES"
    export HARDEN_VERBOSE="$VERBOSE"

    # Initialize profile settings
    init_profile "$PROFILE"
    
    # Show configuration summary
    log_section "Configuration Summary"
    log_info "Profile: $PROFILE"
    log_info "Dry Run: $DRY_RUN"
    log_info "Force Yes: $FORCE_YES"
    echo

    # Ask for confirmation unless --yes is specified
    if [[ "$FORCE_YES" != "true" ]]; then
        read -p "Do you want to continue with the hardening process? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Hardening cancelled by user"
            exit 0
        fi
    fi

    # Run all modules with profile-based configurations
    run_all_modules

    # Show completion message
    echo
    log_section "Hardening completed"
    log_info "Profile: $PROFILE"
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "This was a dry run - no changes were made"
    fi
}

main "$@"