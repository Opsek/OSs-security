#!/usr/bin/env bash

install_fail2ban() {
    # Check if fail2ban is enabled in current profile
    local fail2ban_enabled
    fail2ban_enabled=$(get_profile_setting "FAIL2BAN_ENABLED")
    if [[ "$fail2ban_enabled" != "yes" ]]; then
        log_info "Fail2ban installation skipped - disabled in current profile"
        return 0
    fi

    log_info "Installing Fail2ban intrusion prevention system (paranoid mode)"

    # Install fail2ban based on distribution
    case "$PLATFORM_FAMILY" in
        debian)
            pkg_install fail2ban python3-pyinotify || {
                log_error "Failed to install fail2ban packages"
                return 1
            }
            ;;
        rhel|fedora)
            # EPEL repository might be needed for RHEL/CentOS
            if [[ "$PLATFORM_FAMILY" == "rhel" ]]; then
                pkg_install epel-release || {
                    log_error "Failed to install EPEL repository"
                    return 1
                }
            fi
            pkg_install fail2ban fail2ban-systemd || {
                log_error "Failed to install fail2ban packages"
                return 1
            }
            ;;
        *)
            log_error "Unsupported platform family for fail2ban: $PLATFORM_FAMILY"
            return 1
            ;;
    esac

    # Verify installation
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        log_error "fail2ban-client command not found after installation"
        return 1
    fi

    # Create required directories
    mkdir -p /etc/fail2ban/jail.d || {
        log_error "Failed to create fail2ban configuration directories"
        return 1
    }

    log_info "Fail2ban installation completed successfully"
}

configure_fail2ban() {
    # Check if fail2ban is enabled in current profile
    local fail2ban_enabled
    fail2ban_enabled=$(get_profile_setting "FAIL2BAN_ENABLED")
    if [[ "$fail2ban_enabled" != "yes" ]]; then
        log_info "Fail2ban configuration skipped - disabled in current profile"
        return 0
    fi

    log_info "Configuring Fail2ban security policies (paranoid mode)"
    log_info "Setting up strict intrusion detection rules and ban policies"
    
    # Ensure fail2ban configuration directory exists
    if [[ ! -d /etc/fail2ban ]]; then
        log_info "Creating fail2ban configuration directory"
        if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
            log_info "[dry-run] mkdir -p /etc/fail2ban"
        else
            mkdir -p /etc/fail2ban || {
                log_error "Failed to create /etc/fail2ban directory"
                return 1
            }
        fi
    fi

    local jail=/etc/fail2ban/jail.local
    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] write jail.local and enable fail2ban"
        return
    fi
    backup_file "$jail"
    

    log_info "Writing fail2ban jail configuration"
    mkdir -p "$(dirname "$jail")" || {
        log_error "Failed to create jail.local parent directory"
        return 1
    }
    
    # Get SSH port from profile for fail2ban configuration
    local ssh_port
    ssh_port=$(get_profile_setting "SSH_PORT")
    
    cat > "$jail" <<JAIL
[DEFAULT]
# More aggressive settings for paranoid mode
bantime = 24h        # Ban for 24 hours
findtime = 5m        # Look back time reduced to 5 minutes
maxretry = 3         # Less retries allowed
backend = systemd
banaction = iptables-multiport
chain = INPUT

[sshd]
enabled = true
port = $ssh_port     # Using SSH port from profile
filter = sshd
logpath = %(sshd_log)s
maxretry = 2         # Even stricter for SSH
bantime = 48h        # Longer ban time for SSH attempts
JAIL
}

enable_fail2ban_service() {
    # Check profile setting
    local fail2ban_enabled
    fail2ban_enabled=$(get_profile_setting "FAIL2BAN_ENABLED")
    
    if [[ "$fail2ban_enabled" == "no" ]]; then
        log_info "Fail2ban is disabled in current profile - skipping activation"
        return 0
    fi

    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] would enable and start fail2ban service"
        return 0
    fi
    
    log_info "Enabling and starting Fail2ban service"

    # Copy default configuration if it doesn't exist
    if [[ ! -f /etc/fail2ban/jail.local ]]; then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local 2>/dev/null || {
            log_error "Failed to create initial jail.local configuration"
            return 1
        }
    fi

    # Enable and start the service
    systemctl enable fail2ban.service || {
        log_error "Failed to enable fail2ban.service"
        return 1
    }

    systemctl start fail2ban.service || {
        log_error "Failed to start fail2ban.service"
        systemctl status fail2ban.service
        return 1
    }

    # Verify service is running
    if ! systemctl is-active fail2ban.service >/dev/null 2>&1; then
        log_error "fail2ban service is not running after start attempt"
        return 1
    fi

    # Test configuration
    if ! fail2ban-client ping >/dev/null 2>&1; then
        log_error "fail2ban service is not responding to client ping"
        return 1
    fi

    log_info "Fail2ban is now active and monitoring for suspicious activities"
}




