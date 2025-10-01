#!/usr/bin/env bash

detect_active_services() {
    local services=()
    
    # Check for SSH
    if is_ssh_installed && systemctl is-active sshd.service >/dev/null 2>&1; then
        local ssh_port
        ssh_port=$(get_profile_setting "SSH_PORT")
        services+=("ssh:$ssh_port")
    fi
    
    # Check for HTTP/HTTPS (Apache or Nginx)
    if systemctl is-active apache2.service >/dev/null 2>&1 || \
       systemctl is-active httpd.service >/dev/null 2>&1 || \
       systemctl is-active nginx.service >/dev/null 2>&1; then
        services+=("web")
    fi

    echo "${services[*]}"
}

configure_ufw_firewall() {
    log_info "Setting up UFW for network security"
    
    # Install UFW if not present
    if ! command -v ufw >/dev/null 2>&1; then
        if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
            log_info "[dry-run] Would install UFW"
            return
        fi
        pkg_install ufw || {
            log_error "Failed to install UFW"
            return 1
        }
    fi

    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] Would configure UFW"
        return
    fi
    
    log_info "Resetting firewall to default state"
    ufw --force reset

    log_info "Setting default deny policies"
    ufw default deny incoming
    ufw default allow outgoing

    # Get active services that need firewall rules
    local active_services
    active_services=$(detect_active_services)
    
    # Configure rules based on active services
    for service in $active_services; do
        case "${service%%:*}" in
            ssh)
                local port="${service#*:}"
                log_info "Allowing SSH access on port $port (active service)"
                ufw allow "$port/tcp" comment 'SSH access'
                ;;
            web)
                log_info "Allowing HTTP/HTTPS access (active service)"
                ufw allow http comment 'HTTP access'
                ufw allow https comment 'HTTPS access'
                ;;
        esac
    done
    
    # Apply paranoid mode restrictions if enabled
    if [[ "${HARDEN_PROFILE:-}" == "paranoid" ]]; then
        log_info "Applying paranoid mode restrictions"
        # Rate limit incoming connections
        ufw limit 22/tcp comment 'Rate limit SSH'
        # Log all blocked traffic
        ufw logging high
    else
        ufw logging low
    fi
    
    log_info "Enabling UFW firewall"
    ufw --force enable
    
    # Verify UFW is active and configured
    if ! ufw status >/dev/null 2>&1; then
        log_error "UFW failed to enable properly"
        return 1
    fi
    
    log_info "UFW configuration completed successfully"
}

configure_firewalld() {
    log_info "Setting up FirewallD for network protection"
    pkg_install firewalld || true
    
    log_info "Enabling and starting FirewallD service"
    service_enable_start firewalld
    
    # Get SSH port from profile
    local ssh_port
    ssh_port=$(get_profile_setting "SSH_PORT")
    
    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] Configuring FirewallD with SSH on port $ssh_port"
        return
    fi
    
    log_info "Setting default zone to public"
    firewall-cmd --set-default-zone=public || true
    
    log_info "Configuring SSH access"
    if [[ "$ssh_port" != "22" ]]; then
        log_info "Adding custom SSH port $ssh_port"
        firewall-cmd --permanent --add-port="$ssh_port/tcp" || true
    else
        log_info "Adding standard SSH service"
        firewall-cmd --permanent --add-service=ssh || true
    fi
    
    log_info "Reloading FirewallD configuration"
    firewall-cmd --reload || true
    
    log_info "FirewallD configuration completed"
}


