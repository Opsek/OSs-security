#!/usr/bin/env bash


# detect_active_services: detect running SSH and web services along with their listening ports
# returns a list of services in the format "name:port"
detect_active_services() {
    local services=()

    # Check for SSH
    if is_ssh_installed && systemctl is-active sshd.service >/dev/null 2>&1; then
        local ssh_port
        ssh_port=$(get_profile_setting "SSH_PORT")
        services+=("ssh:$ssh_port")
    fi

    # Check for HTTP/HTTPS (Apache or Nginx)
    local web_services=("apache2" "httpd" "nginx")
    for svc in "${web_services[@]}"; do
        if systemctl is-active "$svc" >/dev/null 2>&1; then
            # Detect actual listening TCP ports for this service
            local ports=($(ss -tlnp | grep -E "$svc" | awk '{gsub(/.*:/,"",$4); print $4}' | sort -u))
            
            if [[ ${#ports[@]} -eq 0 ]]; then
                log_warn "$svc is active but no listening TCP ports detected — skipping"
                continue
            fi

            # Ask user for explicit consent for each port
            for p in "${ports[@]}"; do
                read -r -p "Allow incoming TCP traffic on port $p for $svc? [y/N]: " consent
                if [[ "$consent" =~ ^[Yy]$ ]]; then
                    services+=("$svc:$p")
                    log_info "User approved $svc on port $p"
                else
                    log_info "User declined $svc on port $p"
                fi
            done
        fi
    done

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
    
    local ssh_port
    ssh_port=$(get_profile_setting "SSH_PORT")

    # Apply paranoid mode restrictions if enabled
    local profile_name
    profile_name=$(get_profile_setting "PROFILE_NAME")
    if [[ "$profile_name" == "paranoid" ]]; then
        log_info "Applying paranoid mode restrictions"
        log_info "$ssh_port"

        # Block default SSH port if it's different from the profile port
        if [[ "$ssh_port" != "22" ]]; then
            ufw deny 22/tcp comment 'Block default SSH'
        fi

        # Allow and rate-limit only on the hardened port
        ufw allow "$ssh_port/tcp" comment 'Allow hardened SSH port'
        ufw limit "$ssh_port/tcp" comment 'Rate limit hardened SSH'

        ufw logging high
    else
        ufw logging low
    fi

    # Ensure SSH daemon matches the firewall
    backup_file /etc/ssh/sshd_config
    
    if ! grep -q "^Port $ssh_port" /etc/ssh/sshd_config; then
        sed -i "s/^#\?Port .*/Port $ssh_port/" /etc/ssh/sshd_config
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

ssh_service_active() {
    systemctl list-unit-files | grep -qE '^sshd\.service' &&
    systemctl is-enabled sshd &>/dev/null &&
    systemctl is-active sshd &>/dev/null
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
        log_info "[dry-run] Would configure FirewallD with SSH on port $ssh_port"
        return
    fi

    log_info "Setting default zone to public"
    firewall-cmd --set-default-zone=public || true

    if ssh_service_active; then
        log_info "Verified SSH service is active"

        if [[ "$ssh_port" != "22" ]]; then
            log_info "Allowing SSH on hardened port $ssh_port"
            firewall-cmd --permanent --add-port="$ssh_port/tcp" || true
        else
            log_info "Allowing standard SSH service"
            firewall-cmd --permanent --add-service=ssh || true
        fi
    else
        log_warn "SSH service not active — not opening inbound SSH ports"
    fi

    firewall-cmd --reload || log_warn "Firewall reload failed"
    
    log_info "FirewallD configuration completed"
}


