#!/usr/bin/env bash

# Check if SSH server is installed
is_ssh_installed() {
    # Check for sshd binary
    if command -v sshd >/dev/null 2>&1; then
        return 0
    fi
    
    # Check for common SSH server packages based on distribution
    case "$PLATFORM_FAMILY" in
        debian)
            dpkg -l openssh-server >/dev/null 2>&1
            return $?
            ;;
        rhel|fedora)
            rpm -q openssh-server >/dev/null 2>&1
            return $?
            ;;
        *)
            return 1
            ;;
    esac
}

configure_ssh_security() {
    # First check if SSH is installed
    if ! is_ssh_installed; then
        log_info "SSH server not detected - skipping SSH hardening"
        return 0
    fi
    
    log_info "SSH server detected - proceeding with security hardening"
    log_info "Configuring SSH security settings for enhanced protection"
    log_info "Setting up SSH protocol and authentication restrictions"
    
    # Get SSH configuration from profile
    local ssh_port
    local permit_root_login
    local password_auth
    
    ssh_port=$(get_profile_setting "SSH_PORT")
    permit_root_login=$(get_profile_setting "SSH_PERMIT_ROOT_LOGIN")
    password_auth=$(get_profile_setting "SSH_PASSWORD_AUTH")
    
    # Basic SSH protocol and authentication settings from profile
    ensure_sshd_conf Protocol 2
    ensure_sshd_conf Port "$ssh_port"
    ensure_sshd_conf PermitRootLogin "$permit_root_login"
    ensure_sshd_conf PasswordAuthentication "$password_auth"
    ensure_sshd_conf PubkeyAuthentication yes
    ensure_sshd_conf PermitEmptyPasswords no
    
    # Authentication and session settings
    ensure_sshd_conf ChallengeResponseAuthentication no
    ensure_sshd_conf UsePAM yes
    ensure_sshd_conf MaxAuthTries 3
    ensure_sshd_conf MaxSessions 5
    ensure_sshd_conf LoginGraceTime 30
    
    # Connection and forwarding settings
    ensure_sshd_conf X11Forwarding no
    ensure_sshd_conf AllowTcpForwarding no
    ensure_sshd_conf AllowAgentForwarding no
    ensure_sshd_conf ClientAliveInterval 300
    ensure_sshd_conf ClientAliveCountMax 2
}

restart_ssh_service() {
    log_info "Checking SSH service state before applying configuration"

    local ssh_service=""
    local was_running=false

    # Detect service name
    if systemctl list-unit-files | grep '^sshd\.service'; then
        ssh_service="sshd"
    elif systemctl list-unit-files | grep '^ssh\.service'; then
        ssh_service="ssh"
    else
        log_info "SSH service not installed — skipping"
        return 0
    fi

    # Check if it is currently active
    if systemctl is-active --quiet "$ssh_service"; then
        was_running=true
    fi

    if [[ "$was_running" != true ]]; then
        log_info "SSH service is not running — will not start it (attack surface preserved)"
        return 0
    fi

    log_info "SSH service is running — applying configuration safely"

    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] systemctl reload $ssh_service || systemctl restart $ssh_service"
    else
        systemctl reload "$ssh_service" 2>/dev/null || systemctl restart "$ssh_service" 2>/dev/null || true
    fi

    log_info "SSH configuration applied without changing exposure"
}




