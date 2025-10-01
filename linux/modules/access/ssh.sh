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
    # Basic SSH protocol and authentication settings
    ensure_sshd_conf Protocol 2
    ensure_sshd_conf PermitRootLogin no
    ensure_sshd_conf PasswordAuthentication no
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
    log_info "Applying new SSH configuration by restarting the service"
    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] systemctl reload sshd || service ssh restart"
    else
        systemctl reload sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
    fi
    log_info "SSH service has been configured and restarted"
}




