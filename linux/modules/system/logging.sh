#!/usr/bin/env bash

setup_rsyslog() {
    log_info "Installing and configuring RSyslog logging service"
    pkg_install rsyslog || true
    log_info "Enabling and starting RSyslog service"
    service_enable_start rsyslog || true
    log_info "RSyslog is now configured and running"
}

configure_journald() {
    log_info "Configuring systemd-journald for persistent logging"
    log_info "Enabling persistent storage for system logs"
    backup_file /etc/systemd/journald.conf
    apply_line /etc/systemd/journald.conf "^Storage\s*=" "Storage=persistent"
    
    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] systemctl restart systemd-journald"
    else
        systemctl restart systemd-journald 2>/dev/null || true
    fi
}

configure_system_logging() {
    log_info "Setting up system-wide logging configuration"
    if command -v rsyslogd >/dev/null 2>&1 || systemctl list-unit-files | grep -q '^rsyslog\.service'; then
        log_info "RSyslog detected - using RSyslog for system logging"
        setup_rsyslog
    else
        log_info "Using systemd-journald for system logging"
        configure_journald
    fi
    log_info "System logging has been configured and enabled"
}




