#!/usr/bin/env bash

disable_unnecessary_services() {
    log_info "Identifying and disabling unnecessary network services"
    local profile_name
    profile_name=$(get_profile_setting "PROFILE_NAME")
    if [[ "$profile_name" == "paranoid" ]]; then
        log_info "Warning : Disabling avahi-daemon and cups can affect local network discovery (including .local hostnames, AirPrint, IPP printing, and casting/IoT device functionality) as well as any printing operations on the local system."
        local disable=(avahi-daemon cups telnet vsftpd xinetd tftp)
    else
        local disable=(telnet vsftpd xinetd tftp)
    fi
    log_info "Services to be disabled: ${disable[*]}"

    for s in "${disable[@]}"; do
        if systemctl list-unit-files | grep -q "^$s\.service"; then
            if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
                log_info "[dry-run] systemctl disable --now $s"
            else
                systemctl disable --now "$s" 2>/dev/null || true
            fi
        fi
    done
}

ensure_time_synchronization() {
    log_info "Configuring system time synchronization"
    if systemctl list-unit-files | grep -q '^systemd-timesyncd\.service'; then
        log_info "Using systemd-timesyncd for time synchronization"
        service_enable_start systemd-timesyncd
    elif systemctl list-unit-files | grep -q '^chronyd\.service'; then
        service_enable_start chronyd
    elif systemctl list-unit-files | grep -q '^ntpd\.service'; then
        service_enable_start ntpd
    fi
}




