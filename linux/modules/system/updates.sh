#!/usr/bin/env bash

update_debian_system() {
    log_info "Updating Debian/Ubuntu system packages"
    
    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y && apt-get autoremove -y"
        return
    fi
    
    log_info "Updating package cache..."
    apt-get update -y
    
    log_info "Upgrading installed packages..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    
    log_info "Performing distribution upgrade..."
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y || true
    
    log_info "Removing unused packages..."
    apt-get autoremove -y || true
    
    log_info "System update completed"
}

update_rhel_system() {
    log_info "Updating RHEL/Fedora system packages"
    
    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] dnf -y upgrade || yum -y update"
        return
    fi
    
    if command -v dnf >/dev/null 2>&1; then
        log_info "Using DNF package manager..."
        dnf -y upgrade || true
    else
        log_info "Using YUM package manager..."
        yum -y update || true
    fi
    
    log_info "System update completed"
}

