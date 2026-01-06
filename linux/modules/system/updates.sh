#!/usr/bin/env bash

update_debian_system() {
    log_info "Updating Debian/Ubuntu system packages"

    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] apt-get update"
        log_info "[dry-run] apt-get upgrade --simulate"
        log_info "[dry-run] apt-get dist-upgrade --simulate"
        return 0
    fi

    log_info "Updating package cache..."
    if ! apt-get update -y; then
        log_error "Package cache update failed — aborting"
        return 1
    fi

    log_info "Simulating safe upgrade..."
    safe_plan=$(apt-get upgrade --simulate)

    log_info "Simulating aggressive upgrade..."
    aggressive_plan=$(apt-get dist-upgrade --simulate)

    if [[ "$safe_plan" != "$aggressive_plan" ]]; then
        log_warn "Upgrade plans differ between safe and aggressive modes"
        log_warn "Aggressive mode may remove or replace packages"

        echo
        echo "===== SAFE UPGRADE PLAN ====="
        echo "$safe_plan"
        echo
        echo "=== AGGRESSIVE UPGRADE PLAN ==="
        echo "$aggressive_plan"
        echo

        read -r -p "Proceed with aggressive upgrade? [y/N]: " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || {
            log_info "Proceeding with safe upgrade only"
            if ! DEBIAN_FRONTEND=noninteractive apt-get upgrade -y; then
                log_error "Safe upgrade failed"
                return 1
            fi
            log_info "System update completed (safe mode)"
            return 0
        }
    fi

    log_info "Performing aggressive upgrade"
    if ! DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y; then
        log_error "Aggressive upgrade failed"
        return 1
    fi

    log_info "Removing unused packages..."
    if ! apt-get autoremove -y; then
        log_warn "Autoremove encountered issues"
    fi

    log_info "System update completed successfully"
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

