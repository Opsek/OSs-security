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

disable_popularity_contest() {
    log_info "Disabling popularity-contest package (telemetry service)"
    
    # Only applicable to Debian/Ubuntu-based distributions
    if [[ "$PLATFORM_FAMILY" != "debian" ]]; then
        log_info "Not a Debian/Ubuntu system; skipping popularity-contest disabling"
        return 0
    fi

    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] Check if popularity-contest is installed"
        log_info "[dry-run] Remove popularity-contest package"
        log_info "[dry-run] Prevent popularity-contest from being auto-installed"
        return 0
    fi

    # Check if popularity-contest is installed
    if dpkg -l | grep -q "^ii.*popularity-contest"; then
        log_info "Removing popularity-contest package..."
        if ! apt-get remove -y popularity-contest 2>/dev/null; then
            log_warn "Failed to remove popularity-contest package"
            return 1
        fi
        log_info "popularity-contest package removed successfully"
    else
        log_info "popularity-contest package is not installed"
    fi

    # Prevent it from being automatically installed by adding to apt hold list
    log_info "Adding popularity-contest to apt hold list to prevent auto-installation..."
    if ! apt-mark hold popularity-contest 2>/dev/null; then
        log_warn "Could not add popularity-contest to hold list (package may not exist in repos)"
    fi

    log_info "popularity-contest telemetry service disabled"
    return 0
}

