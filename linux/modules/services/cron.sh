#!/usr/bin/env bash

remove_deny_files() {
    log_info "Removing legacy cron and at deny files"
    log_info "Switching to allowlist-based access control for scheduled tasks"
    for f in /etc/cron.deny /etc/at.deny; do
        if [[ -f "$f" ]]; then
            if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
                log_info "[dry-run] remove $f"
            else
                rm -f "$f" || true
            fi
        fi
    done
}

configure_allow_files() {
    log_info "Setting up secure cron and at access control"
    log_info "Creating and securing allowlist files for scheduled tasks"
    for f in /etc/cron.allow /etc/at.allow; do
        if [[ ! -f "$f" ]]; then
            if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
                log_info "[dry-run] touch $f"
            else
                touch "$f"
            fi
        fi
        ensure_owner_perm "$f" root root 0600
    done
}




