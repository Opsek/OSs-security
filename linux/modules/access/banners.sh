#!/usr/bin/env bash

set_banner_text() {
    log_info "Configuring system login banner"
    local text="Acces autorise uniquement. Activite surveillee."
    local file="$1"
    log_info "Setting up security warning message in $file"
    
    backup_file "$file"
    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] write banner to $file"
    else
        echo "$text" > "$file"
        ensure_owner_perm "$file" root root 0644
    fi
}

configure_all_banners() {
    log_info "Setting up system-wide security banners and warnings"
    log_info "Configuring login warning messages for all access points"
    for f in /etc/issue /etc/issue.net /etc/motd; do
        set_banner_text "$f"
    done
    log_info "Security banners have been configured for all login interfaces"
}




