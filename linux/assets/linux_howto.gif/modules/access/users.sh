#!/usr/bin/env bash

lock_system_accounts() {
    log_info "Securing system accounts by restricting shell access"
    log_info "Identifying and locking non-essential system accounts"
    while IFS=: read -r name _ uid gid gecos home shell; do
        if [[ $uid -lt 1000 && $shell != */nologin && $shell != */false ]]; then
            if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
                log_info "[dry-run] usermod -s /usr/sbin/nologin $name"
            else
                command -v usermod >/dev/null 2>&1 && usermod -s /usr/sbin/nologin "$name" 2>/dev/null || true
            fi
        fi
    done </etc/passwd
}

configure_password_aging() {
    log_info "Configuring password aging policies for user accounts"
    if ! command -v chage >/dev/null 2>&1; then
        log_warn "Password aging tool (chage) not found - skipping configuration"
        return
    fi

    for u in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
        if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
            log_info "[dry-run] chage -M 90 -m 1 -W 14 $u"
        else
            chage -M 90 -m 1 -W 14 "$u" 2>/dev/null || true
        fi
    done
}

secure_login_defs() {
    log_info "Setting up system-wide password and login policies"
    log_info "Configuring password expiration and warning periods"
    
    local max_days
    local min_days
    local warn_age
    
    max_days=$(get_profile_setting "PASSWORD_MAX_DAYS")
    min_days=$(get_profile_setting "PASSWORD_MIN_DAYS")
    warn_age=$(get_profile_setting "PASSWORD_WARN_AGE")
    
    # Configure password aging policies
    log_info "Setting password maximum age to $max_days days"
    apply_line /etc/login.defs "^PASS_MAX_DAYS" "PASS_MAX_DAYS   $max_days"
    
    log_info "Setting password minimum age to $min_days days"
    apply_line /etc/login.defs "^PASS_MIN_DAYS" "PASS_MIN_DAYS   $min_days"
    
    log_info "Setting password warning period to $warn_age days"
    apply_line /etc/login.defs "^PASS_WARN_AGE" "PASS_WARN_AGE   $warn_age"
    
    # Configure default UMASK for new files
    log_info "Setting secure default UMASK"
    apply_line /etc/login.defs "^UMASK" "UMASK           027"
    
    log_info "Login policies have been configured"
}


