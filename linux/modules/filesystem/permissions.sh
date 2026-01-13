#!/usr/bin/env bash

secure_authentication_files() {
    log_info "Securing authentication files with appropriate permissions"
    log_info "Setting restrictive access rights on password and group files"
    # Secure password and group files
    ensure_owner_perm /etc/passwd root root 0644
    ensure_owner_perm /etc/group root root 0644
    ensure_owner_perm /etc/shadow root root 0640
    ensure_owner_perm /etc/gshadow root root 0640
}

secure_sudo_configuration() {
    log_info "Securing sudo configuration file permissions"
    log_info "Ensuring sudo configuration is only readable by root"
    ensure_owner_perm /etc/sudoers root root 0440
}

secure_critical_directories() {
    log_info "Applying secure permissions to critical system directories"
    # Base directories security
    log_info "Setting base security permissions for root and log directories"
    ensure_owner_perm /root root root 0700
    ensure_owner_perm /var/log root root 0755

    # Additional paranoid mode restrictions
    local profile_name
    profile_name=$(get_profile_setting "PROFILE_NAME")
    if [[ "$profile_name" == "paranoid" ]]; then
        log_info "Applying paranoid-level directory restrictions"
        log_info "Setting strict permissions on system binaries and configuration directories"
        # Restrict access to system binaries
        ensure_owner_perm /usr/local/bin root root 0755
        ensure_owner_perm /usr/local/sbin root root 0755
        
        # Secure boot files
        ensure_owner_perm /boot root root 0700
        
        # Restrict access to core dumps
        ensure_owner_perm /var/crash root root 0700
        
        # Secure kernel module directory
        ensure_owner_perm /lib/modules root root 0700
        
        # Restrict access to cron
        ensure_owner_perm /etc/cron.d root root 0700
        ensure_owner_perm /etc/cron.daily root root 0700
        ensure_owner_perm /etc/cron.hourly root root 0700
        ensure_owner_perm /etc/cron.weekly root root 0700
        ensure_owner_perm /etc/cron.monthly root root 0700
    fi
}




