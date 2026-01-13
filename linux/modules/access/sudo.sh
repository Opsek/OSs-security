#!/usr/bin/env bash

install_sudo() {
    pkg_install sudo || true
}

configure_sudo_defaults() {
    local tmp_file="/etc/sudoers.d/.hardening.tmp"
    local final_file="/etc/sudoers.d/99-hardening"

    log_info "Configuring sudo using drop-in file"

    mkdir -p /etc/sudoers.d
    chmod 0750 /etc/sudoers.d

    cat > "$tmp_file" << 'EOF'
Defaults logfile=/var/log/sudo.log
Defaults passwd_tries=3
Defaults requiretty
Defaults use_pty
EOF

    chmod 0440 "$tmp_file"

    if ! visudo -cf "$tmp_file"; then
        log_error "Sudo configuration validation failed — aborting changes"
        rm -f "$tmp_file"
        return 1
    fi

    mv "$tmp_file" "$final_file"
    log_info "Sudo hardening rules safely installed at $final_file"

    ensure_owner_perm /var/log/sudo.log root root 0600
}



