#!/usr/bin/env bash

install_sudo() {
    pkg_install sudo || true
}

configure_sudo_defaults() {
    backup_file /etc/sudoers
    
    # Configure logging
    apply_line /etc/sudoers "^Defaults\s+logfile\s*=" "Defaults    logfile=/var/log/sudo.log"
    ensure_owner_perm /var/log/sudo.log root root 0600
    
    # Set security options
    apply_line /etc/sudoers "^Defaults\s+passwd_tries\s*=" "Defaults    passwd_tries=3"
    apply_line /etc/sudoers "^Defaults\s+requiretty\s*=" "Defaults    requiretty"
    apply_line /etc/sudoers "^Defaults\s+use_pty\s*=" "Defaults    use_pty"
}




