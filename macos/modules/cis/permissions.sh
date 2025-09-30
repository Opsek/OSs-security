#!/usr/bin/env bash

# ==============================================================================
# CIS Module - Permissions and security
# ==============================================================================

# CIS 5.1.1 - Secure Home Folders
secure_home_folders() {
    info "CIS 5.1.1 - Securing home folder permissions"
    
    # Set proper permissions for existing user home folders
    for user_home in /Users/*; do
        if [[ -d "$user_home" ]] && [[ "$(basename "$user_home")" != "Shared" ]]; then
            execute "chmod 700 '$user_home'" || warn "Could not secure $user_home"
        fi
    done
    
    success "Home folder permissions secured"
}

# CIS 5.1.2 - Check System Wide Applications for appropriate permissions
check_application_permissions() {
    info "CIS 5.1.2 - Checking system application permissions"
    
    execute "chmod -R o-w /Applications"
    execute "chmod -R o-w /System/Applications"
    
    success "System application permissions verified"
}

# CIS 5.1.3 - Check System folder for world writable files
fix_system_permissions() {
    info "CIS 5.1.3 - Fixing world-writable files in System folder"
    
    execute "find /System -type f -perm -002 -exec chmod o-w {} \\; 2>/dev/null || true"
    execute "find /usr -type f -perm -002 -exec chmod o-w {} \\; 2>/dev/null || true"
    
    success "System folder permissions fixed"
}

# CIS 5.1.4 - Check Library folder for world writable files
fix_library_permissions() {
    info "CIS 5.1.4 - Fixing world-writable files in Library folder"
    
    execute "find /Library -type f -perm -002 -exec chmod o-w {} \\; 2>/dev/null || true"
    
    success "Library folder permissions fixed"
}

# CIS 5.2 - Password Policy
configure_password_policy() {
    info "CIS 5.2 - Configuring password policy"
    
    # Set minimum password length
    execute "pwpolicy -n /Local/Default -setglobalpolicy 'minChars=14'"
    execute "pwpolicy -n /Local/Default -setglobalpolicy 'requiresAlpha=1'"
    execute "pwpolicy -n /Local/Default -setglobalpolicy 'requiresNumeric=1'"
    execute "pwpolicy -n /Local/Default -setglobalpolicy 'maxMinutesUntilChangePassword=525600'"
    
    success "Password policy configured"
}

# CIS 5.3 - Reduce the sudo timeout period
configure_sudo_timeout() {
    info "CIS 5.3 - Configuring sudo timeout"
    
    backup_file "/etc/sudoers"
    
    # Write secure sudoers.d drop-in and validate with visudo
    execute "printf 'Defaults timestamp_timeout=0\n' | tee /etc/sudoers.d/timeout >/dev/null"
    execute "chmod 440 /etc/sudoers.d/timeout"
    
    # Validate syntax to avoid locking out sudo
    if ! visudo -cf /etc/sudoers >/dev/null 2>&1; then
        warn "visudo reported issues in /etc/sudoers; attempting rollback"
        restore_from_backup "$CURRENT_BACKUP" "/etc/sudoers" || true
        return 1
    fi
    if ! visudo -cf /etc/sudoers.d/timeout >/dev/null 2>&1; then
        warn "visudo reported issues in /etc/sudoers.d/timeout; removing file"
        execute "rm -f /etc/sudoers.d/timeout"
        return 1
    fi
    
    success "Sudo timeout configured to 0 (require password every time)"
}

# CIS 5.4 - Automatically lock the login keychain for inactivity
configure_keychain_lock() {
    info "CIS 5.4 - Configuring keychain auto-lock"
    
    execute "security set-keychain-settings -t 21600 -l ~/Library/Keychains/login.keychain"
    
    success "Keychain auto-lock configured"
}

# CIS 5.5 - Ensure login keychain is locked when the computer sleeps
configure_keychain_sleep_lock() {
    info "CIS 5.5 - Configuring keychain lock on sleep"
    
    execute "security set-keychain-settings -l ~/Library/Keychains/login.keychain"
    
    success "Keychain sleep lock configured"
}

# CIS 5.6 - Enable OCSP and CRL certificate checking
enable_certificate_checking() {
    info "CIS 5.6 - Enabling certificate revocation checking"
    
    execute "defaults write com.apple.security.revocation CRLStyle -string RequireIfPresent"
    execute "defaults write com.apple.security.revocation OCSPStyle -string RequireIfPresent"
    
    success "Certificate revocation checking enabled"
}

# CIS 5.7 - Do not enable the "root" account
disable_root_account() {
    info "CIS 5.7 - Ensuring root account is disabled"
    
    execute "dscl . -create /Users/root UserShell /usr/bin/false"
    
    success "Root account shell disabled"
}

# CIS 5.8 - Disable automatic login
disable_automatic_login() {
    info "CIS 5.8 - Disabling automatic login"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    execute "defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || true"
    
    success "Automatic login disabled"
}

# CIS 5.9 - Require a password to wake the computer from sleep or screen saver
require_password_wake() {
    info "CIS 5.9 - Requiring password on wake"
    
    execute "defaults write com.apple.screensaver askForPassword -int 1"
    execute "defaults write com.apple.screensaver askForPasswordDelay -int 0"
    
    success "Password required on wake"
}

# CIS 5.11 - Require an administrator password to access system-wide preferences
require_admin_system_prefs() {
    info "CIS 5.11 - Requiring admin password for system preferences"
    
    execute "security authorizationdb read system.preferences > /tmp/system.preferences.plist"
    execute "defaults write /tmp/system.preferences.plist shared -bool false"
    execute "security authorizationdb write system.preferences < /tmp/system.preferences.plist"
    execute "rm /tmp/system.preferences.plist"
    
    success "Admin password required for system preferences"
}

# CIS 5.12 - Disable ability to login to another user's active and locked session
disable_fast_user_switching() {
    info "CIS 5.12 - Disabling fast user switching"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    execute "defaults write /Library/Preferences/.GlobalPreferences MultipleSessionEnabled -bool false"
    
    success "Fast user switching disabled"
}

# CIS 5.16 - Secure individual keychains and items
secure_keychains() {
    info "CIS 5.16 - Securing keychains"
    
    execute "security set-keychain-settings -t 21600 -l login.keychain"
    
    success "Keychains secured"
}
