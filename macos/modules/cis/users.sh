#!/usr/bin/env bash

# ==============================================================================
# Module CIS - Configuration utilisateurs
# ==============================================================================

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

# CIS 5.13 - Create a custom message for the Login Screen
set_login_message() {
    info "CIS 5.13 - Setting login screen message"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    local login_message="This system is for authorized users only. All activity is logged and monitored."
    execute "defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText '$login_message'"
    
    success "Login screen message configured"
}

# CIS 5.14 - Create a Login window banner
set_login_banner() {
    info "CIS 5.14 - Creating login window banner"
    
    backup_file "/Library/Security/PolicyBanner.txt"
    
    cat > /Library/Security/PolicyBanner.txt << 'EOF'
This computer system is the private property of its owner, whether
individual, corporate or government. It is for authorized use only.
Users (authorized or unauthorized) have no explicit or implicit
expectation of privacy.

Any or all uses of this system and all files on this system may be
intercepted, monitored, recorded, copied, audited, inspected, and
disclosed to your employer, to authorized site, government, and law
enforcement personnel, as well as authorized officials of government
agencies, both domestic and foreign.

By using this system, the user consents to such interception, monitoring,
recording, copying, auditing, inspection, and disclosure at the
discretion of such personnel or officials. Unauthorized or improper use
of this system may result in civil and criminal penalties and
administrative or disciplinary action, as appropriate. By continuing to
use this system you indicate your awareness of and consent to these terms
and conditions of use. LOG OFF IMMEDIATELY if you do not agree to the
conditions stated in this warning.
EOF
    
    execute "chmod 644 /Library/Security/PolicyBanner.txt"
    
    success "Login banner created"
}

# CIS 5.15 - Do not enter a password-based screensaver mode
disable_password_screensaver_mode() {
    info "CIS 5.15 - Configuring screensaver password mode"
    
    execute "defaults write com.apple.screensaver askForPassword -int 1"
    
    success "Screensaver password mode configured"
}

# CIS 6.1.1 - Display login window as name and password
configure_login_window_style() {
    info "CIS 6.1.1 - Configuring login window style"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    execute "defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true"
    
    success "Login window configured to show name and password fields"
}

# CIS 6.1.2 - Disable "Show password hints"
disable_password_hints() {
    info "CIS 6.1.2 - Disabling password hints"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    execute "defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0"
    
    success "Password hints disabled"
}

# CIS 6.1.3 - Disable guest account login
disable_guest_account() {
    info "CIS 6.1.3 - Disabling guest account"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    execute "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"
    execute "sysadminctl -guestAccount off 2>/dev/null || true"
    
    success "Guest account disabled"
}

# CIS 6.1.4 - Disable "Allow guests to connect to shared folders"
disable_guest_shared_folders() {
    info "CIS 6.1.4 - Disabling guest access to shared folders"
    
    execute "defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false"
    execute "defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false"
    
    success "Guest access to shared folders disabled"
}

# CIS 6.1.5 - Remove Guest home folder
remove_guest_home() {
    info "CIS 6.1.5 - Removing guest home folder"
    
    execute "rm -rf /Users/Guest" || true
    
    success "Guest home folder removed"
}

# CIS 6.2 - Turn on filename extensions
show_filename_extensions() {
    info "CIS 6.2 - Showing filename extensions"
    
    execute "defaults write NSGlobalDomain AppleShowAllExtensions -bool true"
    
    success "Filename extensions enabled"
}

# CIS 6.3 - Disable the automatic run of safe files in Safari
disable_safari_safe_files() {
    info "CIS 6.3 - Disabling Safari automatic safe file opening"
    
    execute "defaults write com.apple.Safari AutoOpenSafeDownloads -bool false"
    
    success "Safari automatic safe file opening disabled"
}
