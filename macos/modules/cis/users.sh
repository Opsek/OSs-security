#!/usr/bin/env bash

# ==============================================================================
# Module CIS - Configuration utilisateurs
# ==============================================================================

# CIS 5.8 - Disable automatic login
disable_automatic_login() {
    info "CIS 5.8 - Disabling automatic login"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    execute "defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || true"
    
}

# CIS 5.9 - Require a password to wake the computer from sleep or screen saver
require_password_wake() {
    info "CIS 5.9 - Requiring password on wake"
    
    backup_file "$HOME/Library/Preferences/com.apple.screensaver.plist"
    
    execute "defaults write com.apple.screensaver askForPassword -int 1"
    execute "defaults write com.apple.screensaver askForPasswordDelay -int 0"
    
}

# CIS 5.11 - Require an administrator password to access system-wide preferences
require_admin_system_prefs() {
    info "CIS 5.11 - Requiring admin password for system preferences"
    
    execute "security authorizationdb read system.preferences > /tmp/system.preferences.plist"
    execute "defaults write /tmp/system.preferences.plist shared -bool false"
    execute "security authorizationdb write system.preferences < /tmp/system.preferences.plist"
    execute "rm /tmp/system.preferences.plist"
    
}

# CIS 5.12 - Disable ability to login to another user's active and locked session
disable_fast_user_switching() {
    info "CIS 5.12 - Disabling fast user switching"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    execute "defaults write /Library/Preferences/.GlobalPreferences MultipleSessionEnabled -bool false"
    
}

# CIS 5.13 - Create a custom message for the Login Screen
set_login_message() {
    info "CIS 5.13 - Setting login screen message"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    local login_message="This system is for authorized users only. All activity is logged and monitored."
    execute "defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText '$login_message'"
    
}


# CIS 5.15 - Do not enter a password-based screensaver mode
disable_password_screensaver_mode() {
    info "CIS 5.15 - Configuring screensaver password mode"
    
    backup_file "$HOME/Library/Preferences/com.apple.screensaver.plist"
    
    execute "defaults write com.apple.screensaver askForPassword -int 1"
    
}

# CIS 6.1.1 - Display login window as name and password
configure_login_window_style() {
    info "CIS 6.1.1 - Configuring login window style"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    execute "defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true"
    
}

# CIS 6.1.2 - Disable "Show password hints"
disable_password_hints() {
    info "CIS 6.1.2 - Disabling password hints"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    execute "defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0"
    
}

# CIS 6.1.3 - Disable guest account login
disable_guest_account() {
    info "CIS 6.1.3 - Disabling guest account"
    
    backup_file "/Library/Preferences/com.apple.loginwindow.plist"
    
    execute "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"
    execute "sysadminctl -guestAccount off 2>/dev/null || true"
    
}

# CIS 6.1.4 - Disable "Allow guests to connect to shared folders"
disable_guest_shared_folders() {
    info "CIS 6.1.4 - Disabling guest access to shared folders"
    
    backup_file "/Library/Preferences/com.apple.AppleFileServer.plist"
    backup_file "/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist"
    
    execute "defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false"
    execute "defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false"
    
}

# CIS 6.1.5 - Remove Guest home folder
remove_guest_home() {
    info "CIS 6.1.5 - Removing guest home folder"
    
    execute "rm -rf /Users/Guest" || true
    
}

# CIS 6.2 - Turn on filename extensions
show_filename_extensions() {
    info "CIS 6.2 - Showing filename extensions"
    
    backup_file "$HOME/Library/Preferences/.GlobalPreferences.plist"
    
    execute "defaults write NSGlobalDomain AppleShowAllExtensions -bool true"
    
}

# CIS 6.3 - Disable the automatic run of safe files in Safari
disable_safari_safe_files() {
    info "CIS 6.3 - Disabling Safari automatic safe file opening"
    
    backup_file "$HOME/Library/Preferences/com.apple.Safari.plist"
    
    execute "defaults write com.apple.Safari AutoOpenSafeDownloads -bool false"
    
}
