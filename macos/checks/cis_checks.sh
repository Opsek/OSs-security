#!/usr/bin/env bash

# ==============================================================================
# CIS Compliance Check Functions
# ==============================================================================

# CIS compliance check for FileVault
cis_check_filevault() {
    info "Checking FileVault compliance"
    
    if fdesetup status | grep -q "FileVault is On"; then
        success "✓ CIS 2.6.1 - FileVault is enabled"
        return 0
    else
        warn "✗ CIS 2.6.1 - FileVault is not enabled"
        return 1
    fi
}

# CIS compliance check for Firewall
cis_check_firewall() {
    info "Checking Firewall compliance"
    
    if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -q "Firewall is enabled"; then
        success "✓ CIS 2.7.1 - Firewall is enabled"
        return 0
    else
        warn "✗ CIS 2.7.1 - Firewall is not enabled"
        return 1
    fi
}

# CIS compliance check for Gatekeeper
cis_check_gatekeeper() {
    info "Checking Gatekeeper compliance"
    
    if spctl --status | grep -q "assessments enabled"; then
        success "✓ CIS 2.8 - Gatekeeper is enabled"
        return 0
    else
        warn "✗ CIS 2.8 - Gatekeeper is not enabled"
        return 1
    fi
}

# CIS compliance check for Remote Services
cis_check_remote_services() {
    info "Checking remote services compliance"
    
    local issues=0
    
    # Check SSH
    if systemsetup -getremotelogin | grep -q "Remote Login: Off"; then
        success "✓ CIS 2.4.5 - SSH is disabled"
    else
        warn "✗ CIS 2.4.5 - SSH is enabled"
        ((issues++))
    fi
    
    # Check Screen Sharing
    if ! launchctl list | grep -q "com.apple.screensharing"; then
        success "✓ CIS 2.4.3 - Screen Sharing is disabled"
    else
        warn "✗ CIS 2.4.3 - Screen Sharing is enabled"
        ((issues++))
    fi
    
    # Check Remote Apple Events
    if systemsetup -getremoteappleevents | grep -q "Remote Apple Events: Off"; then
        success "✓ CIS 2.4.1 - Remote Apple Events disabled"
    else
        warn "✗ CIS 2.4.1 - Remote Apple Events enabled"
        ((issues++))
    fi
    
    return $issues
}

# CIS compliance check for User Settings
cis_check_user_settings() {
    info "Checking user settings compliance"
    
    local issues=0
    
    # Check automatic login
    if ! defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null; then
        success "✓ CIS 5.8 - Automatic login is disabled"
    else
        warn "✗ CIS 5.8 - Automatic login is enabled"
        ((issues++))
    fi
    
    # Check guest account
    if defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null | grep -q "0"; then
        success "✓ CIS 6.1.3 - Guest account is disabled"
    else
        warn "✗ CIS 6.1.3 - Guest account is enabled"
        ((issues++))
    fi
    
    # Check password screensaver
    if defaults read com.apple.screensaver askForPassword 2>/dev/null | grep -q "1"; then
        success "✓ CIS 5.9 - Password required for screensaver"
    else
        warn "✗ CIS 5.9 - Password not required for screensaver"
        ((issues++))
    fi
    
    return $issues
}
