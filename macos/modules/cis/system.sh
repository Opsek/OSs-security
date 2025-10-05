#!/usr/bin/env bash

# ==============================================================================
# CIS Module - System configuration
# ==============================================================================

# CIS 1.1 - Verify all Apple provided software is current
update_system() {
    info "CIS 1.1 - Configuring automatic software updates"
    
    backup_file "/Library/Preferences/com.apple.SoftwareUpdate.plist"
    
    execute "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true"
    execute "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true"
    execute "defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true"
    execute "defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true"
    execute "defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true"
    
    success "Automatic updates configured"
}

# CIS 2.2.2 - Ensure time set is within appropriate limits
configure_time_sync() {
    info "CIS 2.2.2 - Configuring network time synchronization"
    
    execute "systemsetup -setusingnetworktime on"
    execute "systemsetup -setnetworktimeserver time.apple.com"
    
    success "Network time synchronization configured"
}

# CIS 2.3.1 - Set an inactivity interval of 20 minutes or less for the screen saver
configure_screensaver() {
    info "CIS 2.3.1 - Configuring screen saver timeout"
    
    backup_file ~/Library/Preferences/com.apple.screensaver.plist
    
    execute "defaults write com.apple.screensaver askForPassword -int 1"
    execute "defaults write com.apple.screensaver askForPasswordDelay -int 0"
    execute "defaults write com.apple.screensaver idleTime -int 1200"
    
    success "Screen saver timeout configured to 20 minutes"
}


# CIS 2.6.1 - Enable FileVault
enable_filevault() {
    info "CIS 2.6.1 - Checking FileVault status"
    
    if fdesetup status | grep -q "FileVault is On"; then
        success "FileVault is already enabled"
    else
        warn "FileVault is not enabled"
        warn "FileVault must be enabled manually via System Preferences > Security & Privacy"
        warn "Refer to https://support.apple.com/en-us/HT204837 for instructions"
    fi
}

# CIS 2.7.1 - Turn on Firewall
enable_firewall() {
    info "CIS 2.7.1 - Enabling Application Firewall"
    info "You can skip this step if the system is already secured by default (socketfilterfw no longer exists on newer Mac models)."

    execute "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
    execute "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
    execute "/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off"
    execute "/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off"
    execute "/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on"
    success "Application Firewall enabled and configured"
}

# CIS 2.8 - Enable Gatekeeper
enable_gatekeeper() {
    info "CIS 2.8 - Enabling Gatekeeper"
    
    execute "spctl --master-enable"
    
    success "Gatekeeper enabled"
}

# CIS 2.9 - Enable Security Auditing
enable_security_auditing() {
    info "CIS 2.9 - Enabling Security Auditing"
    
    backup_file "/etc/security/audit_control"
    
    execute "launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true"
    
    # Configure audit flags
    if [[ -f /etc/security/audit_control ]]; then
        execute "sed -i '' 's/^flags:.*/flags:lo,aa/' /etc/security/audit_control"
    fi
    
    success "Security auditing enabled"
}

# CIS 2.10 - Configure Security Auditing Flags
configure_audit_flags() {
    info "CIS 2.10 - Configuring audit flags"
    
    backup_file "/etc/security/audit_control"
    
    cat > /tmp/audit_control << 'EOF'
#
# $P4: //depot/projects/trustedbsd/openbsm/etc/audit_control#8 $
#
dir:/var/audit
flags:lo,aa
minfree:25
naflags:lo,aa
policy:cnt,argv
filesz:2M
expire-after:10G
superuser-set-sflags-mask:has_authenticated,has_console_access
superuser-clear-sflags-mask:has_authenticated,has_console_access
member-set-sflags-mask:
member-clear-sflags-mask:has_authenticated
EOF
    
    execute "cp /tmp/audit_control /etc/security/audit_control"
    execute "rm /tmp/audit_control"
    
    success "Audit flags configured"
}

# CIS 3.1 - Enable security auditing
enable_audit_logs() {
    info "CIS 3.1 - Ensuring audit logs are enabled"
    
    execute "launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true"
    
    success "Audit logs enabled"
}

# CIS 3.2 - Configure Security Auditing Flags
configure_security_auditing() {
    info "CIS 3.2 - Configuring security auditing flags"
    
    backup_file "/etc/security/audit_control"
    
    # Set appropriate audit flags
    execute "sed -i '' 's/^flags:.*/flags:lo,aa,ad,fd,fm,-all/' /etc/security/audit_control"
    
    success "Security auditing flags configured"
}

# CIS 3.3 - Ensure security auditing retention
configure_audit_retention() {
    info "CIS 3.3 - Configuring audit log retention"
    
    backup_file "/etc/security/audit_control"
    
    execute "sed -i '' 's/^expire-after:.*/expire-after:60d OR 10G/' /etc/security/audit_control"
    
    success "Audit log retention configured"
}

# CIS 5.10 - Ensure system is set to hibernate
configure_hibernate_mode() {
    info "CIS 5.10 - Configuring hibernate mode"
    
    execute "pmset -a standby 1"
    execute "pmset -a standbydelay 7200"
    execute "pmset -a hibernatemode 25"
    
    success "Hibernate mode configured"
}

# CIS 5.18 - System Integrity Protection status
verify_sip() {
    info "CIS 5.18 - Verifying System Integrity Protection"
    
    if csrutil status | grep -q "System Integrity Protection status: enabled"; then
        success "System Integrity Protection is enabled"
    else
        warn "System Integrity Protection is not fully enabled"
    fi
}
