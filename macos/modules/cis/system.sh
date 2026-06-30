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
    
}

# CIS 2.2.2 - Ensure time set is within appropriate limits
configure_time_sync() {
    info "CIS 2.2.2 - Configuring network time synchronization"
    
    execute "systemsetup -setusingnetworktime on"
    execute "systemsetup -setnetworktimeserver time.apple.com"
    
}

# CIS 2.3.1 - Set an inactivity interval of 20 minutes or less for the screen saver
configure_screensaver() {
    info "CIS 2.3.1 - Configuring screen saver timeout"

    user_backup_file "Library/Preferences/com.apple.screensaver.plist"

    # Idle timeout lives in the ByHost domain (-currentHost); 1200s = 20 min.
    user_execute "defaults -currentHost write com.apple.screensaver idleTime -int 1200"

    # The password requirement (CIS 5.9) is not set here: the defaults keys are
    # inert on macOS 13+. See require_password_wake.
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

    local fw="/usr/libexec/ApplicationFirewall/socketfilterfw"
    if [[ ! -x "$fw" ]]; then
        warn "Application Firewall control (socketfilterfw) is not present on this macOS build; skipping."
        return 0
    fi

    # Firewall state for Restore is captured by snapshot_system_state into a
    # dedicated firewall_restore.sh (applied last in the rollback). We do NOT
    # back up com.apple.alf.plist: it is daemon-owned, and restoring it by cp
    # makes the firewall daemon re-sync and clobber the toggle.

    # Firewall on + stealth. Block-all is paranoid-only (see
    # enable_firewall_block_all): it breaks AirDrop and sharing.
    execute "$fw --setglobalstate on"
    execute "$fw --setstealthmode on"

    # Best-effort controls. Several socketfilterfw subcommands were removed or
    # renamed on newer macOS builds, so any one of them can fail. Treat these as
    # optional so the firewall still ends up on and stealthed.
    execute "$fw --setallowsigned off" || warn "socketfilterfw --setallowsigned not supported on this build (ignored)"
    execute "$fw --setallowsignedapp off" || warn "socketfilterfw --setallowsignedapp not supported on this build (ignored)"
    execute "$fw --setloggingmode on" || warn "socketfilterfw --setloggingmode not supported on this build (ignored)"

    return 0
}

# CIS 2.7.3 - Block all incoming connections (paranoid profile only).
# Aggressive: breaks AirDrop and sharing, so it is not in the recommended profile.
enable_firewall_block_all() {
    info "CIS 2.7.3 - Blocking all incoming connections (paranoid)"

    local fw="/usr/libexec/ApplicationFirewall/socketfilterfw"
    if [[ ! -x "$fw" ]]; then
        warn "Application Firewall control (socketfilterfw) is not present on this macOS build; skipping block-all."
        return 0
    fi

    # Firewall state (including block-all) is captured for Restore by
    # snapshot_system_state into firewall_restore.sh; the daemon-owned
    # com.apple.alf.plist is intentionally not backed up (see enable_firewall).

    # Ensure the firewall is on first, then block all non-essential incoming.
    execute "$fw --setglobalstate on"
    execute "$fw --setblockall on"

    return 0
}

# CIS 2.8 - Enable Gatekeeper
enable_gatekeeper() {
    info "CIS 2.8 - Enabling Gatekeeper"
    
    execute "spctl --master-enable"
    
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
    
}

# CIS 2.10 - Configure Security Auditing Flags
configure_audit_flags() {
    info "CIS 2.10 - Configuring audit flags"
    
    backup_file "/etc/security/audit_control"
    
    local temp_dir
    local audit_control_file
    temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/audit_control.XXXXXX")" || {
        warn "Could not create secure temporary directory for audit_control"
        return 1
    }
    chmod 700 "$temp_dir"
    audit_control_file="$temp_dir/audit_control"

    cat > "$audit_control_file" << 'EOF'
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
    
    execute "cp '$audit_control_file' /etc/security/audit_control"
    rm -rf "$temp_dir"
    
}

# CIS 3.1 - Enable security auditing
enable_audit_logs() {
    info "CIS 3.1 - Ensuring audit logs are enabled"
    
    execute "launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true"
    
}

# CIS 3.2 - Configure Security Auditing Flags
configure_security_auditing() {
    info "CIS 3.2 - Configuring security auditing flags"
    
    backup_file "/etc/security/audit_control"
    
    # Set appropriate audit flags
    execute "sed -i '' 's/^flags:.*/flags:lo,aa,ad,fd,fm,-all/' /etc/security/audit_control"
    
}

# CIS 3.3 - Ensure security auditing retention
configure_audit_retention() {
    info "CIS 3.3 - Configuring audit log retention"
    
    backup_file "/etc/security/audit_control"
    
    execute "sed -i '' 's/^expire-after:.*/expire-after:60d OR 10G/' /etc/security/audit_control"
    
}

# CIS 5.10 - Ensure system is set to hibernate
configure_hibernate_mode() {
    info "CIS 5.10 - Configuring hibernate mode"
    
    execute "pmset -a standby 1"
    execute "pmset -a standbydelay 7200"
    execute "pmset -a hibernatemode 25"
    
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
