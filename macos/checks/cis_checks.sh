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
        # Critical control: emit as a failure (not a warning) so disk
        # encryption being off is reflected in the score, not half-credited.
        error "✗ CIS 2.6.1 - FileVault is not enabled"
        return 1
    fi
}

# CIS compliance check for Firewall
cis_check_firewall() {
    info "Checking Firewall compliance"

    # macOS 15+ prints "blocking all non-essential" in block-all mode, not
    # "Firewall is enabled". Match every on variant; only "disabled" fails.
    if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null \
        | grep -Eqi "firewall is enabled|blocking all non-essential|set to block all"; then
        success "✓ CIS 2.7.1 - Firewall is enabled"
        return 0
    else
        error "✗ CIS 2.7.1 - Firewall is not enabled"
        return 1
    fi
}

# CIS compliance check for Firewall hardening (stealth mode + block all incoming)
# The plain firewall check above only confirms it is ON. The feedback showed a
# firewall that was on but with stealth mode and "block all incoming" not set,
# which the audit did not flag. This catches that.
cis_check_firewall_hardening() {
    info "Checking Firewall stealth mode and block-all-incoming"

    local fw="/usr/libexec/ApplicationFirewall/socketfilterfw"
    local issues=0

    if [[ ! -x "$fw" ]]; then
        info "→ CIS 2.7 - socketfilterfw not present on this build, skipping stealth/block-all check"
        return 0
    fi

    # Stealth mode only matters while the firewall is on: macOS keeps the stealth
    # preference set even after the firewall is turned off, which made this report
    # a false pass. Gate it on the firewall actually being enabled.
    local fw_on=false
    if "$fw" --getglobalstate 2>/dev/null | grep -Eqi "firewall is enabled|blocking all non-essential|set to block all"; then
        fw_on=true
    fi

    # Modern: "stealth mode is on"; legacy: "Stealth mode enabled".
    if [[ "$fw_on" == true ]] && "$fw" --getstealthmode 2>/dev/null | grep -Eqi "stealth mode is on|stealth mode enabled"; then
        success "✓ CIS 2.7.2 - Firewall stealth mode is enabled"
    elif [[ "$fw_on" != true ]]; then
        warn "✗ CIS 2.7.2 - Firewall stealth mode is off (the firewall itself is disabled)"
        issues=$((issues+1))
    else
        warn "✗ CIS 2.7.2 - Firewall stealth mode is not enabled"
        issues=$((issues+1))
    fi

    # Block-all is an optional, Paranoid-only control because it breaks AirDrop,
    # printer and file sharing. Off is the intended state for the Recommended
    # profile, so report it as info (neutral), never a failure.
    if "$fw" --getblockall 2>/dev/null | grep -Eqi "blocking all non-essential|set to block all"; then
        success "✓ CIS 2.7.3 - Firewall blocks all incoming connections"
    else
        info "→ CIS 2.7.3 - Block all incoming is off (intended for Recommended; the Paranoid profile turns it on)"
    fi

    return $issues
}

# CIS compliance check for pending software updates.
# Uses the cached LastUpdatesAvailable count so the check stays instant and
# offline. The feedback flagged that an outdated macOS/Safari was not surfaced.
cis_check_software_updates() {
    info "Checking for pending software updates"

    local pending
    pending="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate LastUpdatesAvailable 2>/dev/null)"

    if [[ -z "$pending" ]]; then
        info "→ CIS 1.1 - Update status unknown (no cached update count). Open Software Update to refresh."
        return 0
    fi

    if [[ "$pending" -eq 0 ]] 2>/dev/null; then
        success "✓ CIS 1.1 - No pending software updates"
        return 0
    else
        # Informational, not scored: a detected pending update is real system
        # state that a snapshot restore cannot undo (you cannot un-detect an
        # available update), so counting it against the score would make the
        # score fail to return to baseline after a restore. The user still sees
        # it and can install from System Settings.
        info "→ CIS 1.1 - $pending pending software update(s) available; install from System Settings (not counted in the score)"
        return 0
    fi
}

# CIS compliance check for screen-lock password settings (per user).
# Reads the real state via `sysadminctl -screenLock status`; the old
# com.apple.screensaver askForPassword keys are inert on macOS 13+.
cis_check_lockscreen() {
    info "Checking lock screen password settings"

    local issues=0
    local status
    status="$(user_screenlock_status 2>/dev/null)"

    if [[ -n "$status" ]]; then
        if echo "$status" | grep -qi "screenLock is off"; then
            warn "✗ CIS 5.9 - Screen lock is off: a password is not required after the screen saver or display turns off"
            issues=$((issues+1))
        elif echo "$status" | grep -qi "screenLock delay is immediate"; then
            success "✓ CIS 5.9 - Screen lock requires a password immediately"
        elif echo "$status" | grep -Eqi "screenLock delay is [0-9]+ seconds"; then
            local secs
            secs="$(echo "$status" | grep -Eo "[0-9]+ seconds" | grep -Eo "[0-9]+")"
            if [[ -n "$secs" && "$secs" -le 5 ]] 2>/dev/null; then
                success "✓ CIS 5.9 - Screen lock password delay is short ($secs seconds)"
            else
                warn "✗ CIS 5.9 - Screen lock password delay is too long (${secs:-unknown} seconds); set it to Immediately"
                issues=$((issues+1))
            fi
        else
            warn "✗ CIS 5.9 - Screen lock state could not be read; verify manually in System Settings > Lock Screen"
            issues=$((issues+1))
        fi
        return $issues
    fi

    # Fallback when no console user resolved (e.g. an SSH-only audit).
    local ask delay
    ask="$(user_defaults_read com.apple.screensaver askForPassword 2>/dev/null)"
    delay="$(user_defaults_read com.apple.screensaver askForPasswordDelay 2>/dev/null)"

    # Keep delay numeric: it comes from the user's defaults domain, and a
    # non-numeric value in the -le arithmetic context would be evaluated.
    if [[ "$ask" == "1" && "$delay" =~ ^[0-9]+$ ]] && (( delay <= 5 )); then
        success "✓ CIS 5.9 - Screen lock password appears required (legacy read, confirm in System Settings > Lock Screen)"
    else
        warn "✗ CIS 5.9 - Screen lock could not be confirmed; set Require password to Immediately in System Settings > Lock Screen"
        issues=$((issues+1))
    fi

    return $issues
}

# CIS compliance check: require an administrator password for system-wide settings.
cis_check_admin_required() {
    info "Checking admin password requirement for system settings"

    local shared
    shared="$(security authorizationdb read system.preferences 2>/dev/null | plutil -extract shared raw - 2>/dev/null)"

    if [[ "$shared" == "false" ]]; then
        success "✓ CIS 5.11 - Administrator password required for system-wide settings"
        return 0
    else
        warn "✗ CIS 5.11 - Administrator password is not required for system-wide settings"
        return 1
    fi
}

# CIS compliance check: show all filename extensions (per user).
cis_check_file_extensions() {
    info "Checking filename extension visibility"

    local show
    show="$(user_defaults_read NSGlobalDomain AppleShowAllExtensions 2>/dev/null)"

    if [[ "$show" == "1" ]]; then
        success "✓ CIS 6.2 - All filename extensions are shown"
        return 0
    else
        warn "✗ CIS 6.2 - All filename extensions are not shown"
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
        error "✗ CIS 2.8 - Gatekeeper is not enabled"
        return 1
    fi
}

# CIS compliance check for Remote Services
cis_check_remote_services() {
    info "Checking remote services compliance"
    
    local issues=0
    
    # Check SSH (remote login). systemsetup -getremotelogin needs Full Disk
    # Access and fails under the GUI's root-without-FDA context, returning an
    # admin error that is easily misread as "SSH enabled". The sshd launchd job
    # state is readable without FDA and reflects the same on/off.
    if launchctl print system/com.openssh.sshd >/dev/null 2>&1; then
        warn "✗ CIS 2.4.5 - SSH is enabled"
        issues=$((issues+1))
    else
        success "✓ CIS 2.4.5 - SSH is disabled"
    fi
    
    # Check Screen Sharing
    if ! launchctl list | grep -q "com.apple.screensharing"; then
        success "✓ CIS 2.4.3 - Screen Sharing is disabled"
    else
        warn "✗ CIS 2.4.3 - Screen Sharing is enabled"
        issues=$((issues+1))
    fi
    
    # Check Remote Apple Events. Capture stderr too and branch explicitly: any
    # output that is neither "On" nor "Off" (a systemsetup error, or the feature
    # being absent on newer Mac models) is reported as not-applicable rather than
    # a false "enabled".
    local rae
    rae="$(systemsetup -getremoteappleevents 2>&1)"
    if echo "$rae" | grep -qi "remote apple events: on"; then
        warn "✗ CIS 2.4.1 - Remote Apple Events enabled"
        issues=$((issues+1))
    elif echo "$rae" | grep -qi "remote apple events: off"; then
        success "✓ CIS 2.4.1 - Remote Apple Events disabled"
    else
        info "→ CIS 2.4.1 - Remote Apple Events state unavailable (often not present on newer Macs)"
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
        issues=$((issues+1))
    fi
    
    # Check guest account
    if defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null | grep -q "0"; then
        success "✓ CIS 6.1.3 - Guest account is disabled"
    else
        warn "✗ CIS 6.1.3 - Guest account is enabled"
        issues=$((issues+1))
    fi
    
    # Password screensaver is covered in detail by cis_check_lockscreen (read
    # from the login user's domain, not root). Not repeated here to avoid a
    # duplicate, wrong-domain CIS 5.9 row.

    return $issues
}
