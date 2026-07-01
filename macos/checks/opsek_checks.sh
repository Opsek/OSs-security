#!/usr/bin/env bash

# ==============================================================================
# OPSEK Compliance Checks Module
# ==============================================================================

# OPSEK compliance check for Bluetooth
opsek_check_bluetooth() {
    info "Checking OPSEK Bluetooth compliance"

    # Read the live controller state, which is what System Settings reflects. The
    # old check read the stale system ControllerPowerState key with an unanchored
    # grep "0", so it reported a false "disabled" while Bluetooth was actually on.
    local state
    state="$(system_profiler SPBluetoothDataType 2>/dev/null)"

    if echo "$state" | grep -Eqi "State: On|Bluetooth Power: On"; then
        warn "✗ OPSEK - Bluetooth is not disabled"
        return 1
    elif echo "$state" | grep -Eqi "State: Off|Bluetooth Power: Off"; then
        success "✓ OPSEK - Bluetooth is disabled"
        return 0
    fi

    # Fallback when system_profiler does not expose the state: require the system
    # power key to be exactly 0 AND the user ByHost power to be off or absent.
    local cps user_pe
    cps="$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null)"
    user_pe="$(user_defaults_read_currenthost com.apple.Bluetooth PowerEnabled 2>/dev/null)"
    if [[ "$cps" == "0" && ( -z "$user_pe" || "$user_pe" == "0" ) ]]; then
        success "✓ OPSEK - Bluetooth is disabled"
        return 0
    else
        warn "✗ OPSEK - Bluetooth is not disabled"
        return 1
    fi
}

# OPSEK compliance check for Wi-Fi
opsek_check_wifi() {
    info "Checking OPSEK Wi-Fi compliance"
    
    local wifi_interfaces=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/ {getline; print $2}')
    local wifi_disabled=true
    
    for interface in $wifi_interfaces; do
        if [[ -n "$interface" ]]; then
            if networksetup -getairportpower "$interface" | grep -q "On"; then
                wifi_disabled=false
                break
            fi
        fi
    done
    
    if [[ "$wifi_disabled" == true ]]; then
        success "✓ OPSEK - Wi-Fi is disabled"
        return 0
    else
        warn "✗ OPSEK - Wi-Fi is not disabled"
        return 1
    fi
}

# OPSEK compliance check for Lockdown Mode.
# Always evaluated now (the feedback noted Lockdown Mode being off was never
# flagged). Apple exposes no reliable read-only API for the real Lockdown Mode
# state, so we use the per-user Safari proxy key the hardening sets. Read it
# from the login user, not root.
opsek_check_lockdown_mode() {
    info "Checking OPSEK Lockdown Mode compliance"

    if user_defaults_read com.apple.Safari LockdownModeEnabled 2>/dev/null | grep -q "1"; then
        success "✓ OPSEK - Lockdown Mode settings are enabled"
        return 0
    else
        warn "✗ OPSEK - Lockdown Mode is not enabled (turn it on in System Settings > Privacy & Security, then restart)"
        return 1
    fi
}

# OPSEK compliance check for AirDrop, Handoff and the AirPlay receiver (per user).
# Reads the live OS state (sharingd DiscoverableMode, useractivityd, controlcenter)
# rather than OPSEK's own markers, so a change in System Settings shows on the scan.
opsek_check_airdrop_handoff() {
    info "Checking OPSEK AirDrop, Handoff and AirPlay compliance"

    local issues=0

    # AirDrop
    local mode
    mode="$(user_defaults_read com.apple.sharingd DiscoverableMode 2>/dev/null)"
    if [[ -n "$mode" ]]; then
        case "$mode" in
            Off)
                success "✓ OPSEK - AirDrop receiving is off"
                ;;
            "Contacts Only")
                warn "✗ OPSEK - AirDrop is discoverable by Contacts Only; set it to No One when not in use"
                issues=$((issues+1))
                ;;
            *)
                # Strip control bytes: log_message uses echo -e and $mode is
                # user-controlled.
                local mode_safe
                mode_safe="$(printf '%s' "$mode" | LC_ALL=C tr -d '[:cntrl:]')"
                warn "✗ OPSEK - AirDrop is discoverable ($mode_safe); set it to No One"
                issues=$((issues+1))
                ;;
        esac
    elif user_defaults_read com.apple.NetworkBrowser DisableAirDrop 2>/dev/null | grep -q "^1$"; then
        success "✓ OPSEK - AirDrop is disabled"
    else
        warn "✗ OPSEK - AirDrop is not disabled"
        issues=$((issues+1))
    fi

    # Absent keys mean enabled; off only when every scope reads an explicit 0.
    local handoff_off=true key val
    for key in ActivityReceivingAllowed ActivityAdvertisingAllowed; do
        val="$(user_defaults_read_currenthost com.apple.coreservices.useractivityd "$key" 2>/dev/null)"
        [[ -z "$val" ]] && val="$(user_defaults_read com.apple.coreservices.useractivityd "$key" 2>/dev/null)"
        [[ "$val" != "0" ]] && handoff_off=false
    done
    if [[ "$handoff_off" == true ]]; then
        success "✓ OPSEK - Handoff is disabled"
    else
        warn "✗ OPSEK - Handoff is not disabled"
        issues=$((issues+1))
    fi

    # AirPlay receiver
    local airplay
    airplay="$(user_defaults_read_currenthost com.apple.controlcenter AirplayRecieverEnabled 2>/dev/null)"
    if [[ "$airplay" == "0" ]]; then
        success "✓ OPSEK - AirPlay receiver is off"
    else
        warn "✗ OPSEK - AirPlay receiver is enabled"
        issues=$((issues+1))
    fi

    return $issues
}

# OPSEK compliance check for keyboard security
opsek_check_keyboard_security() {
    info "Checking OPSEK keyboard security compliance"
    
    local issues=0
    
    # Check if automatic spelling correction is disabled. Read the LOGIN USER's
    # domain (secure_keyboard_settings writes it via user_execute), not root's:
    # under the GUI's elevated run a bare `defaults read` hits /var/root and the
    # warning never cleared no matter how often Paranoid was applied.
    if user_defaults_read NSGlobalDomain NSAutomaticSpellingCorrectionEnabled 2>/dev/null | grep -q "0"; then
        success "✓ OPSEK - Automatic spelling correction disabled"
    else
        warn "✗ OPSEK - Automatic spelling correction enabled"
        issues=$((issues+1))
    fi

    # Check if automatic capitalization is disabled (login user's domain, as above).
    if user_defaults_read NSGlobalDomain NSAutomaticCapitalizationEnabled 2>/dev/null | grep -q "0"; then
        success "✓ OPSEK - Automatic capitalization disabled"
    else
        warn "✗ OPSEK - Automatic capitalization enabled"
        issues=$((issues+1))
    fi
    
    return $issues
}
