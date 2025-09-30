#!/usr/bin/env bash

# ==============================================================================
# OPSEK Compliance Checks Module
# ==============================================================================

# OPSEK compliance check for Bluetooth
opsek_check_bluetooth() {
    info "Checking OPSEK Bluetooth compliance"
    
    if defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null | grep -q "0"; then
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

# OPSEK compliance check for Lockdown Mode
opsek_check_lockdown_mode() {
    info "Checking OPSEK Lockdown Mode compliance"
    
    if [[ "$ENABLE_LOCKDOWN" != true ]]; then
        info "→ OPSEK - Lockdown Mode was not requested (use --lockdown)"
        return 0
    fi
    
    if defaults read com.apple.Safari LockdownModeEnabled 2>/dev/null | grep -q "1"; then
        success "✓ OPSEK - Lockdown Mode settings are enabled"
        return 0
    else
        warn "✗ OPSEK - Lockdown Mode settings are not enabled"
        return 1
    fi
}

# OPSEK compliance check for keyboard security
opsek_check_keyboard_security() {
    info "Checking OPSEK keyboard security compliance"
    
    local issues=0
    
    # Check if automatic spelling correction is disabled
    if defaults read NSGlobalDomain NSAutomaticSpellingCorrectionEnabled 2>/dev/null | grep -q "0"; then
        success "✓ OPSEK - Automatic spelling correction disabled"
    else
        warn "✗ OPSEK - Automatic spelling correction enabled"
        ((issues++))
    fi
    
    # Check if automatic capitalization is disabled
    if defaults read NSGlobalDomain NSAutomaticCapitalizationEnabled 2>/dev/null | grep -q "0"; then
        success "✓ OPSEK - Automatic capitalization disabled"
    else
        warn "✗ OPSEK - Automatic capitalization enabled"
        ((issues++))
    fi
    
    return $issues
}
