#!/usr/bin/env bash

# ==============================================================================
# Module OPSEK - Wi-Fi Management
# ==============================================================================

# OPSEK - Disable Wi-Fi
disable_wifi() {
    info "OPSEK - Disabling Wi-Fi"
    
    # Get all Wi-Fi interfaces
    local wifi_interfaces=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/ {getline; print $2}')
    
    for interface in $wifi_interfaces; do
        if [[ -n "$interface" ]]; then
            execute "networksetup -setairportpower '$interface' off"
            success "Wi-Fi disabled on interface: $interface"
        fi
    done
    
    # Backup files before modification
    backup_file "$HOME/Library/Preferences/com.apple.systemuiserver.plist"
    backup_file "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
    
    # Disable Wi-Fi menu bar icon
    execute "defaults write com.apple.systemuiserver 'NSStatusItem Visible com.apple.menu.airport' -bool false"
    
    # Prevent automatic joining of Wi-Fi networks
    execute "defaults write /Library/Preferences/SystemConfiguration/com.apple.airport.preferences DisableAssociation -bool true"
    
    # Disable Wi-Fi networking entirely
    execute "defaults write /Library/Preferences/SystemConfiguration/com.apple.airport.preferences AllowEnable -bool false"
    
    success "Wi-Fi completely disabled"
}

