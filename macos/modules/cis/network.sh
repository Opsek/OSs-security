#!/usr/bin/env bash

# ==============================================================================
# CIS Module - Network configuration
# ==============================================================================

# CIS 2.1.1 - Turn off Bluetooth "Discoverable" mode when not pairing devices
disable_bluetooth_discoverable() {
    info "CIS 2.1.1 - Disabling Bluetooth discoverable mode"
    
    backup_file "/Library/Preferences/com.apple.Bluetooth.plist"
    
    execute "defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0"
    execute "launchctl unload /System/Library/LaunchDaemons/com.apple.blued.plist 2>/dev/null || true"
}

# CIS 2.1.3 - Show Bluetooth status in menu bar
show_bluetooth_status() {
    info "CIS 2.1.3 - Showing Bluetooth status in menu bar"
    
    backup_file "$HOME/Library/Preferences/com.apple.systemuiserver.plist"
    
    execute "defaults write ~/Library/Preferences/com.apple.systemuiserver 'NSStatusItem Visible com.apple.menu.bluetooth' -bool true"
    execute "defaults write ~/Library/Preferences/com.apple.systemuiserver menuExtras -array-add '/System/Library/CoreServices/Menu Extras/Bluetooth.menu'"
    
}

# Service-related CIS functions are implemented in modules/cis/services.sh to avoid duplication.
