#!/usr/bin/env bash

# ==============================================================================
# Module OPSEK - Bluetooth Management
# ==============================================================================

# OPSEK - Completely disable Bluetooth
disable_bluetooth_completely() {
    info "OPSEK - Completely disabling Bluetooth"
    
    backup_file "/Library/Preferences/com.apple.Bluetooth.plist"
    backup_file "$HOME/Library/Preferences/com.apple.Bluetooth.plist"
    backup_file "$HOME/Library/Preferences/ByHost/com.apple.Bluetooth.plist"
    
    execute "defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0"
    execute "launchctl unload -w /System/Library/LaunchDaemons/com.apple.blued.plist 2>/dev/null || true"
    execute "nvram bluetoothHostControllerSwitchBehavior=never"
    execute "defaults write com.apple.Bluetooth PrefKeyServicesEnabled -bool false"
    execute "defaults write ~/Library/Preferences/ByHost/com.apple.Bluetooth PowerEnabled -bool false"
    
}

# Enhanced OPSEK function to disable all Bluetooth services
disable_all_bluetooth_services() {
    info "OPSEK - Disabling all Bluetooth services and daemons"
    
    local bluetooth_services=(
        "com.apple.bluetoothReporter"
        "com.apple.bluetoothaudiod"
        "com.apple.BluetoothReporter"
        "com.apple.bluetooth.cupsd"
    )
    
    for service in "${bluetooth_services[@]}"; do
        execute "launchctl unload -w /System/Library/LaunchDaemons/$service.plist 2>/dev/null || true"
        execute "launchctl unload -w /System/Library/LaunchAgents/$service.plist 2>/dev/null || true"
    done
    
    # Disable Bluetooth kernel extension
    execute "kextunload /System/Library/Extensions/IOBluetoothFamily.kext 2>/dev/null || true"
    
}

