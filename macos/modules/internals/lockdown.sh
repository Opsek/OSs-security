#!/usr/bin/env bash

# ==============================================================================
# Module OPSEK - Lockdown Mode
# ==============================================================================

# OPSEK - Enable Lockdown Mode (macOS 13+) - Optional
enable_lockdown_mode() {
    info "OPSEK - Enabling Lockdown Mode"
    
    # Check if Lockdown Mode is available (macOS 13+)
    local os_version="$(sw_vers -productVersion)"
    local major_version="$(echo "$os_version" | cut -d. -f1)"
    
    if [[ $major_version -lt 13 ]]; then
        warn "Lockdown Mode requires macOS 13 or later (current: $os_version)"
        return 1
    fi
    
    # Backup files before modification
    backup_file "$HOME/Library/Preferences/com.apple.Safari.plist"
    backup_file "$HOME/Library/Preferences/com.apple.WebKit.plist"
    backup_file "$HOME/Library/Preferences/.GlobalPreferences.plist"
    backup_file "$HOME/Library/Preferences/com.apple.Messages.plist"
    backup_file "$HOME/Library/Preferences/com.apple.facetime.plist"
    
    # Enable Lockdown Mode via defaults
    execute "defaults write com.apple.Safari LockdownModeEnabled -bool true"
    execute "defaults write com.apple.WebKit LockdownModeEnabled -bool true"
    
    # Additional Lockdown Mode configurations
    execute "defaults write NSGlobalDomain LockdownModeEnabled -bool true"
    
    # Disable JIT compilation in Safari
    execute "defaults write com.apple.Safari JavaScriptEnabled -bool false"
    execute "defaults write com.apple.Safari WebKitJavaEnabled -bool false"
    execute "defaults write com.apple.Safari WebKitPluginsEnabled -bool false"
    
    # Disable complex web technologies
    execute "defaults write com.apple.Safari WebGL2Enabled -bool false"
    execute "defaults write com.apple.Safari WebGLEnabled -bool false"
    
    # Restrict font loading
    execute "defaults write com.apple.Safari WebKitSuppressesIncrementalRenderingDuringLoading -bool true"
    
    # Disable preview attachments in Messages
    execute "defaults write com.apple.Messages EnablePersistentConversions -bool false"
    execute "defaults write com.apple.Messages LoadRemoteContent -bool false"
    
    # Disable FaceTime calls from unknown numbers
    execute "defaults write com.apple.facetime blockUnknownCallers -bool true"
    
    # Note: Full Lockdown Mode requires manual activation in System Settings
    warn "Note: Complete Lockdown Mode must be manually activated in System Settings > Privacy & Security"
    warn "This function enables related security settings compatible with Lockdown Mode"
    
    success "Lockdown Mode compatible settings enabled"
}

