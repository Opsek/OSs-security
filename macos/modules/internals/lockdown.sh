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
    
    # Backup files before modification (read from the real user's home)
    user_backup_file "Library/Preferences/com.apple.Safari.plist"
    user_backup_file "Library/Preferences/com.apple.WebKit.plist"
    user_backup_file "Library/Preferences/.GlobalPreferences.plist"
    user_backup_file "Library/Preferences/com.apple.Messages.plist"
    user_backup_file "Library/Preferences/com.apple.facetime.plist"

    # Enable Lockdown Mode via defaults
    user_execute "defaults write com.apple.Safari LockdownModeEnabled -bool true"
    user_execute "defaults write com.apple.WebKit LockdownModeEnabled -bool true"

    # Additional Lockdown Mode configurations
    user_execute "defaults write NSGlobalDomain LockdownModeEnabled -bool true"

    # Disable JIT compilation in Safari
    user_execute "defaults write com.apple.Safari JavaScriptEnabled -bool false"
    user_execute "defaults write com.apple.Safari WebKitJavaEnabled -bool false"
    user_execute "defaults write com.apple.Safari WebKitPluginsEnabled -bool false"

    # Disable complex web technologies
    user_execute "defaults write com.apple.Safari WebGL2Enabled -bool false"
    user_execute "defaults write com.apple.Safari WebGLEnabled -bool false"

    # Restrict font loading
    user_execute "defaults write com.apple.Safari WebKitSuppressesIncrementalRenderingDuringLoading -bool true"

    # Disable preview attachments in Messages
    user_execute "defaults write com.apple.Messages EnablePersistentConversions -bool false"
    user_execute "defaults write com.apple.Messages LoadRemoteContent -bool false"

    # Disable FaceTime calls from unknown numbers
    user_execute "defaults write com.apple.facetime blockUnknownCallers -bool true"

    # IMPORTANT: Apple's actual Lockdown Mode cannot be toggled from the command
    # line or via defaults. The keys above only configure related, compatible
    # hardening. The real toggle lives in System Settings and must be turned on
    # by the user, after which a restart is required. The audit reflects this:
    # it reports Lockdown Mode as off until it is enabled there.
    warn "Apple Lockdown Mode itself must be turned on manually in System Settings > Privacy & Security, then restart."
    warn "This step applied the related, compatible hardening only."
    
    success "Lockdown Mode compatible settings enabled"
}

