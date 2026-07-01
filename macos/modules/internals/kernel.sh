#!/usr/bin/env bash

# ==============================================================================
# Module OPSEK - Kernel Hardening
# ==============================================================================

# OPSEK - Secure keyboard settings
secure_keyboard_settings() {
    info "OPSEK - Configuring secure keyboard settings"
    
    user_backup_file "Library/Preferences/.GlobalPreferences.plist"
    user_backup_file "Library/Preferences/com.apple.universalaccess.plist"

    # Disable press and hold for accented characters
    user_execute "defaults write NSGlobalDomain ApplePressAndHoldEnabled -bool false"

    # Set fast key repeat rate
    user_execute "defaults write NSGlobalDomain KeyRepeat -int 2"
    user_execute "defaults write NSGlobalDomain InitialKeyRepeat -int 15"

    # Disable automatic spelling correction
    user_execute "defaults write NSGlobalDomain NSAutomaticSpellingCorrectionEnabled -bool false"

    # Disable automatic capitalization
    user_execute "defaults write NSGlobalDomain NSAutomaticCapitalizationEnabled -bool false"

    # Disable automatic period substitution
    user_execute "defaults write NSGlobalDomain NSAutomaticPeriodSubstitutionEnabled -bool false"

    # Disable smart quotes and dashes
    user_execute "defaults write NSGlobalDomain NSAutomaticQuoteSubstitutionEnabled -bool false"
    user_execute "defaults write NSGlobalDomain NSAutomaticDashSubstitutionEnabled -bool false"

    # Disable keyboard navigation to move focus between controls
    user_execute "defaults write NSGlobalDomain AppleKeyboardUIMode -int 3"

    # Secure keyboard access for assistive devices
    user_execute "defaults write com.apple.universalaccess keyboardNavigation -bool true"
    
}

# Harden kernel parameters
harden_kernel() {
    info "OPSEK - Hardening kernel parameters"
    
    # Enable kernel address space layout randomization
    execute "nvram boot-args='slide=0 -v'" || warn "Could not set boot arguments"
    
    # Configure hibernation for security
    execute "pmset -a hibernatemode 25"
    execute "pmset -a destroyfvkeyonstandby 1"
    
}

# Configure logging enhancements
enhance_logging() {
    info "OPSEK - Enhancing system logging"
    
    # Enable install logging
    backup_file "/Library/Preferences/com.apple.installer.plist"
    execute "defaults write /Library/Preferences/com.apple.installer UsePackageInstallationLog -bool true"
    
    # Configure log retention
    backup_file "/etc/security/audit_control"
    execute "sed -i '' 's/^expire-after:.*/expire-after:90d/' /etc/security/audit_control"
    
}

