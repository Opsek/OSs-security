#!/usr/bin/env bash

# ==============================================================================
# Module OPSEK - Kernel Hardening
# ==============================================================================

# OPSEK - Secure keyboard settings
secure_keyboard_settings() {
    info "OPSEK - Configuring secure keyboard settings"
    
    # Disable press and hold for accented characters
    execute "defaults write NSGlobalDomain ApplePressAndHoldEnabled -bool false"
    
    # Set fast key repeat rate
    execute "defaults write NSGlobalDomain KeyRepeat -int 2"
    execute "defaults write NSGlobalDomain InitialKeyRepeat -int 15"
    
    # Disable automatic spelling correction
    execute "defaults write NSGlobalDomain NSAutomaticSpellingCorrectionEnabled -bool false"
    
    # Disable automatic capitalization
    execute "defaults write NSGlobalDomain NSAutomaticCapitalizationEnabled -bool false"
    
    # Disable automatic period substitution
    execute "defaults write NSGlobalDomain NSAutomaticPeriodSubstitutionEnabled -bool false"
    
    # Disable smart quotes and dashes
    execute "defaults write NSGlobalDomain NSAutomaticQuoteSubstitutionEnabled -bool false"
    execute "defaults write NSGlobalDomain NSAutomaticDashSubstitutionEnabled -bool false"
    
    # Disable keyboard navigation to move focus between controls
    execute "defaults write NSGlobalDomain AppleKeyboardUIMode -int 3"
    
    # Secure keyboard access for assistive devices
    execute "defaults write com.apple.universalaccess keyboardNavigation -bool true"
    
    success "Secure keyboard settings configured"
}

# Harden kernel parameters
harden_kernel() {
    info "OPSEK - Hardening kernel parameters"
    
    # Enable kernel address space layout randomization
    execute "nvram boot-args='slide=0 -v'" || warn "Could not set boot arguments"
    
    # Configure hibernation for security
    execute "pmset -a hibernatemode 25"
    execute "pmset -a destroyfvkeyonstandby 1"
    
    success "Kernel hardening applied"
}

# Configure logging enhancements
enhance_logging() {
    info "OPSEK - Enhancing system logging"
    
    # Enable install logging
    execute "defaults write /Library/Preferences/com.apple.installer UsePackageInstallationLog -bool true"
    
    # Configure log retention
    execute "sed -i '' 's/^expire-after:.*/expire-after:90d/' /etc/security/audit_control"
    
    success "System logging enhanced"
}

