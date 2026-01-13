#!/usr/bin/env bash

# ==============================================================================
# CIS Module - System services
# ==============================================================================

# CIS 2.4.1 - Disable Remote Apple Events
disable_remote_apple_events() {
    info "CIS 2.4.1 - Disabling Remote Apple Events"
    info "You can skip this step if the system is already secured by default (Remote Apple Events no longer exists on newer Mac models)."
    execute "systemsetup -setremoteappleevents off"
    

}

# CIS 2.4.2 - Disable Internet Sharing
disable_internet_sharing() {
    info "CIS 2.4.2 - Disabling Internet Sharing"
    
    backup_file "/Library/Preferences/SystemConfiguration/com.apple.nat.plist"
    
    execute "defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict Enabled -int 0"

}

# CIS 2.4.3 - Disable Screen Sharing
disable_screen_sharing() {
    info "CIS 2.4.3 - Disabling Screen Sharing"
    
    execute "launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null || true"
}

# CIS 2.4.4 - Disable Printer Sharing
disable_printer_sharing() {
    info "CIS 2.4.4 - Disabling Printer Sharing"
    info "Printer Sharing can be disabled by default, skip if command failed"
    execute "cupsctl --no-share-printers"
    execute "launchctl unload -w /System/Library/LaunchDaemons/org.cups.cupsd.plist 2>/dev/null || true"

}


# CIS 2.4.6 - Disable File Sharing
disable_file_sharing() {
    info "CIS 2.4.6 - Disabling File Sharing"
    
    execute "launchctl unload -w /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist 2>/dev/null || true"
    execute "launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist 2>/dev/null || true"
    
}

# CIS 2.4.8 - Disable Remote Management
disable_remote_management() {
    info "CIS 2.4.8 - Disabling Remote Management"
    
    execute "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop 2>/dev/null || true"
    
}

# CIS 2.5.1 - Disable "Wake for network access"
disable_wake_on_lan() {
    info "CIS 2.5.1 - Disabling Wake for network access"
    
    execute "pmset -a womp 0"
    
}

# CIS 2.11 - Disabling AirDrop
disable_airdrop() {
    info "CIS 2.11 - Disabling AirDrop"
    
    backup_file "$HOME/Library/Preferences/com.apple.NetworkBrowser.plist"
    
    execute "defaults write com.apple.NetworkBrowser DisableAirDrop -bool true"

}

# CIS 4.1 - Disable Bonjour advertising service
disable_bonjour() {
    info "CIS 4.1 - Disabling Bonjour advertising"
    
    backup_file "/Library/Preferences/com.apple.mDNSResponder.plist"
    
    execute "defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true"

}

# CIS 4.2 - Ensure HTTP server is not running
disable_http_server() {
    info "CIS 4.2 - Ensuring HTTP server is not running"
    
    execute "launchctl unload -w /System/Library/LaunchDaemons/org.apache.httpd.plist 2>/dev/null || true"

}

# CIS 4.4 - Ensure NFS server is not running
disable_nfs_server() {
    info "CIS 4.4 - Disabling NFS server"
    
    execute "launchctl unload -w /System/Library/LaunchDaemons/com.apple.nfsd.plist 2>/dev/null || true"

}
