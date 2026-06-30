#!/usr/bin/env bash

# ==============================================================================
# Module OPSEK - Privacy Settings
# ==============================================================================

# Disable Siri and dictation
disable_siri_dictation() {
    info "OPSEK - Disabling Siri and dictation"
    
    user_backup_file "Library/Preferences/com.apple.assistant.support.plist"
    user_backup_file "Library/Preferences/com.apple.Siri.plist"
    user_backup_file "Library/Preferences/com.apple.speech.recognition.AppleSpeechRecognition.prefs.plist"

    user_execute "defaults write com.apple.assistant.support 'Assistant Enabled' -bool false"
    user_execute "defaults write com.apple.Siri StatusMenuVisible -bool false"
    user_execute "defaults write com.apple.Siri UserHasDeclinedEnable -bool true"
    user_execute "defaults write com.apple.speech.recognition.AppleSpeechRecognition.prefs DictationIMMasterDictationEnabled -bool false"
    
}

# Disable diagnostic and usage data
disable_diagnostics() {
    info "OPSEK - Disabling diagnostic and usage data"
    
    backup_file "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"
    
    execute "defaults write /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit -bool false"
    execute "defaults write /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist SeedAutoSubmit -bool false"
    
}

# Disable location services
disable_location_services() {
    info "OPSEK - Disabling location services"
    
    backup_file "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist"
    
    execute "defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false"
    
}

# Disable Spotlight suggestions
disable_spotlight_suggestions() {
    info "OPSEK - Disabling Spotlight suggestions"
    
    user_backup_file "Library/Preferences/com.apple.spotlight.plist"

    user_execute "defaults write com.apple.spotlight orderedItems -array \
        '{ enabled = 1; name = APPLICATIONS; }' \
        '{ enabled = 1; name = SYSTEM_PREFS; }' \
        '{ enabled = 1; name = DIRECTORIES; }' \
        '{ enabled = 1; name = PDF; }' \
        '{ enabled = 1; name = FONTS; }' \
        '{ enabled = 1; name = DOCUMENTS; }' \
        '{ enabled = 1; name = MESSAGES; }' \
        '{ enabled = 1; name = CONTACT; }' \
        '{ enabled = 1; name = EVENT_TODO; }' \
        '{ enabled = 1; name = IMAGES; }' \
        '{ enabled = 1; name = BOOKMARKS; }' \
        '{ enabled = 1; name = MUSIC; }' \
        '{ enabled = 1; name = MOVIES; }' \
        '{ enabled = 1; name = PRESENTATIONS; }' \
        '{ enabled = 1; name = SPREADSHEETS; }' \
        '{ enabled = 1; name = SOURCE; }' \
        '{ enabled = 0; name = MENU_DEFINITION; }' \
        '{ enabled = 0; name = MENU_OTHER; }' \
        '{ enabled = 0; name = MENU_CONVERSION; }' \
        '{ enabled = 0; name = MENU_EXPRESSION; }' \
        '{ enabled = 0; name = MENU_WEBSEARCH; }' \
        '{ enabled = 0; name = MENU_SPOTLIGHT_SUGGESTIONS; }'"
    
}

# Configure IPv6 settings
disable_ipv6_on_interfaces() {
    info "OPSEK - Disabling IPv6 on network interfaces"
    
    local interfaces=$(networksetup -listallnetworkservices | tail -n +2)
    while IFS= read -r interface; do
        if [[ "$interface" != *"*"* ]]; then
            execute "networksetup -setv6off '$interface'" || warn "Failed to disable IPv6 on $interface"
        fi
    done <<< "$interfaces"
    
}

# Secure Safari settings
secure_safari() {
    info "OPSEK - Securing Safari browser"
    
    user_backup_file "Library/Preferences/com.apple.Safari.plist"

    user_execute "defaults write com.apple.Safari WebKitJavaEnabled -bool false"
    user_execute "defaults write com.apple.Safari WebKitJavaScriptCanOpenWindowsAutomatically -bool false"
    user_execute "defaults write com.apple.Safari SafariGeolocationPermissionPolicy -int 0"
    user_execute "defaults write com.apple.Safari BlockStoragePolicy -int 1"
    user_execute "defaults write com.apple.Safari WebKitStorageBlockingPolicy -int 1"
    user_execute "defaults write com.apple.Safari SendDoNotTrackHTTPHeader -bool true"
    user_execute "defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool true"
    
}

# Disable unnecessary daemons
disable_unnecessary_daemons() {
    info "OPSEK - Disabling unnecessary daemons"
    
    local daemons=(
        "com.apple.netbiosd"
        "com.apple.dhcp6d"
        "com.apple.alf.useragent"
        "com.apple.AppleShareClientCore"
    )
    
    for daemon in "${daemons[@]}"; do
        execute "launchctl unload -w /System/Library/LaunchDaemons/$daemon.plist 2>/dev/null || true"
    done
    
}

# Configure system-wide privacy settings
configure_privacy_settings() {
    info "OPSEK - Configuring privacy settings"
    
    # Disable analytics
    backup_file "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"
    execute "defaults write /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist ThirdPartyDataSubmit -bool false"
    
    # Disable personalized ads
    user_backup_file "Library/Preferences/com.apple.AdLib.plist"
    user_execute "defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool false"
    user_execute "defaults write com.apple.AdLib allowIdentifierForAdvertising -bool false"

    # Disable Handoff (ByHost). Restart useractivityd so it takes effect now.
    user_backup_file "Library/Preferences/ByHost/com.apple.coreservices.useractivityd.plist"
    user_execute "defaults -currentHost write com.apple.coreservices.useractivityd ActivityAdvertisingAllowed -bool no"
    user_execute "defaults -currentHost write com.apple.coreservices.useractivityd ActivityReceivingAllowed -bool no"
    user_execute "killall useractivityd 2>/dev/null || true"

    # Disable the AirPlay receiver (ByHost). Restart Control Center to refresh.
    # Back up the ByHost controlcenter plist first so Restore reverts AirPlay (the
    # OPSEK audit reads this). The file carries a hardware-UUID suffix, so glob it.
    if [[ -n "$TARGET_HOME" ]]; then
        for _cc in "$TARGET_HOME"/Library/Preferences/ByHost/com.apple.controlcenter.*.plist; do
            [[ -f "$_cc" ]] && backup_file "$_cc"
        done
    fi
    user_execute "defaults -currentHost write com.apple.controlcenter AirplayRecieverEnabled -bool false"
    user_execute "killall ControlCenter 2>/dev/null || true"

}
