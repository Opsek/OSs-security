#!/bin/bash

# MDM Policies for macOS Hardening
# This file contains all policy generation functions

# Configure password policy
add_password_policy() {
    local profile_type="$1"
    local min_length="$2"
    local min_complex="$3"
    local max_failed="$4"
    
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.mobiledevice.passwordpolicy</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.password.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Password Policy</string>
            <key>allowSimple</key>
            <false/>
            <key>forcePIN</key>
            <true/>
            <key>maxFailedAttempts</key>
            <integer>${max_failed}</integer>
            <key>maxPINAgeInDays</key>
            <integer>90</integer>
            <key>minComplexChars</key>
            <integer>${min_complex}</integer>
            <key>minLength</key>
            <integer>${min_length}</integer>
            <key>requireAlphanumeric</key>
            <true/>
        </dict>
EOF
}

# Configure screensaver/lock screen
add_screensaver_policy() {
    local idle_time="$1"
    
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.screensaver</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.screensaver.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Screensaver Policy</string>
            <key>askForPassword</key>
            <true/>
            <key>askForPasswordDelay</key>
            <integer>0</integer>
            <key>idleTime</key>
            <integer>${idle_time}</integer>
        </dict>
EOF
}

# Configure FileVault encryption
add_filevault_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCX.FileVault2</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.filevault.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>FileVault Configuration</string>
            <key>Enable</key>
            <string>On</string>
            <key>Defer</key>
            <false/>
            <key>UseRecoveryKey</key>
            <true/>
            <key>ShowRecoveryKey</key>
            <false/>
        </dict>
EOF
}

# Configure firewall
add_firewall_policy() {
    local stealth_mode="$1"
    
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.firewall</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.firewall.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Firewall Configuration</string>
            <key>EnableFirewall</key>
            <true/>
            <key>BlockAllIncoming</key>
            <false/>
            <key>EnableStealthMode</key>
            <${stealth_mode}/>
        </dict>
EOF
}

# Configure Gatekeeper
add_gatekeeper_policy() {
    local allowed_source="$1"
    
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.systempolicy.control</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.gatekeeper.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Gatekeeper Configuration</string>
            <key>EnableAssessment</key>
            <true/>
            <key>AllowIdentifiedDevelopers</key>
            <${allowed_source}/>
        </dict>
EOF
}

# Disable guest account
add_guest_account_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCX</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.guest.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Guest Account Policy</string>
            <key>DisableGuestAccount</key>
            <true/>
        </dict>
EOF
}

# Configure automatic updates
add_update_policy() {
    local auto_check="$1"
    local auto_download="$2"
    local auto_install="$3"
    
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.SoftwareUpdate</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.updates.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Software Update Policy</string>
            <key>AutomaticCheckEnabled</key>
            <${auto_check}/>
            <key>AutomaticDownload</key>
            <${auto_download}/>
            <key>ConfigDataInstall</key>
            <${auto_install}/>
            <key>CriticalUpdateInstall</key>
            <${auto_install}/>
        </dict>
EOF
}

# Disable Bluetooth (paranoid mode)
add_bluetooth_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCXBluetooth</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.bluetooth.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Bluetooth Policy</string>
            <key>DisableBluetooth</key>
            <true/>
        </dict>
EOF
}

# Disable AirDrop (paranoid mode)
add_airdrop_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.applicationaccess</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.airdrop.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>AirDrop Policy</string>
            <key>allowAirDrop</key>
            <false/>
        </dict>
EOF
}

# Disable automatic login
add_autologin_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.loginwindow</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.autologin.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Automatic Login Policy</string>
            <key>com.apple.login.mcx.DisableAutoLoginClient</key>
            <true/>
            <key>DisableFDEAutoLogin</key>
            <true/>
        </dict>
EOF
}

# Harden privacy preferences - Screen Recording
add_screen_recording_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.TCC.configuration-profile-policy</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.screenrecording.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Screen Recording Privacy Policy</string>
            <key>Services</key>
            <dict>
                <key>ScreenCapture</key>
                <array>
                    <dict>
                        <key>Allowed</key>
                        <false/>
                        <key>CodeRequirement</key>
                        <string>identifier "com.apple.screencapture" and anchor apple</string>
                    </dict>
                </array>
            </dict>
        </dict>
EOF
}

# Harden privacy preferences - Microphone
add_microphone_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.TCC.configuration-profile-policy</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.microphone.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Microphone Privacy Policy</string>
            <key>Services</key>
            <dict>
                <key>Microphone</key>
                <array>
                    <dict>
                        <key>Allowed</key>
                        <false/>
                        <key>CodeRequirement</key>
                        <string>identifier "com.apple.audio" and anchor apple</string>
                    </dict>
                </array>
            </dict>
        </dict>
EOF
}

# Harden privacy preferences - Camera
add_camera_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.TCC.configuration-profile-policy</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.camera.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Camera Privacy Policy</string>
            <key>Services</key>
            <dict>
                <key>Camera</key>
                <array>
                    <dict>
                        <key>Allowed</key>
                        <false/>
                        <key>CodeRequirement</key>
                        <string>identifier "com.apple.camera" and anchor apple</string>
                    </dict>
                </array>
            </dict>
        </dict>
EOF
}

# Harden privacy preferences - Location Services
add_location_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCX</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.location.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Location Services Policy</string>
            <key>DisableLocationServices</key>
            <true/>
        </dict>
EOF
}

# Enhanced Gatekeeper - Enforce signed applications only
add_gatekeeper_strict_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.systempolicy.control</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.gatekeeper.strict.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Gatekeeper Strict Policy</string>
            <key>EnableAssessment</key>
            <true/>
            <key>AllowIdentifiedDevelopers</key>
            <false/>
            <key>DisableOverride</key>
            <true/>
        </dict>
EOF
}

# Enforce application signatures and notarization
add_code_signature_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.systempolicy.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.codesign.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Code Signature Enforcement</string>
            <key>DisableLibraryValidation</key>
            <false/>
            <key>RequireNotarization</key>
            <true/>
        </dict>
EOF
}

# Configure Custom DNS Settings
add_custom_dns_policy() {
    local dns_primary="$1"
    local dns_secondary="$2"
    
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.dns.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Custom DNS Configuration</string>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerAddresses</key>
                <array>
                    <string>${dns_primary}</string>
                    <string>${dns_secondary}</string>
                </array>
            </dict>
            <key>ProhibitDisablement</key>
            <true/>
        </dict>
EOF
}

# Harden Safari Browser
add_safari_hardening_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.Safari</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.safari.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Safari Security Hardening</string>
            <key>AutoFillPasswords</key>
            <false/>
            <key>AutoFillCreditCardData</key>
            <false/>
            <key>AutoOpenSafeDownloads</key>
            <false/>
            <key>BlockStoragePolicy</key>
            <integer>2</integer>
            <key>SendDoNotTrackHTTPHeader</key>
            <true/>
            <key>WarnAboutFraudulentWebsites</key>
            <true/>
            <key>WebKitJavaScriptCanOpenWindowsAutomatically</key>
            <false/>
            <key>com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaScriptEnabled</key>
            <true/>
            <key>com.apple.Safari.ContentPageGroupIdentifier.WebKit2PluginsEnabled</key>
            <false/>
        </dict>
EOF
}

# Enforce Content Filtering
add_content_filtering_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.webcontent-filter</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.contentfilter.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Content Filtering Policy</string>
            <key>FilterType</key>
            <string>Plugin</string>
            <key>AutoFilterEnabled</key>
            <true/>
            <key>PermittedURLs</key>
            <array/>
            <key>BlacklistedURLs</key>
            <array>
                <string>*.torrent</string>
                <string>*.onion</string>
            </array>
        </dict>
EOF
}

# Enforce Automated Security Updates
add_security_updates_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.SoftwareUpdate</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.securityupdates.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Automated Security Updates</string>
            <key>AutomaticCheckEnabled</key>
            <true/>
            <key>AutomaticDownload</key>
            <true/>
            <key>AutomaticallyInstallMacOSUpdates</key>
            <true/>
            <key>ConfigDataInstall</key>
            <true/>
            <key>CriticalUpdateInstall</key>
            <true/>
            <key>AutomaticSecurityUpdatesEnabled</key>
            <true/>
        </dict>
EOF
}

# Configure System Auditing
add_system_auditing_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.systemuiserver</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.auditing.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>System Auditing Configuration</string>
            <key>AuditEnabled</key>
            <true/>
            <key>LogAuthenticationEvents</key>
            <true/>
            <key>LogFileAccessEvents</key>
            <true/>
            <key>LogNetworkEvents</key>
            <true/>
        </dict>
EOF
}

# Configure Log Retention
add_log_retention_policy() {
    local retention_days="$1"
    
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.systemlog</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.logretention.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Log Retention Policy</string>
            <key>Enable-Private-Data</key>
            <true/>
            <key>TTL</key>
            <dict>
                <key>Default</key>
                <integer>${retention_days}</integer>
                <key>System</key>
                <integer>${retention_days}</integer>
                <key>Security</key>
                <integer>${retention_days}</integer>
            </dict>
        </dict>
EOF
}

# Configure Unified Logging System
add_unified_logging_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.osanalytics</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.logging.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Unified Logging Configuration</string>
            <key>LogAuthenticationEvents</key>
            <true/>
            <key>LogPrivilegedOperations</key>
            <true/>
            <key>LogSecurityEvents</key>
            <true/>
        </dict>
EOF
}

# Disable Apple Intelligence features
add_apple_intelligence_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.applicationaccess</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.appleintelligence.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Apple Intelligence Restrictions</string>
            <key>allowAssistant</key>
            <false/>
            <key>allowAssistantWhileLocked</key>
            <false/>
            <key>allowDictation</key>
            <false/>
            <key>forceAssistantProfanityFilter</key>
            <true/>
        </dict>
EOF
}

# Disable Siri
add_siri_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.ironwood.support</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.siri.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Siri Restrictions</string>
            <key>Ironwood Allowed</key>
            <false/>
        </dict>
EOF
}

# Disable Handoff
add_handoff_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.applicationaccess</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.handoff.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Handoff Restrictions</string>
            <key>allowActivityContinuation</key>
            <false/>
        </dict>
EOF
}

# Disable iCloud features
add_icloud_restrictions_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.applicationaccess</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.icloud.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>iCloud Restrictions</string>
            <key>allowCloudDocumentSync</key>
            <false/>
            <key>allowCloudKeychainSync</key>
            <false/>
            <key>allowCloudPhotoLibrary</key>
            <false/>
            <key>allowCloudPrivateRelay</key>
            <false/>
        </dict>
EOF
}

# Disable SSH (Remote Login)
add_ssh_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCX</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.ssh.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>SSH Remote Login Policy</string>
            <key>DisableRemoteLogin</key>
            <true/>
        </dict>
EOF
}

# Disable Screen Sharing (VNC)
add_screen_sharing_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCX</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.screensharing.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Screen Sharing Policy</string>
            <key>DisableScreenSharing</key>
            <true/>
        </dict>
EOF
}

# Disable Remote Management (ARD)
add_remote_management_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.RemoteManagement</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.ard.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Remote Management Policy</string>
            <key>DisableRemoteManagement</key>
            <true/>
        </dict>
EOF
}

# Disable Remote Apple Events
add_remote_apple_events_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCX</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.appleevents.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Remote Apple Events Policy</string>
            <key>DisableRemoteAppleEvents</key>
            <true/>
        </dict>
EOF
}

# Disable File Sharing
add_file_sharing_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCX</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.filesharing.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>File Sharing Policy</string>
            <key>DisableFileSharing</key>
            <true/>
        </dict>
EOF
}

# Disable Printer Sharing
add_printer_sharing_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCX</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.printersharing.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>Printer Sharing Policy</string>
            <key>DisablePrinterSharing</key>
            <true/>
        </dict>
EOF
}