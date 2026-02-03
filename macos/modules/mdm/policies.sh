#!/usr/bin/env bash

# ==============================================================================
# MDM Module - Policy Definitions and Payload Generators
# ==============================================================================
# This module defines hardened MDM policies and provides functions to generate
# .mobileconfig (Apple Configuration Profile) payloads that can be installed
# through System Settings > General > Device Management
#
# MDM profiles are superior to direct configuration because:
#   - Supported and maintained by Apple
#   - Persist through system upgrades
#   - Easy to modify or remove via System Settings
#   - Part of officially recommended security practices
# ==============================================================================

set -euo pipefail

# ==============================================================================
# UTILITY FUNCTIONS FOR XML GENERATION
# ==============================================================================

# Encode string for XML/plist
xml_encode() {
    local input="$1"
    input="${input//&/&amp;}"
    input="${input//</&lt;}"
    input="${input//>/&gt;}"
    input="${input//\"/&quot;}"
    input="${input//\'/&apos;}"
    echo "$input"
}

# Generate plist dict entry
plist_dict_begin() {
    echo "	<dict>"

}

plist_dict_end() {
    echo "	</dict>"
}

# Generate plist key-value pair (string)
plist_string() {
    local key="$1"
    local value="$2"
    value=$(xml_encode "$value")
    echo "		<key>$key</key>"
    echo "		<string>$value</string>"
}

# Generate plist key-value pair (bool)
plist_bool() {
    local key="$1"
    local value="$2"
    local bool_value="true"
    [[ "$value" != "true" ]] && bool_value="false"
    echo "		<key>$key</key>"
    echo "		<$bool_value/>"
}

# Generate plist key-value pair (integer)
plist_integer() {
    local key="$1"
    local value="$2"
    echo "		<key>$key</key>"
    echo "		<integer>$value</integer>"
}

# Generate plist array
plist_array_begin() {
    local key="$1"
    echo "		<key>$key</key>"
    echo "		<array>"
}

plist_array_end() {
    echo "		</array>"
}

# Generate plist array string element
plist_array_string() {
    local value="$1"
    value=$(xml_encode "$value")
    echo "			<string>$value</string>"
}

# ==============================================================================
# PASSWORD POLICY PAYLOAD (FIXED)
# ==============================================================================

generate_password_policy_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "Password Policy"
    plist_string "PayloadIdentifier" "com.apple.mdm.passwordpolicy"
    plist_string "PayloadType" "com.apple.mobiledevice.passwordpolicy"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"
    
    # Password requirements
    plist_bool "allowSimple" "false"
    plist_bool "forcePIN" "true"
    plist_integer "maxFailedAttempts" "10"
    plist_integer "maxInactivity" "900"  # 15 minutes
    plist_integer "maxPINAgeInDays" "90"
    plist_integer "minComplexChars" "1"
    plist_integer "minLength" "12"
    plist_integer "minutesUntilFailedLoginReset" "15"
    plist_integer "pinHistory" "5"
    plist_bool "requireAlphanumeric" "true"
    
    echo "	</dict>"
}

# ==============================================================================
# LOGIN POLICY PAYLOAD (FIXED)
# ==============================================================================

generate_login_policy_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "Login Window Policy"
    plist_string "PayloadIdentifier" "com.apple.mdm.loginwindow"
    plist_string "PayloadType" "com.apple.loginwindow"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"
    
    # Disable automatic login
    plist_bool "com.apple.login.mcx.DisableAutoLoginClient" "true"
    
    # Show name and password fields
    plist_bool "SHOWFULLNAME" "true"
    
    # Hide sleep, restart, and shutdown buttons
    plist_bool "PowerOffDisabled" "true"
    plist_bool "RestartDisabled" "true"
    plist_bool "ShutDownDisabled" "true"
    
    # Disable guest account
    plist_bool "DisableGuestAccount" "true"
    
    # Show input menu (language/keyboard selector)
    plist_bool "showInputMenu" "true"
    
    echo "	</dict>"
}

# ==============================================================================
# SECURITY & PRIVACY PAYLOAD (FIXED)
# ==============================================================================

generate_security_privacy_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "Security & Privacy Settings"
    plist_string "PayloadIdentifier" "com.apple.mdm.securityprivacy"
    plist_string "PayloadType" "com.apple.security.firewall"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"
    
    # Enable firewall
    plist_bool "EnableFirewall" "true"
    plist_bool "BlockAllIncoming" "false"
    plist_bool "EnableStealthMode" "true"
    
    echo "	</dict>"
}

# ==============================================================================
# RESTRICTIONS PAYLOAD (FIXED - macOS specific)
# ==============================================================================

generate_restrictions_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "System Restrictions"
    plist_string "PayloadIdentifier" "com.apple.mdm.restrictions"
    plist_string "PayloadType" "com.apple.systempreferences"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"
    
    # Disabled preference panes
    plist_array_begin "DisabledPreferencePanes"
    plist_array_string "com.apple.preferences.sharing"
    plist_array_end
    
    echo "	</dict>"
}

# ==============================================================================
# REMOTE ACCESS RESTRICTIONS PAYLOAD (NEW - Separate from general restrictions)
# ==============================================================================

generate_remote_access_restrictions_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "Remote Access Restrictions"
    plist_string "PayloadIdentifier" "com.apple.mdm.remoteaccess"
    plist_string "PayloadType" "com.apple.MCX"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"
    
    # Disable SSH
    echo "		<key>dscl</key>"
    echo "		<dict>"
    echo "			<key>com.openssh.sshd</key>"
    echo "			<dict>"
    plist_bool "Disabled" "true"
    echo "			</dict>"
    echo "		</dict>"
    
    echo "	</dict>"
}

# ==============================================================================
# FILEVAULT PAYLOAD (FIXED)
# ==============================================================================

generate_filevault_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "FileVault Full Disk Encryption"
    plist_string "PayloadIdentifier" "com.apple.mdm.filevault2"
    plist_string "PayloadType" "com.apple.MCX.FileVault2"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"

    plist_bool "Enable" "true"
    plist_bool "Defer" "true"
    plist_integer "DeferForceAtUserLoginMaxBypassAttempts" "3"
    plist_bool "DeferDontAskAtUserLogout" "false"
    plist_bool "ShowRecoveryKey" "true"

    echo "	</dict>"
}

# ==============================================================================
# GATEKEEPER PAYLOAD (FIXED)
# ==============================================================================

generate_gatekeeper_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "Gatekeeper & System Integrity"
    plist_string "PayloadIdentifier" "com.apple.mdm.gatekeeper"
    plist_string "PayloadType" "com.apple.systempolicy.control"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"

    plist_bool "EnableAssessment" "true"
    plist_bool "AllowIdentifiedDevelopers" "true"

    echo "	</dict>"
}

# ==============================================================================
# SYSTEM UPDATES PAYLOAD (FIXED)
# ==============================================================================

generate_updates_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "Automatic System Updates"
    plist_string "PayloadIdentifier" "com.apple.mdm.softwareupdate"
    plist_string "PayloadType" "com.apple.SoftwareUpdate"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"
    
    # Automatic update settings
    plist_bool "AutomaticCheckEnabled" "true"
    plist_bool "AutomaticDownload" "true"
    plist_bool "AutomaticallyInstallMacOSUpdates" "true"
    plist_bool "CriticalUpdateInstall" "true"
    plist_bool "ConfigDataInstall" "true"
    
    echo "	</dict>"
}

# ==============================================================================
# DNS & NETWORK SECURITY PAYLOAD (FIXED)
# ==============================================================================

generate_dns_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "Encrypted DNS Settings"
    plist_string "PayloadIdentifier" "com.apple.mdm.dns"
    plist_string "PayloadType" "com.apple.dnsSettings.managed"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"
    
    # DNS Settings
    echo "		<key>DNSSettings</key>"
    echo "		<dict>"
    plist_string "DNSProtocol" "HTTPS"
    plist_string "ServerURL" "https://cloudflare-dns.com/dns-query"
    echo "		</dict>"
    
    # Prohibit disabling
    plist_bool "ProhibitDisablement" "true"
    
    echo "	</dict>"
}

# ==============================================================================
# PRIVACY PREFERENCES PAYLOAD (FIXED - TCC)
# ==============================================================================

generate_privacy_preferences_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "Privacy Preferences Policy Control"
    plist_string "PayloadIdentifier" "com.apple.mdm.privacy.tcc"
    plist_string "PayloadType" "com.apple.TCC.configuration-profile-policy"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"
    
    # Services configuration
    echo "		<key>Services</key>"
    echo "		<dict>"
    
    # Screen Recording - Deny all by default
    echo "			<key>ScreenCapture</key>"
    echo "			<array>"
    echo "				<dict>"
    plist_string "Identifier" "com.apple.screensharing.agent"
    plist_string "IdentifierType" "bundleID"
    plist_string "CodeRequirement" "identifier \"com.apple.screensharing.agent\" and anchor apple"
    plist_bool "Allowed" "false"
    plist_string "Comment" "Deny screen recording by default"
    echo "				</dict>"
    echo "			</array>"
    
    echo "		</dict>"
    echo "	</dict>"
}

# ==============================================================================
# AUDIT & LOGGING PAYLOAD (IMPROVED)
# ==============================================================================

generate_audit_logging_payload() {
    echo "	<dict>"
    plist_string "PayloadDisplayName" "Security Audit Configuration"
    plist_string "PayloadIdentifier" "com.apple.mdm.audit"
    plist_string "PayloadType" "com.apple.ManagedClient.preferences"
    plist_string "PayloadUUID" "$(uuidgen | tr '[:upper:]' '[:lower:]')"
    plist_integer "PayloadVersion" "1"
    
    # Enable audit daemon
    echo "		<key>Forced</key>"
    echo "		<array>"
    echo "			<dict>"
    plist_string "mcx_preference_settings" "/etc/security/audit_control"
    echo "			</dict>"
    echo "		</array>"
    
    echo "	</dict>"
}