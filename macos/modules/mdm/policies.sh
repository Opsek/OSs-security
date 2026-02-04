#!/bin/bash

# Modern macOS MDM Hardening Policies (10.15+)
# Valid payloads only – compatible with Jamf / Intune / Kandji / Mosyle

# Helper: UUID generator must exist in parent script
# generate_uuid()

############################
# PASSWORD POLICY
############################
add_password_policy() {
  local min_length="$1"
  local min_complex="$2"
  local max_failed="$3"

cat <<EOF
<dict>
  <key>PayloadType</key>
  <string>com.apple.mobiledevice.passwordpolicy</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.security.password.$(generate_uuid)</string>
  <key>PayloadUUID</key>
  <string>$(generate_uuid)</string>
  <key>PayloadDisplayName</key>
  <string>Password Policy</string>
  <key>allowSimple</key>
  <false/>
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

############################
# SCREEN LOCK
############################
add_screensaver_policy() {
  local idle_time="$1"

cat <<EOF
<dict>
  <key>PayloadType</key>
  <string>com.apple.screensaver</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.security.screensaver.$(generate_uuid)</string>
  <key>PayloadUUID</key>
  <string>$(generate_uuid)</string>
  <key>PayloadDisplayName</key>
  <string>Screen Lock</string>
  <key>askForPassword</key>
  <true/>
  <key>askForPasswordDelay</key>
  <integer>0</integer>
  <key>idleTime</key>
  <integer>${idle_time}</integer>
</dict>
EOF
}

############################
# FILEVAULT (ENFORCE)
############################
# Configure FileVault encryption - Using custom settings
add_filevault_policy() {
    cat << EOF
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCX</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.security.hardening.filevault.$(generate_uuid)</string>
            <key>PayloadUUID</key>
            <string>$(generate_uuid)</string>
            <key>PayloadDisplayName</key>
            <string>FileVault Configuration</string>
            <key>dontAllowFDEDisable</key>
            <true/>
        </dict>
EOF
}
############################
# FIREWALL
############################
add_firewall_policy() {
  local stealth="$1"

cat <<EOF
<dict>
  <key>PayloadType</key>
  <string>com.apple.security.firewall</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.security.firewall.$(generate_uuid)</string>
  <key>PayloadUUID</key>
  <string>$(generate_uuid)</string>
  <key>PayloadDisplayName</key>
  <string>Firewall</string>
  <key>EnableFirewall</key>
  <true/>
  <key>EnableStealthMode</key>
  <${stealth}/>
</dict>
EOF
}

############################
# GATEKEEPER (STRICT)
############################
add_gatekeeper_policy() {
cat <<EOF
<dict>
  <key>PayloadType</key>
  <string>com.apple.systempolicy.control</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.security.gatekeeper.$(generate_uuid)</string>
  <key>PayloadUUID</key>
  <string>$(generate_uuid)</string>
  <key>PayloadDisplayName</key>
  <string>Gatekeeper Strict</string>
  <key>EnableAssessment</key>
  <true/>
  <key>AllowIdentifiedDevelopers</key>
  <false/>
  <key>DisableOverride</key>
  <true/>
</dict>
EOF
}

############################
# AUTO UPDATES
############################
add_updates_policy() {
cat <<EOF
<dict>
  <key>PayloadType</key>
  <string>com.apple.SoftwareUpdate</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.security.updates.$(generate_uuid)</string>
  <key>PayloadUUID</key>
  <string>$(generate_uuid)</string>
  <key>PayloadDisplayName</key>
  <string>Automatic Updates</string>
  <key>AutomaticCheckEnabled</key>
  <true/>
  <key>AutomaticDownload</key>
  <true/>
  <key>AutomaticallyInstallMacOSUpdates</key>
  <true/>
  <key>CriticalUpdateInstall</key>
  <true/>
</dict>
EOF
}


############################
# DNS OVER HTTPS (DoH)
############################
add_dns_policy() {
cat <<EOF
<dict>
<key>PayloadType</key>
<string>com.apple.dnsSettings.managed</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.security.dns.$(generate_uuid)</string>
<key>PayloadUUID</key>
<string>$(generate_uuid)</string>
<key>PayloadDisplayName</key>
<string>DNS over HTTPS</string>
<key>DNSSettings</key>
<dict>
<key>DNSProtocol</key>
<string>HTTPS</string>
<key>ServerURL</key>
<string>https://cloudflare-dns.com/dns-query</string>
</dict>
</dict>
EOF
}

############################
# RESTRICTIONS (CORE)
############################
add_core_restrictions_policy() {
cat <<EOF
<dict>
  <key>PayloadType</key>
  <string>com.apple.applicationaccess</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.security.restrictions.$(generate_uuid)</string>
  <key>PayloadUUID</key>
  <string>$(generate_uuid)</string>
  <key>PayloadDisplayName</key>
  <string>System Restrictions</string>
  <key>allowAirDrop</key>
  <false/>
  <key>allowBluetoothModification</key>
  <false/>
  <key>allowAssistant</key>
  <false/>
  <key>allowAssistantWhileLocked</key>
  <false/>
  <key>allowActivityContinuation</key>
  <false/>
  <key>allowCloudDocumentSync</key>
  <false/>
  <key>allowCloudKeychainSync</key>
  <false/>
  <key>allowCloudPhotoLibrary</key>
  <false/>
</dict>
EOF
}

############################
# LOGIN WINDOW
############################
add_loginwindow_policy() {
cat <<EOF
<dict>
  <key>PayloadType</key>
  <string>com.apple.loginwindow</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.security.login.$(generate_uuid)</string>
  <key>PayloadUUID</key>
  <string>$(generate_uuid)</string>
  <key>PayloadDisplayName</key>
  <string>Login Window</string>
  <key>DisableGuestAccount</key>
  <true/>
  <key>DisableFDEAutoLogin</key>
  <true/>
</dict>
EOF
}

############################
# SSH DISABLE
############################
add_ssh_policy() {
cat <<EOF
<dict>
  <key>PayloadType</key>
  <string>com.apple.sshd</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.security.ssh.$(generate_uuid)</string>
  <key>PayloadUUID</key>
  <string>$(generate_uuid)</string>
  <key>PayloadDisplayName</key>
  <string>Disable SSH</string>
  <key>AllowRemoteLogin</key>
  <false/>
</dict>
EOF
}

############################
# SAFARI HARDENING
############################
add_safari_policy() {
cat <<EOF
<dict>
  <key>PayloadType</key>
  <string>com.apple.Safari</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.security.safari.$(generate_uuid)</string>
  <key>PayloadUUID</key>
  <string>$(generate_uuid)</string>
  <key>PayloadDisplayName</key>
  <string>Safari Hardening</string>
  <key>AutoFillPasswords</key>
  <false/>
  <key>AutoFillCreditCardData</key>
  <false/>
  <key>AutoOpenSafeDownloads</key>
  <false/>
  <key>WarnAboutFraudulentWebsites</key>
  <true/>
</dict>
EOF
}


############################
# SCREEN SHARING / REMOTE MGMT BLOCK
############################
add_remote_access_policy() {
cat <<EOF
<dict>
<key>PayloadType</key>
<string>com.apple.applicationaccess</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.security.remote.$(generate_uuid)</string>
<key>PayloadUUID</key>
<string>$(generate_uuid)</string>
<key>PayloadDisplayName</key>
<string>Remote Access Restrictions</string>
<key>allowScreenSharing</key>
<false/>
<key>allowRemoteAppleEvents</key>
<false/>
</dict>
EOF
}


############################
# SHARING RESTRICTIONS
############################
add_sharing_restrictions_policy() {
cat <<EOF
<dict>
  <key>PayloadType</key>
  <string>com.apple.applicationaccess</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.security.sharing.$(generate_uuid)</string>
  <key>PayloadUUID</key>
  <string>$(generate_uuid)</string>
  <key>PayloadDisplayName</key>
  <string>Sharing Restrictions</string>
  <key>allowAirDrop</key>
  <false/>
  <key>allowContentCaching</key>
  <false/>
  <key>allowMediaSharing</key>
  <false/>
</dict>
EOF
}




############################
# AUTO LOGIN HARD DISABLE
############################
add_autologin_policy() {
cat <<EOF
<dict>
<key>PayloadType</key>
<string>com.apple.loginwindow</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.security.autologin.$(generate_uuid)</string>
<key>PayloadUUID</key>
<string>$(generate_uuid)</string>
<key>PayloadDisplayName</key>
<string>Disable Automatic Login</string>
<key>DisableAutoLoginClient</key>
<true/>
</dict>
EOF
}