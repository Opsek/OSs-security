#!/bin/bash

# MDM Profile Generator for macOS Hardening
# Supports two security levels: recommended and paranoid
# Usage: ./generate_mdm_profile.sh <profile_type>
# Example: ./generate_mdm_profile.sh recommended

set -euo pipefail

# Source the policies file
source "${SCRIPT_DIR}/modules/mdm/policies.sh"

# Generate a unique UUID for the profile
generate_uuid() {
    uuidgen | tr '[:upper:]' '[:lower:]'
}

# Get the current timestamp
get_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Create the MDM profile header
create_profile_header() {
    local profile_type="$1"
    local profile_uuid="$2"
    local timestamp="$3"
    
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
EOF
}

# Create the MDM profile footer
create_profile_footer() {
    local profile_type="$1"
    local profile_uuid="$2"
    local timestamp="$3"
    
    cat << EOF
    </array>
    <key>PayloadDescription</key>
    <string>macOS Security Hardening Profile - ${profile_type}</string>
    <key>PayloadDisplayName</key>
    <string>Security Hardening - ${profile_type}</string>
    <key>PayloadIdentifier</key>
    <string>com.security.hardening.${profile_type}.${profile_uuid}</string>
    <key>PayloadOrganization</key>
    <string>Security Team</string>
    <key>PayloadRemovalDisallowed</key>
    <true/>
    <key>PayloadScope</key>
    <string>System</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF
}

# Generate recommended profile
generate_recommended_profile() {
    local output_file="$1"
    local profile_uuid="$(generate_uuid)"
    local timestamp="$(get_timestamp)"
    
    {
        create_profile_header "recommended" "$profile_uuid" "$timestamp"
        add_password_policy "recommended" 12 2 5
        add_screensaver_policy 600
        add_filevault_policy
        add_firewall_policy "true"
        add_gatekeeper_policy "true"
        add_guest_account_policy
        add_update_policy "true" "true" "true"
        add_autologin_policy
        add_gatekeeper_strict_policy
        add_custom_dns_policy "1.1.1.1" "1.0.0.1"
        add_safari_hardening_policy
        add_security_updates_policy
        add_log_retention_policy 90
        add_unified_logging_policy
        add_airdrop_policy
        add_ssh_policy
        add_screen_sharing_policy
        add_remote_management_policy
        add_remote_apple_events_policy
        create_profile_footer "recommended" "$profile_uuid" "$timestamp"
    } > "$output_file"
}

# Generate paranoid profile
generate_paranoid_profile() {
    local output_file="$1"
    local profile_uuid="$(generate_uuid)"
    local timestamp="$(get_timestamp)"
    
    {
        create_profile_header "paranoid" "$profile_uuid" "$timestamp"
        add_password_policy "paranoid" 16 4 3
        add_screensaver_policy 300
        add_filevault_policy
        add_firewall_policy "true"
        add_gatekeeper_policy "false"
        add_guest_account_policy
        add_update_policy "true" "true" "true"
        add_bluetooth_policy
        add_airdrop_policy
        add_autologin_policy
        add_screen_recording_policy
        add_microphone_policy
        add_camera_policy
        add_location_policy
        add_gatekeeper_strict_policy
        add_code_signature_policy
        add_custom_dns_policy "1.1.1.1" "1.0.0.1"
        add_safari_hardening_policy
        add_content_filtering_policy
        add_security_updates_policy
        add_system_auditing_policy
        add_log_retention_policy 180
        add_unified_logging_policy
        add_apple_intelligence_policy
        add_siri_policy
        add_handoff_policy
        add_icloud_restrictions_policy
        add_ssh_policy
        add_screen_sharing_policy
        add_remote_management_policy
        add_remote_apple_events_policy
        add_file_sharing_policy
        add_printer_sharing_policy
        create_profile_footer "paranoid" "$profile_uuid" "$timestamp"
    } > "$output_file"
}

# Main function to generate MDM profile
generate_mdm_profile() {
    local profile_type="$1"
    
    # Validate input
    if [[ -z "$profile_type" ]]; then
        echo "Error: Profile type is required"
        echo "Usage: generate_mdm_profile <recommended|paranoid>"
        return 1
    fi
    
    # Normalize profile type to lowercase
    profile_type=$(echo "$profile_type" | tr '[:upper:]' '[:lower:]')
    
    # Create output directory if it doesn't exist
    local output_dir="mdm_profiles"
    mkdir -p "$output_dir"
    
    # Set output filename
    local output_file="${output_dir}/macos_hardening_${profile_type}_$(date +%Y%m%d_%H%M%S).mobileconfig"
    
    # Generate appropriate profile
    case "$profile_type" in
        recommended)
            echo "Generating recommended security profile..."
            generate_recommended_profile "$output_file"
            ;;
        paranoid)
            echo "Generating paranoid security profile..."
            generate_paranoid_profile "$output_file"
            ;;
        *)
            echo "Error: Invalid profile type '$profile_type'"
            echo "Valid options: recommended, paranoid"
            return 1
            ;;
    esac
    
    # Verify file was created
    if [[ -f "$output_file" ]]; then
        echo "✓ Profile generated: $output_file"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📦 INSTALLATION INSTRUCTIONS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "STEP 1: Open the profile"
        echo "  Double-click the generated file"
        echo "  "
        echo "  OR use command line:"
        echo "  open \"$output_file\""
        echo ""
        echo "STEP 2: System Settings will open"
        echo "  • Click \"Allow\" when prompted"
        echo "  • Navigate to: General > Device Management"
        echo ""
        echo "STEP 3: Review and Install"
        echo "  • Review policy details"
        echo "  • Click \"Install\" button"
        echo "  • Enter password when prompted"
        echo "  • Confirm installation"
        echo ""
        echo "STEP 4: Verify Installation"
        echo "  • Profile appears as \"Installed\" in Device Management"
        echo "  • Some settings require restart"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🔍 VERIFICATION & MANAGEMENT"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Check installation:"
        echo "  profiles list | grep -i hardening"
        echo ""
        echo "View profile details:"
        echo "  profiles show -type configuration"
        echo ""
        echo "Remove profile:"
        echo "  1. System Settings > General > Device Management"
        echo "  2. Select the profile and click \"Remove\""
        echo "  3. Enter password to confirm"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "⚠️  IMPORTANT NOTES"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• Save FileVault recovery key in a safe location"
        echo "• Update existing passwords to meet policy requirements"
        echo "• Some restrictions may affect existing workflows"
        echo "• Profile can be removed anytime from System Settings"
        echo "• All changes are reversible"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        return 0
    else
        echo "✗ Error: Failed to generate profile"
        return 1
    fi
}

# Run the main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then
        echo "Usage: $0 <recommended|paranoid>"
        exit 1
    fi
    generate_mdm_profile "$1"
fi