#!/bin/bash

# MDM Profile Generator for macOS Hardening
# Supports two security levels: recommended and paranoid
# Usage: ./generate_mdm_profile.sh <profile_type>
# Example: ./generate_mdm_profile.sh recommended

set -euo pipefail

if [[ -z "${SCRIPT_DIR:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fi

# Source the policies file
source "${SCRIPT_DIR}/modules/mdm/policies.sh"

# Source profile metadata when available so generation can warn about shell-only
# controls that still need the traditional paranoid hardening script.
if [[ -f "${SCRIPT_DIR}/config/profiles.conf" ]]; then
    source "${SCRIPT_DIR}/config/profiles.conf"
fi

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
    <string>OPSEK - Security Hardening - ${profile_type}</string>
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

        add_password_policy 12 1 5
        add_screensaver_policy 600
        add_filevault_policy
        add_firewall_policy "false"
        add_gatekeeper_policy
        add_updates_policy
        add_loginwindow_policy
        add_ssh_policy
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

        add_password_policy 16 2 3
        add_screensaver_policy 60
        add_filevault_policy
        add_firewall_policy "true"
        add_gatekeeper_policy
        add_updates_policy

        add_loginwindow_policy
        add_autologin_policy
        add_ssh_policy

        add_core_restrictions_policy
        add_privacy_restrictions_policy
        add_bluetooth_restrictions_policy
        add_remote_access_policy
        add_safari_policy
        add_dns_policy
        add_sharing_restrictions_policy

        create_profile_footer "paranoid" "$profile_uuid" "$timestamp"
    } > "$output_file"
}

print_paranoid_shell_required_warning() {
    if [[ -z "${PROFILE_PARANOID_SHELL_REQUIRED:-}" ]]; then
        return 0
    fi

    echo ""
    echo "========================================================================"
    echo "WARNING: paranoid coverage is incomplete with the MDM profile alone"
    echo "========================================================================"
    echo "The paranoid MDM profile applies the persistent controls available through"
    echo "configuration profiles. The following controls remain shell-only and must"
    echo "be applied with the hardening script to achieve complete paranoid coverage:"
    echo ""

    while IFS= read -r control; do
        control="${control#"${control%%[![:space:]]*}"}"
        control="${control%"${control##*[![:space:]]}"}"
        if [[ -n "$control" ]]; then
            echo "  - $control"
        fi
    done <<< "$PROFILE_PARANOID_SHELL_REQUIRED"

    echo ""
    echo "Recommended command after installing the MDM profile:"
    echo "  sudo ./main.sh --paranoid"
    echo "========================================================================"
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
        if [[ "$profile_type" == "paranoid" ]]; then
            print_paranoid_shell_required_warning
        fi
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
