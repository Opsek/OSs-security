#!/usr/bin/env bash

################################################################################
# MDM Module - Profile Generator
################################################################################
# Generates hardened Apple Mobile Device Management (MDM) profiles.
#
# Usage:
#   source modules/mdm/profile_generator.sh
#   generate_mdm_profile "recommended"  # Balanced security
#   generate_mdm_profile "paranoid"     # Maximum hardening
#
# Prerequisites:
#   - policies.sh must be sourced first
#   - macOS 12.0+ (Configuration Profiles v2)
################################################################################

set -euo pipefail

# Strict error handling
trap '_handle_error $? $LINENO' ERR

# Configuration
readonly ORGANIZATION_NAME="${ORGANIZATION_NAME:-Security Hardening Organization}"
readonly PROFILE_VERSION="1.0"
readonly REQUIRED_POLICIES_FUNC="generate_password_policy_payload"

################################################################################
# ERROR HANDLING
################################################################################

_handle_error() {
    local exit_code="$1"
    local line_number="$2"
    echo "❌ Error at line $line_number (exit code: $exit_code)" >&2
    return "$exit_code"
}

################################################################################
# DEPENDENCY MANAGEMENT
################################################################################

_get_script_dir() {
    cd "$(dirname "${BASH_SOURCE[0]}")" || return 1
    pwd
}

_source_policies() {
    local script_dir
    script_dir=$(_get_script_dir) || return 1
    
    local policies_file="$script_dir/policies.sh"
    
    if [[ ! -f "$policies_file" ]]; then
        echo "❌ Error: policies.sh not found at $policies_file" >&2
        return 1
    fi
    
    # shellcheck source=/dev/null
    source "$policies_file" || {
        echo "❌ Error: Failed to load policies.sh" >&2
        return 1
    }
}

# Load policies if not already loaded
if ! declare -f "$REQUIRED_POLICIES_FUNC" &>/dev/null; then
    _source_policies || return 1
fi

################################################################################
# VALIDATION FUNCTIONS
################################################################################

_is_valid_profile_name() {
    local name="$1"
    [[ "$name" == "recommended" || "$name" == "paranoid" ]]
}

_validate_output_directory() {
    local output_dir="$1"
    mkdir -p "$output_dir" || {
        echo "❌ Error: Cannot create output directory: $output_dir" >&2
        return 1
    }
    [[ -w "$output_dir" ]] || {
        echo "❌ Error: Output directory is not writable: $output_dir" >&2
        return 1
    }
}

_validate_profile_arguments() {
    local profile_name="$1"
    local output_dir="$2"
    
    _is_valid_profile_name "$profile_name" || {
        echo "❌ Error: Invalid profile name: $profile_name" >&2
        echo "   Valid options: recommended, paranoid" >&2
        return 1
    }
    
    _validate_output_directory "$output_dir" || return 1
}

################################################################################
# PROFILE GENERATION - CORE
################################################################################

_generate_profile_uuid() {
    uuidgen | tr '[:upper:]' '[:lower:]'
}

_generate_timestamp() {
    date +%Y%m%d-%H%M%S
}

_write_xml_header() {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0">'
}

_write_plist_dict_open() {
    echo '<dict>'
}

_write_plist_dict_close() {
    echo '</dict>'
}

_write_plist_array_open() {
    echo '<array>'
}

_write_plist_array_close() {
    echo '</array>'
}

_write_plist_key_string() {
    local key="$1"
    local value="$2"
    echo "	<key>$key</key>"
    echo "	<string>$value</string>"
}

_write_plist_key_integer() {
    local key="$1"
    local value="$2"
    echo "	<key>$key</key>"
    echo "	<integer>$value</integer>"
}

_write_plist_key_false() {
    local key="$1"
    echo "	<key>$key</key>"
    echo "	<false/>"
}

################################################################################
# PROFILE METADATA WRITERS
################################################################################

_write_profile_metadata() {
    local organization="$1"
    local profile_name="$2"
    local profile_uuid="$3"
    local timestamp="$4"
    
    local display_name="$organization - macOS Security Hardening (${profile_name^^})"
    local description
    description=$(get_profile_description "$profile_name")
    
    _write_plist_key_string "PayloadDisplayName" "$display_name"
    _write_plist_key_string "PayloadDescription" "$description"
    _write_plist_key_string "PayloadIdentifier" "com.security.hardening.$profile_name.$profile_uuid"
    _write_plist_key_string "PayloadOrganization" "$organization"
    _write_plist_key_false "PayloadRemovalDisallowed"
    _write_plist_key_string "PayloadScope" "System"
    _write_plist_key_string "PayloadType" "Configuration"
    _write_plist_key_string "PayloadUUID" "$profile_uuid"
    _write_plist_key_integer "PayloadVersion" 1
    _write_plist_key_string "GeneratedDate" "$timestamp"
}

################################################################################
# PROFILE PAYLOAD MANAGEMENT
################################################################################

_write_payloads_section_header() {
    echo "	<key>PayloadContent</key>"
}

_add_recommended_payloads() {
    generate_password_policy_payload
    generate_login_policy_payload
    generate_filevault_payload
    generate_gatekeeper_payload
    generate_restrictions_payload
    generate_security_privacy_payload
    generate_updates_payload
}

_add_paranoid_payloads() {
    generate_password_policy_payload
    generate_login_policy_payload
    generate_filevault_payload
    generate_gatekeeper_payload
    generate_restrictions_payload
    generate_remote_access_restrictions_payload
    generate_security_privacy_payload
    generate_updates_payload
    generate_dns_payload "1.1.1.1,1.0.0.1"
    generate_privacy_preferences_payload
    generate_audit_logging_payload
}

_write_profile_payloads() {
    local profile_name="$1"
    
    _write_payloads_section_header
    _write_plist_array_open
    
    case "$profile_name" in
        recommended)
            _add_recommended_payloads
            ;;
        paranoid)
            _add_paranoid_payloads
            ;;
    esac
    
    _write_plist_array_close
}

################################################################################
# PROFILE FILE OPERATIONS
################################################################################

_create_profile_content() {
    local profile_name="$1"
    local organization="$2"
    local profile_uuid="$3"
    local timestamp="$4"
    
    {
        _write_xml_header
        _write_plist_dict_open
        
        _write_profile_metadata "$organization" "$profile_name" "$profile_uuid" "$timestamp"
        _write_profile_payloads "$profile_name"
        
        _write_plist_dict_close
        echo '</plist>'
    }
}

_write_profile_to_file() {
    local output_file="$1"
    local content_command="$2"
    
    local temp_file="${output_file}.tmp"
    
    if ! "$@" content_command > "$temp_file" 2>/dev/null; then
        rm -f "$temp_file"
        return 1
    fi
    
    if [[ ! -s "$temp_file" ]]; then
        rm -f "$temp_file"
        echo "❌ Error: Failed to create profile content" >&2
        return 1
    fi
    
    if ! mv "$temp_file" "$output_file" 2>/dev/null; then
        rm -f "$temp_file"
        echo "❌ Error: Failed to write profile to: $output_file" >&2
        return 1
    fi
}

################################################################################
# PROFILE DESCRIPTIONS
################################################################################

get_profile_description() {
    local profile_name="$1"
    
    case "$profile_name" in
        recommended)
            echo "Recommended security hardening profile balancing protection and usability. Includes password policies, FileVault encryption, Gatekeeper enforcement, automatic updates, and basic remote access restrictions."
            ;;
        paranoid)
            echo "Maximum security hardening profile with comprehensive controls. Includes all recommended policies plus strict privacy controls, DNS security, audit logging, and enhanced restrictions. Best for high-security environments."
            ;;
    esac
}

################################################################################
# PUBLIC API - MAIN FUNCTION
################################################################################

generate_mdm_profile() {
    local profile_name="${1:-recommended}"
    local output_dir="${2:-.}"
    local organization="${3:-$ORGANIZATION_NAME}"
    
    # Validation
    _validate_profile_arguments "$profile_name" "$output_dir" || return 1
    
    # Generate identifiers
    local profile_uuid
    local timestamp
    profile_uuid=$(_generate_profile_uuid)
    timestamp=$(_generate_timestamp)
    
    local output_file="$output_dir/${profile_name}_hardening_profile.mobileconfig"
    
    echo "🔧 Generating $profile_name profile..." >&2
    
    # Create and write profile
    if ! _create_profile_content "$profile_name" "$organization" "$profile_uuid" "$timestamp" > "${output_file}.tmp" 2>/dev/null; then
        rm -f "${output_file}.tmp"
        echo "❌ Error: Failed to create profile content" >&2
        return 1
    fi
    
    if [[ ! -s "${output_file}.tmp" ]]; then
        rm -f "${output_file}.tmp"
        echo "❌ Error: Profile file is empty" >&2
        return 1
    fi
    
    if ! mv "${output_file}.tmp" "$output_file" 2>/dev/null; then
        rm -f "${output_file}.tmp"
        echo "❌ Error: Failed to write profile to: $output_file" >&2
        return 1
    fi
    
    # Validate and display results
    if validate_profile_file "$output_file"; then
        echo "✅ Profile generated successfully: $output_file" >&2
        echo "" >&2
        profile_summary "$output_file"
        echo "" >&2
        show_next_steps "$output_file"
        echo "$output_file"
        return 0
    else
        echo "❌ Profile generation failed validation" >&2
        return 1
    fi
}

################################################################################
# PROFILE VALIDATION
################################################################################

_is_valid_xml_file() {
    local file="$1"
    head -1 "$file" | grep -q "<?xml" || return 1
}

_is_valid_plist_file() {
    local file="$1"
    grep -q '<plist version="1.0">' "$file" || return 1
}

_check_required_profile_keys() {
    local file="$1"
    local required_keys=("PayloadType" "PayloadIdentifier" "PayloadUUID" "PayloadContent")
    
    for key in "${required_keys[@]}"; do
        grep -q "<key>$key</key>" "$file" || {
            echo "❌ Error: Missing required key: $key" >&2
            return 1
        }
    done
}

_validate_with_plutil() {
    local file="$1"
    
    if ! command -v plutil &>/dev/null; then
        return 0
    fi
    
    if plutil -lint "$file" &>/dev/null; then
        echo "✅ Profile validated with plutil" >&2
    else
        echo "⚠️  Warning: plutil validation found issues" >&2
        plutil -lint "$file" >&2 || true
    fi
}

validate_profile_file() {
    local file="$1"
    
    [[ -f "$file" ]] || {
        echo "❌ Error: Profile file not found: $file" >&2
        return 1
    }
    
    [[ -s "$file" ]] || {
        echo "❌ Error: Profile file is empty" >&2
        return 1
    }
    
    _is_valid_xml_file "$file" || {
        echo "❌ Error: Not a valid XML file" >&2
        return 1
    }
    
    _is_valid_plist_file "$file" || {
        echo "❌ Error: Not a valid plist file" >&2
        return 1
    }
    
    _check_required_profile_keys "$file" || return 1
    
    _validate_with_plutil "$file"
}

################################################################################
# PROFILE INFORMATION EXTRACTION
################################################################################

_extract_plist_string() {
    local file="$1"
    local key="$2"
    grep -A 1 "<key>$key</key>" "$file" | tail -1 | sed 's/.*<string>//;s/<\/string>.*//' | xargs
}

_count_payloads() {
    local file="$1"
    # Subtract 1 for root PayloadType
    echo $(($(grep -c '<key>PayloadType</key>' "$file") - 1))
}

_list_payload_types() {
    local file="$1"
    grep -A 1 'PayloadDisplayName' "$file" | grep '<string>' | \
        sed 's/.*<string>//;s/<\/string>.*//' | \
        grep -v 'macOS Security Hardening' | \
        while read -r name; do
            echo "  ✓ $name" >&2
        done
}

################################################################################
# PROFILE DISPLAY FUNCTIONS
################################################################################

_print_profile_separator() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
}

_print_profile_header() {
    local title="$1"
    _print_profile_separator
    echo "📋 $title" >&2
    _print_profile_separator
}

profile_summary() {
    local file="$1"
    
    [[ -f "$file" ]] || {
        echo "❌ Error: Profile file not found" >&2
        return 1
    }
    
    _print_profile_header "PROFILE SUMMARY"
    
    local display_name
    local description
    local identifier
    local organization
    display_name=$(_extract_plist_string "$file" "PayloadDisplayName")
    description=$(_extract_plist_string "$file" "PayloadDescription")
    identifier=$(_extract_plist_string "$file" "PayloadIdentifier")
    organization=$(_extract_plist_string "$file" "PayloadOrganization")
    
    echo "Name:         $display_name" >&2
    echo "Organization: $organization" >&2
    echo "Identifier:   $identifier" >&2
    echo "" >&2
    echo "Description:" >&2
    echo "$description" | fold -w 70 -s | sed 's/^/  /' >&2
    echo "" >&2
    
    local payload_count
    payload_count=$(_count_payloads "$file")
    echo "Payloads:     $payload_count policies configured" >&2
    echo "" >&2
    echo "Configured Policies:" >&2
    _list_payload_types "$file"
    
    _print_profile_separator
}

################################################################################
# INSTALLATION INSTRUCTIONS
################################################################################

show_next_steps() {
    local profile_file="$1"
    
    cat >&2 <<'EOF'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 INSTALLATION INSTRUCTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STEP 1: Open the profile
  Double-click the generated file
  
  OR use command line:
  open "<profile_path>"

STEP 2: System Settings will open
  • Click "Allow" when prompted
  • Navigate to: General > Device Management

STEP 3: Review and Install
  • Review policy details
  • Click "Install" button
  • Enter password when prompted
  • Confirm installation

STEP 4: Verify Installation
  • Profile appears as "Installed" in Device Management
  • Some settings require restart

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 VERIFICATION & MANAGEMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Check installation:
  profiles list | grep -i hardening

View profile details:
  profiles show -type configuration

Remove profile:
  1. System Settings > General > Device Management
  2. Select the profile and click "Remove"
  3. Enter password to confirm

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  IMPORTANT NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• Save FileVault recovery key in a safe location
• Update existing passwords to meet policy requirements
• Some restrictions may affect existing workflows
• Profile can be removed anytime from System Settings
• All changes are reversible

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF
}

show_mdm_installation_instructions() {
    local profile_file="${1:-}"
    
    if [[ -z "$profile_file" ]]; then
        cat >&2 <<'EOF'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📚 MDM PROFILE INSTALLATION GUIDE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Generate a profile using:
  generate_mdm_profile "recommended"  # Balanced security
  generate_mdm_profile "paranoid"     # Maximum security

Then follow the installation instructions shown after generation.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
    else
        show_next_steps "$profile_file"
    fi
}

################################################################################
# PROFILE COMPARISON & BATCH OPERATIONS
################################################################################

_extract_payload_count() {
    local file="$1"
    echo $(($(grep -c '<key>PayloadType</key>' "$file") - 1))
}

compare_profiles() {
    local profile1="$1"
    local profile2="$2"
    
    [[ -f "$profile1" && -f "$profile2" ]] || {
        echo "❌ Error: One or both profile files not found" >&2
        return 1
    }
    
    echo "Comparing profiles:" >&2
    echo "  Profile 1: $profile1" >&2
    echo "  Profile 2: $profile2" >&2
    echo "" >&2
    
    local count1
    local count2
    count1=$(_extract_payload_count "$profile1")
    count2=$(_extract_payload_count "$profile2")
    
    echo "Payload count:" >&2
    echo "  Profile 1: $count1 payloads" >&2
    echo "  Profile 2: $count2 payloads" >&2
    echo "" >&2
    
    if command -v diff &>/dev/null; then
        echo "Detailed differences:" >&2
        diff -u "$profile1" "$profile2" || true
    fi
}

generate_all_profiles() {
    local output_dir="${1:-.}"
    
    echo "🔧 Generating all profile variants..." >&2
    echo "" >&2
    
    local recommended_file
    recommended_file=$(generate_mdm_profile "recommended" "$output_dir")
    
    echo "" >&2
    _print_profile_separator
    echo "" >&2
    
    local paranoid_file
    paranoid_file=$(generate_mdm_profile "paranoid" "$output_dir")
    
    echo "" >&2
    echo "✅ All profiles generated in: $output_dir" >&2
    echo "   - Recommended: $recommended_file" >&2
    echo "   - Paranoid: $paranoid_file" >&2
}


