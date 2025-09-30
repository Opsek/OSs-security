#!/usr/bin/env bash

# ==============================================================================
# Compliance tests for macOS hardening script
# ==============================================================================

# Load utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../utils/common.sh"
source "$SCRIPT_DIR/../utils/logging.sh"

# ==============================================================================
# TEST FUNCTIONS
# ==============================================================================

# CIS compliance test
test_cis_compliance() {
    info "Running CIS compliance tests"
    
    local total_issues=0
    
    # Test FileVault
    if cis_check_filevault; then
        success "✓ FileVault test passed"
    else
        warn "✗ FileVault test failed"
        ((total_issues++))
    fi
    
    # Test Firewall
    if cis_check_firewall; then
        success "✓ Firewall test passed"
    else
        warn "✗ Firewall test failed"
        ((total_issues++))
    fi
    
    # Test Gatekeeper
    if cis_check_gatekeeper; then
        success "✓ Gatekeeper test passed"
    else
        warn "✗ Gatekeeper test failed"
        ((total_issues++))
    fi
    
    # Test Remote Services
    local remote_issues
    cis_check_remote_services
    remote_issues=$?
    total_issues=$((total_issues + remote_issues))
    
    # Test User Settings
    local user_issues
    cis_check_user_settings
    user_issues=$?
    total_issues=$((total_issues + user_issues))
    
    if [[ $total_issues -eq 0 ]]; then
        success "All CIS compliance tests passed"
    else
        warn "$total_issues CIS compliance issues found"
    fi
    
    return $total_issues
}

# OPSEK compliance test
test_opsek_compliance() {
    info "Running OPSEK compliance tests"
    
    local total_issues=0
    
    # Test Bluetooth
    if function_exists "opsek_check_bluetooth"; then
        if opsek_check_bluetooth; then
            success "✓ OPSEK Bluetooth test passed"
        else
            warn "✗ OPSEK Bluetooth test failed"
            ((total_issues++))
        fi
    fi
    
    # Test Wi-Fi
    if function_exists "opsek_check_wifi"; then
        if opsek_check_wifi; then
            success "✓ OPSEK Wi-Fi test passed"
        else
            warn "✗ OPSEK Wi-Fi test failed"
            ((total_issues++))
        fi
    fi
    
    # Test Lockdown Mode
    if function_exists "opsek_check_lockdown_mode"; then
        if opsek_check_lockdown_mode; then
            success "✓ OPSEK Lockdown Mode test passed"
        else
            warn "✗ OPSEK Lockdown Mode test failed"
            ((total_issues++))
        fi
    fi
    
    # Test Keyboard Security
    if function_exists "opsek_check_keyboard_security"; then
        local keyboard_issues
        opsek_check_keyboard_security
        keyboard_issues=$?
        total_issues=$((total_issues + keyboard_issues))
    fi
    
    if [[ $total_issues -eq 0 ]]; then
        success "All OPSEK compliance tests passed"
    else
        warn "$total_issues OPSEK compliance issues found"
    fi
    
    return $total_issues
}

# Profile validation test
test_profile_validation() {
    info "Testing profile validation"
    
    local profiles=("basic" "moderate" "strict" "paranoid")
    local total_issues=0
    
    for profile in "${profiles[@]}"; do
        if validate_profile "$profile"; then
            success "✓ Profile $profile validation passed"
        else
            warn "✗ Profile $profile validation failed"
            ((total_issues++))
        fi
    done
    
    if [[ $total_issues -eq 0 ]]; then
        success "All profile validations passed"
    else
        warn "$total_issues profile validation issues found"
    fi
    
    return $total_issues
}

# Module loading test
test_module_loading() {
    info "Testing module loading"
    
    local total_issues=0
    
    # Test CIS modules
    local cis_modules=("system" "network" "services" "permissions" "users")
    for module in "${cis_modules[@]}"; do
        if load_module "$SCRIPT_DIR/../modules/cis/$module.sh"; then
            success "✓ CIS module $module loaded"
        else
            warn "✗ CIS module $module failed to load"
            ((total_issues++))
        fi
    done
    
    # Test modules
    local opsek_modules=("bluetooth" "wifi" "lockdown" "privacy" "kernel")
    for module in "${opsek_modules[@]}"; do
        if load_module "$SCRIPT_DIR/../modules/internals/$module.sh"; then
            success "✓ Opsek module $module loaded"
        else
            warn "✗ Opsek module $module failed to load"
            ((total_issues++))
        fi
    done
    
    if [[ $total_issues -eq 0 ]]; then
        success "All modules loaded successfully"
    else
        warn "$total_issues module loading issues found"
    fi
    
    return $total_issues
}

# Configuration test
test_configuration() {
    info "Testing configuration loading"
    
    local total_issues=0
    
    # Test settings.conf
    if [[ -f "$SCRIPT_DIR/../config/settings.conf" ]]; then
        success "✓ settings.conf found"
    else
        warn "✗ settings.conf not found"
        ((total_issues++))
    fi
    
    # Test profiles.conf
    if [[ -f "$SCRIPT_DIR/../config/profiles.conf" ]]; then
        success "✓ profiles.conf found"
    else
        warn "✗ profiles.conf not found"
        ((total_issues++))
    fi
    
    # Test configuration loading
    if load_config; then
        success "✓ Configuration loaded successfully"
    else
        warn "✗ Configuration loading failed"
        ((total_issues++))
    fi
    
    if [[ $total_issues -eq 0 ]]; then
        success "All configuration tests passed"
    else
        warn "$total_issues configuration issues found"
    fi
    
    return $total_issues
}

# ==============================================================================
# MAIN TEST FUNCTION
# ==============================================================================

run_all_tests() {
    info "=== Running All Compliance Tests ==="
    
    local total_issues=0
    
    # Configuration test
    local config_issues
    test_configuration
    config_issues=$?
    total_issues=$((total_issues + config_issues))
    
    # Module loading test
    local module_issues
    test_module_loading
    module_issues=$?
    total_issues=$((total_issues + module_issues))
    
    # Profile validation test
    local profile_issues
    test_profile_validation
    profile_issues=$?
    total_issues=$((total_issues + profile_issues))
    
    # CIS compliance test
    local cis_issues
    test_cis_compliance
    cis_issues=$?
    total_issues=$((total_issues + cis_issues))
    
    # OPSEK compliance test
    local opsek_issues
    test_opsek_compliance
    opsek_issues=$?
    total_issues=$((total_issues + opsek_issues))
    
    echo
    if [[ $total_issues -eq 0 ]]; then
        success "All tests passed successfully!"
    else
        warn "$total_issues total issues found across all tests"
    fi
    
    return $total_issues
}

# Run tests if script is called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_all_tests
fi
