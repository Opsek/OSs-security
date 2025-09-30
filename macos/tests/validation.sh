#!/usr/bin/env bash

# ==============================================================================
# Validation tests for macOS hardening script
# ==============================================================================

# Load utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../utils/common.sh"
source "$SCRIPT_DIR/../utils/logging.sh"

# ==============================================================================
# VALIDATION FUNCTIONS
# ==============================================================================

# Validate project structure
validate_project_structure() {
    info "Validating project structure"
    
    local total_issues=0
    local required_dirs=(
        "config"
        "modules/cis"
        "modules/internals"
        "utils"
        "tests"
        "checks"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [[ -d "$SCRIPT_DIR/../$dir" ]]; then
            success "✓ Directory $dir exists"
        else
            warn "✗ Directory $dir missing"
            ((total_issues++))
        fi
    done
    
    return $total_issues
}

# Validate configuration files
validate_config_files() {
    info "Validating configuration files"
    
    local total_issues=0
    local config_files=(
        "config/settings.conf"
        "config/profiles.conf"
    )
    
    for file in "${config_files[@]}"; do
        if [[ -f "$SCRIPT_DIR/../$file" ]]; then
            success "✓ Configuration file $file exists"
        else
            warn "✗ Configuration file $file missing"
            ((total_issues++))
        fi
    done
    
    return $total_issues
}

# Validate CIS modules
validate_cis_modules() {
    info "Validating CIS modules"
    
    local total_issues=0
    local cis_modules=(
        "modules/cis/system.sh"
        "modules/cis/network.sh"
        "modules/cis/services.sh"
        "modules/cis/permissions.sh"
        "modules/cis/users.sh"
    )
    
    for module in "${cis_modules[@]}"; do
        if [[ -f "$SCRIPT_DIR/../$module" ]]; then
            success "✓ CIS module $module exists"
        else
            warn "✗ CIS module $module missing"
            ((total_issues++))
        fi
    done
    
    return $total_issues
}

# Validate OPSEK modules
validate_opsek_modules() {
    info "Validating OPSEK modules"
    
    local total_issues=0
    local opsek_modules=(
        "modules/internals/bluetooth.sh"
        "modules/internals/wifi.sh"
        "modules/internals/lockdown.sh"
        "modules/internals/privacy.sh"
        "modules/internals/kernel.sh"
    )
    
    for module in "${opsek_modules[@]}"; do
        if [[ -f "$SCRIPT_DIR/../$module" ]]; then
            success "✓ OPSEK module $module exists"
        else
            warn "✗ OPSEK module $module missing"
            ((total_issues++))
        fi
    done
    
    return $total_issues
}

# Validate utilities
validate_utilities() {
    info "Validating utility modules"
    
    local total_issues=0
    local utility_files=(
        "utils/common.sh"
        "utils/logging.sh"
        "utils/backup.sh"
        "checks/cis_checks.sh"
        "checks/opsek_checks.sh"
    )
    
    for file in "${utility_files[@]}"; do
        if [[ -f "$SCRIPT_DIR/../$file" ]]; then
            success "✓ Utility $file exists"
        else
            warn "✗ Utility $file missing"
            ((total_issues++))
        fi
    done
    
    return $total_issues
}

# Validate file permissions
validate_file_permissions() {
    info "Validating file permissions"
    
    local total_issues=0
    
    # Check that main script is executable
    if [[ -x "$SCRIPT_DIR/../main.sh" ]]; then
        success "✓ main.sh is executable"
    else
        warn "✗ main.sh is not executable"
        ((total_issues++))
    fi
    
    # Check that modules are executable
    local modules=(
        "modules/cis/system.sh"
        "modules/cis/network.sh"
        "modules/cis/services.sh"
        "modules/cis/permissions.sh"
        "modules/cis/users.sh"
        "modules/internals/bluetooth.sh"
        "modules/internals/wifi.sh"
        "modules/internals/lockdown.sh"
        "modules/internals/privacy.sh"
        "modules/internals/kernel.sh"
        "utils/common.sh"
        "utils/logging.sh"
        "utils/backup.sh"
        "checks/cis_checks.sh"
        "checks/opsek_checks.sh"
        "tests/compliance.sh"
        "tests/validation.sh"
    )
    
    for module in "${modules[@]}"; do
        if [[ -x "$SCRIPT_DIR/../$module" ]]; then
            success "✓ $module is executable"
        else
            warn "✗ $module is not executable"
            ((total_issues++))
        fi
    done
    
    return $total_issues
}

# Validate script syntax
validate_script_syntax() {
    info "Validating script syntax"
    
    local total_issues=0
    local scripts=(
        "main.sh"
        "modules/cis/system.sh"
        "modules/cis/network.sh"
        "modules/cis/services.sh"
        "modules/cis/permissions.sh"
        "modules/cis/users.sh"
        "modules/internals/bluetooth.sh"
        "modules/internals/wifi.sh"
        "modules/internals/lockdown.sh"
        "modules/internals/privacy.sh"
        "modules/internals/kernel.sh"
        "utils/common.sh"
        "utils/logging.sh"
        "utils/backup.sh"
        "checks/cis_checks.sh"
        "checks/opsek_checks.sh"
        "tests/compliance.sh"
        "tests/validation.sh"
    )
    
    for script in "${scripts[@]}"; do
        if bash -n "$SCRIPT_DIR/../$script" 2>/dev/null; then
            success "✓ $script syntax is valid"
        else
            warn "✗ $script syntax is invalid"
            ((total_issues++))
        fi
    done
    
    return $total_issues
}

# ==============================================================================
# MAIN VALIDATION FUNCTION
# ==============================================================================

run_all_validations() {
    info "=== Running All Validation Tests ==="
    
    local total_issues=0
    
    # Validate project structure
    local structure_issues
    validate_project_structure
    structure_issues=$?
    total_issues=$((total_issues + structure_issues))
    
    # Validate configuration files
    local config_issues
    validate_config_files
    config_issues=$?
    total_issues=$((total_issues + config_issues))
    
    # Validate CIS modules
    local cis_issues
    validate_cis_modules
    cis_issues=$?
    total_issues=$((total_issues + cis_issues))
    
    # Validate OPSEK modules
    local opsek_issues
    validate_opsek_modules
    opsek_issues=$?
    total_issues=$((total_issues + opsek_issues))
    
    # Validate utilities
    local utility_issues
    validate_utilities
    utility_issues=$?
    total_issues=$((total_issues + utility_issues))
    
    # Validate file permissions
    local permission_issues
    validate_file_permissions
    permission_issues=$?
    total_issues=$((total_issues + permission_issues))
    
    # Validate script syntax
    local syntax_issues
    validate_script_syntax
    syntax_issues=$?
    total_issues=$((total_issues + syntax_issues))
    
    echo
    if [[ $total_issues -eq 0 ]]; then
        success "All validations passed successfully!"
    else
        warn "$total_issues total issues found across all validations"
    fi
    
    return $total_issues
}

# Run validations if script is called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_all_validations
fi
