#!/usr/bin/env bash

# ==============================================================================
# Installation script for macOS hardening project
# ==============================================================================

set -euo pipefail

# Reuse shared logging utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils/logging.sh"

# Check prerequisites
check_prereqs() {
    info "Checking prerequisites..."
    
    # Check macOS
    if [[ "$(uname)" != "Darwin" ]]; then
        error "This script is designed for macOS only"
        exit 1
    fi
    
    # Check macOS version
    local os_version="$(sw_vers -productVersion)"
    local major_version="$(echo "$os_version" | cut -d. -f1)"
    
    if [[ $major_version -lt 13 ]]; then
        warn "This script is optimized for macOS 13+ (current: $os_version)"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    
    # Check required commands
    local required_commands=("git" "bash" "chmod")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    success "Prerequisites check passed"
}

# Install dependencies
install_dependencies() {
    info "Installing dependencies..."
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Install necessary tools
    local packages=("bash" "git")
    for package in "${packages[@]}"; do
        if ! brew list "$package" &> /dev/null; then
            info "Installing $package..."
            brew install "$package"
        else
            success "$package is already installed"
        fi
    done
}

# Configure permissions
setup_permissions() {
    info "Setting up file permissions..."
    
    # Make main script executable
    chmod +x main.sh
    
    # Make modules executable
    find modules/ -name "*.sh" -exec chmod +x {} \;
    find utils/ -name "*.sh" -exec chmod +x {} \;
    find checks/ -name "*.sh" -exec chmod +x {} \;
    find tests/ -name "*.sh" -exec chmod +x {} \;
    
    success "File permissions configured"
}

# Create necessary directories
create_directories() {
    info "Creating necessary directories..."
    
    local dirs=(
        "/var/backups/macos_hardening"
        "/var/log"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            sudo mkdir -p "$dir"
            success "Created directory: $dir"
        else
            info "Directory already exists: $dir"
        fi
    done
}

# Test installation
test_installation() {
    info "Testing installation..."
    
    # Validation test
    if ./tests/validation.sh; then
        success "Validation tests passed"
    else
        warn "Validation tests failed"
    fi
    
    # Compliance test
    if ./tests/compliance.sh; then
        success "Compliance tests passed"
    else
        warn "Compliance tests failed"
    fi
}

# Display post-installation information
show_post_install_info() {
    echo
    success "Installation completed successfully!"
    echo
    info "Next steps:"
    echo "1. Review the configuration files in config/"
    echo "2. Test the installation: ./tests/validation.sh"
        echo "3. Run a dry-run test: sudo ./main.sh --dry-run"
        echo "4. Apply hardening: sudo ./main.sh"
    echo
    info "Documentation:"
    echo "- README.md: General information"
    echo "- INSTALL.md: Installation guide"
    echo "- CONTRIBUTING.md: Contribution guide"
    echo
    warn "IMPORTANT: Always test with --dry-run before applying changes!"
}

# Main function
main() {
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║                       macOS Security Hardening Script                        ║"
    echo "║                              OPSEK Integration                               ║"
    echo "║                                Installation                                  ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo
    
    check_prereqs
    install_dependencies
    setup_permissions
    create_directories
    test_installation
    show_post_install_info
}

# Run installation
main "$@"
