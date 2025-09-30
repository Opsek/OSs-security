# macOS Hardening Script

## Introduction

This project provides a comprehensive security hardening solution for macOS systems, integrating both CIS (Center for Internet Security) benchmarks and OPSEK-specific security measures. It is designed to enhance the security posture of macOS machines through automated configuration and hardening processes.

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd macos-hardening
```

2. Make the main script executable:
```bash
chmod +x main.sh
```

3. Review the configuration in `config/settings.conf` and adjust if needed.



TODO GIF INSTALL


## Usage

The script supports different security profiles to match your security requirements:

```bash
```bash
# Run with recommended profile (suitable for most users)
sudo ./main.sh --profile recommended

# Run in test mode (dry-run)
sudo ./main.sh --profile recommended --dry-run

# Run with compliance checks
sudo ./main.sh --profile recommended --checks
```

Available profiles:
- **recommended**: Balanced security suitable for most environments
- **paranoid**: Maximum security (may affect system functionality)

## Structure

The project follows a modular structure for better organization and maintainability:

- `main.sh`: Primary script that orchestrates the hardening process
- `config/`: Configuration files for profiles and settings
- `modules/`: Core functionality modules
  - `cis/`: CIS benchmark implementation modules
  - `internals/`: OPSEK-specific security modules
- `utils/`: Utility scripts for common functions
- `checks/`: Compliance and verification scripts
- `tests/`: Testing and validation scripts

```
macos-hardening/
├── README.md
├── main.sh                    # Main script
├── config/
│   ├── profiles.conf          # Profile configuration
│   └── settings.conf          # General settings
├── modules/
│   ├── cis/                   # CIS Benchmark modules
│   │   ├── system.sh          # System configuration
│   │   ├── network.sh         # Network configuration
│   │   ├── services.sh        # System services
│   │   ├── permissions.sh     # Permissions and security
│   │   └── users.sh           # User configuration
│   └── internals/             # OPSEK modules
│       ├── bluetooth.sh       # Bluetooth management
│       ├── wifi.sh           # Wi-Fi management
│       ├── lockdown.sh       # Lockdown mode
│       ├── privacy.sh       # Privacy settings
│       └── kernel.sh        # Kernel hardening
├── utils/
│   ├── common.sh             # Common utility functions
│   ├── logging.sh            # Logging system
│   └── backup.sh             # Backup management
├── checks/
│   ├── cis_checks.sh         # CIS compliance checks
│   └── opsek_checks.sh       # OPSEK compliance checks
└── tests/
    ├── compliance.sh         # Compliance tests
    └── validation.sh         # Configuration validation
```


## Available Hardening Functions

The script includes various security functions organized by category:

### System Security
- `update_system`: Ensures system is up to date
- `enable_gatekeeper`: Enforces app signing and notarization
- `configure_hibernate_mode`: Secures system sleep and hibernation
- `harden_kernel`: Applies kernel-level security parameters
- `fix_system_permissions`: Corrects system file permissions
- `fix_library_permissions`: Secures library permissions

### Network Security
- `enable_firewall`: Activates and configures the built-in firewall
- `disable_internet_sharing`: Prevents unauthorized network sharing
- `disable_remote_apple_events`: Blocks remote Apple events
- `disable_bonjour`: Disables multicast advertising
- `disable_wake_on_lan`: Prevents network wake-up capabilities
- `disable_ipv6_on_interfaces`: Disables IPv6 when not needed

### Access Control
- `disable_automatic_login`: Requires authentication at startup
- `require_password_wake`: Enforces authentication after sleep
- `configure_password_policy`: Sets strong password requirements
- `disable_guest_account`: Removes guest access
- `disable_root_account`: Secures root account
- `configure_sudo_timeout`: Sets sudo command timeout
- `require_admin_system_prefs`: Requires admin for system changes

### Privacy & Data Protection
- `enable_filevault`: Activates full disk encryption
- `secure_home_folders`: Protects user home directories
- `configure_privacy_settings`: Sets privacy preferences
- `disable_location_services`: Controls location tracking
- `disable_spotlight_suggestions`: Limits data collection
- `disable_diagnostics`: Reduces system data reporting

### Service Management
- `disable_ssh`: Disables remote shell access
- `disable_printer_sharing`: Turns off printer sharing
- `disable_file_sharing`: Prevents file sharing
- `disable_screen_sharing`: Disables remote viewing
- `disable_remote_management`: Blocks remote administration
- `disable_unnecessary_daemons`: Stops unneeded services

### Wireless & Bluetooth
- `disable_wifi`: Deactivates wireless networking
- `disable_bluetooth_completely`: Turns off Bluetooth
- `disable_airdrop`: Disables AirDrop file sharing
- `disable_all_bluetooth_services`: Removes Bluetooth services

### Logging & Auditing
- `enable_security_auditing`: Activates security audit logs
- `configure_audit_flags`: Sets audit log parameters
- `configure_audit_retention`: Manages audit log retention
- `enhance_logging`: Increases system logging detail

### Application Security
- `disable_safari_safe_files`: Improves Safari security
- `secure_safari`: Applies Safari security settings
- `check_application_permissions`: Verifies app permissions
- `disable_siri_dictation`: Turns off voice input

### Authentication & Keychain
- `configure_keychain_lock`: Sets keychain security
- `configure_keychain_sleep_lock`: Locks keychain on sleep
- `secure_keychains`: Hardens keychain configuration

## Warnings

⚠️ **Important considerations before use:**

1. **Backup**: Always backup your system before running the hardening script
2. **Testing**: Use the `--dry-run` option first to preview changes
3. **System Impact**: Some security measures may affect system functionality or user experience
4. **Root Access**: The script requires root privileges to apply system-level changes
5. **Recovery**: Some changes may be difficult to reverse - review the settings carefully
6. **Compatibility**: Certain applications may not work properly under strict security profiles

For any issues or questions, please open an issue on the project repository.
