# Linux Hardening Tool

A comprehensive Linux hardening tool designed to enhance system security across multiple distributions (Debian/Ubuntu/CentOS/RHEL/Alma/Rocky/Fedora). This tool implements security best practices through modular, idempotent Bash scripts.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/linux-hardening.git
cd linux-hardening
```

2. Make the main script executable:
```bash
chmod +x main.sh
```

TODO GIF INSTALL

## Usage

Execute the script as root or via sudo:

```bash
sudo ./main.sh [options]
```

Available options:
- `--profile <profile>`: Select security profile (recommended, paranoid)
- `--dry-run`: Show actions without applying them
- `-v, --verbose`: Show detailed execution information
- `-y, --yes`: Skip confirmation prompts
- `-h, --help`: Display help information

Examples:
```bash
# Run with recommended profile
sudo ./main.sh --profile recommended

# Dry run with paranoid profile
sudo ./main.sh --profile paranoid --dry-run

# Run in verbose mode
sudo ./main.sh --profile recommended -v
```

## Project Structure

```
.
├── main.sh            # Main script
├── modules/           # Modular security components
│   ├── access/        # Access control modules
│   │   ├── banners.sh   # Security banners
│   │   ├── ssh.sh       # SSH hardening
│   │   ├── sudo.sh      # Sudo configuration
│   │   └── users.sh     # User/group security
│   ├── core/          # Core functionality
│   │   ├── common.sh    # Shared functions
│   │   └── summary.sh   # Execution summary
│   ├── filesystem/    # Filesystem security
│   │   ├── filesystem.sh  # Filesystem hardening
│   │   └── permissions.sh # File permissions
│   ├── network/       # Network security
│   │   ├── fail2ban.sh   # Intrusion prevention
│   │   ├── firewall.sh   # Firewall rules
│   │   └── network.sh    # Network hardening
│   ├── services/      # Service hardening
│   │   ├── cron.sh      # Cron security
│   │   └── services.sh   # Service configuration
│   └── system/        # System hardening
│       ├── info.sh      # System information
│       ├── kernel.sh    # Kernel hardening
│       ├── logging.sh   # System logging
│       └── updates.sh   # System updates
└── LICENSE

## Module Features

### Access Control (`access/`)
- `banners.sh`: Security banners for login screens
- `ssh.sh`: SSH daemon hardening (ports, auth methods, ciphers)
- `sudo.sh`: Secure sudo configuration
- `users.sh`: User account security and password policies

### Core (`core/`)
- `common.sh`: Shared functions, platform detection, logging
- `summary.sh`: Execution reporting and status

### Filesystem (`filesystem/`)
- `filesystem.sh`: Mount options, tmp dirs, sticky bits
- `permissions.sh`: Critical file permissions, umask settings

### Network (`network/`)
- `fail2ban.sh`: Intrusion prevention (paranoid profile only)
- `firewall.sh`: UFW/firewalld rules and policies
- `network.sh`: TCP/IP stack hardening, IPv6 settings

### Services (`services/`)
- `cron.sh`: Cron/at access control
- `services.sh`: Service hardening and unnecessary service removal

### System (`system/`)
- `info.sh`: System information gathering
- `kernel.sh`: Kernel parameter hardening
- `logging.sh`: System logging configuration
- `updates.sh`: System updates and package security

## Security Profiles

### Recommended Profile
- Standard secure configuration
- Balanced security vs usability
- Suitable for most production systems

### Paranoid Profile
- Maximum security settings
- Additional security measures:
  - Stricter firewall rules
  - Fail2ban enabled
  - More restrictive SSH settings
  - Additional filesystem restrictions
  - Enhanced auditing
  - Stricter process limits

## Warnings

**Important: Read Before Use**

1. **Testing Environment**
   - Always test in a pre-production environment first
   - Create system backups before applying hardening
   - Document your current configuration

2. **Service Impact**
   - Hardening may break existing services
   - Use `--module` to apply changes gradually
   - The paranoid profile may require additional configuration
   - Some changes require system restart

3. **Access Considerations**
   - SSH configuration changes may affect remote access
   - Firewall rules might block necessary services
   - Password policies may affect user access
   - Some changes are not easily reversible

4. **Platform Specific**
   - Not all measures apply to all distributions
   - Some features require specific package versions
   - Custom configurations may conflict with hardening

For emergency recovery:
- Backups are stored in `/var/backups/linux-harden/`
- Use `--dry-run` to preview changes
- Consider maintaining an emergency access procedure
