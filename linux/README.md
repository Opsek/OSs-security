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
```

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

⚠️ **Important considerations before use:**

1. **Backup**: Always backup your system before running the hardening script
2. **Testing**: Use the `--dry-run` option first to preview changes
3. **System Impact**: Some security measures may affect system functionality or user experience
4. **Root Access**: The script requires root privileges to apply system-level changes
5. **Recovery**: Some changes may be difficult to reverse - review the settings carefully
6. **Compatibility**: Certain applications may not work properly under strict security profiles

For any issues or questions, please open an issue on the project repository.

For emergency recovery:
- Backups are stored in `/var/backups/linux-harden/`
- Use `--dry-run` to preview changes
- Consider maintaining an emergency access procedure
