# 📱 MDM Hardening Module

This module generates Apple Mobile Device Management (MDM) profiles for macOS hardening. MDM profiles are the **recommended approach for macOS 26+** because they are maintained by Apple and persist through system upgrades.

## Overview

MDM profiles are XML-based configuration files (`.mobileconfig` format) that can be installed directly through **System Settings > General > Device Management**. Unlike direct configuration changes via scripts, MDM policies are:

✅ **Officially supported** by Apple  
✅ **Maintained** through OS updates  
✅ **Non-destructive** — easy to remove  
✅ **Reversible** — modify settings anytime  
✅ **No root required** — user can install  

## Quick Start

### Generate a Recommended Profile

```bash
./main.sh --generate-mdm
```

This generates `./mdm_profiles/recommended_hardening_profile.mobileconfig`

### Generate Other Profiles

```bash
# Strict hardening
./main.sh --generate-mdm --mdm-profile recommended

# Comprehensive (all policies)
./main.sh --generate-mdm --mdm-profile paranoid
```

### Installation Steps

1. **Run the generation command** above
2. **Open the `.mobileconfig` file**
   - Double-click the file, or
   - Terminal: `open path/to/profile.mobileconfig`
3. **System Settings opens** automatically
4. **Navigate to Device Management**
   - Settings > General > Device Management
5. **Review policies** and click **Install**
6. **Authenticate** with your password
7. **Verify** — profile appears in Device Management

## Available Profiles

### Basic Profile

Fundamental security controls for all users.

**Includes:**
- Password policy enforcement
- Automatic login disabled
- Gatekeeper enabled (app security)
- FileVault requirement


### Recommended Profile (Default)

Balanced security suitable for most organizations and users.

**Includes:**
- All Basic controls
- Remote access restrictions (SSH, file sharing)
- Automatic security updates
- System update enforcement
- AirDrop and sharing restrictions

### Paranoid Profile

Comprehensive hardening for security-conscious environments.

**Includes:**
- All Recommended controls
- Privacy preferences (screen recording, microphone restrictions)
- Audit and logging configuration
- Enhanced security settings

## Profile Payloads

Each profile consists of multiple payloads targeting specific hardening areas:

| Payload                              | Purpose                                           |
| ------------------------------------ | ------------------------------------------------- |
| **Password Policy**                  | Enforce password requirements                     |
| **Login Policy**                     | Disable automatic login                           |
| **Gatekeeper**                       | Enforce app signing verification                  |
| **FileVault Encryption**             | Require full-disk encryption                      |
| **Restrictions**                     | Disable remote access (SSH, file sharing)         |
| **Security & Privacy**               | Harden privacy settings                           |
| **Automatic Updates**                | Force security update installation                |
| **Privacy Preferences (TCC)**        | Control app permissions (screen recording, mic)   |
| **DNS Settings**                     | Configure hardened DNS servers                    |
| **Audit & Logging**                  | Enable system auditing                            |
| **Sharing Restrictions**             | Disable AirDrop and sharing features              |

## File Structure

```
modules/mdm/
├── README.md                    # This file
├── profile_generator.sh         # Main profile generation functions
└── policies.sh                  # MDM policy payload definitions
```

## Additional Resources

- [Apple MDM Documentation](https://developer.apple.com/documentation/devicemanagement)
- [Apple Configuration Profile Reference](https://developer.apple.com/business/documentation/Configuration-Profile-Reference.pdf)
- [macOS Security Best Practices](https://support.apple.com/en-us/HT207518)
- [CIS macOS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
