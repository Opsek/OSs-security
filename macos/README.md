# macOS Hardening Script

This project provides a comprehensive security hardening solution for macOS systems, integrating both CIS (Center for Internet Security) benchmarks and OPSEK-specific security measures. It is designed to enhance the security posture of macOS machines through automated configuration and hardening processes. 

> **Requires Administrator privileges** for full effect.

---

## Important Warnings

Before running the script:

1. **Backup your system** — some actions may be difficult to revert
2. **Test first using** `--dry-run` to preview changes
3. **Expect behavior changes** — strict security measures may impact applications
4. **Requires root access** — run with `sudo`
5. **Manual configuration may still be required** for certain protections (e.g. FileVault, full Lockdown Mode)
6. **Application compatibility** is not guaranteed under highly restricted profiles

---

## Installation

```bash
git clone <repository-url>
cd macos-hardening
chmod +x main.sh
```

Review `config/settings.conf` before execution to adjust default policy settings.

---

## Usage

![Demo](assets/macos_howto.gif)

The script provides different security profiles depending on your security needs:

```bash
# Default recommended profile
sudo ./main.sh

# Test mode (no changes applied)
sudo ./main.sh --dry-run

# Run with compliance checks only
sudo ./main.sh --checks

# Maximum restrictions (may affect usability)
sudo ./main.sh --paranoid

# Enable Lockdown-compatible restrictions (macOS 13+)
sudo ./main.sh --lockdown
```

### Available profiles

| Profile         | Description                                                 |
| --------------- | ----------------------------------------------------------- |
| **recommended** | Balanced security for most users                            |
| **paranoid**    | Maximum hardening for high-risk environments                |
| **lockdown**    | Activates Lockdown Mode compatible restrictions (macOS 13+) |

---

## Hardening Capabilities

### System Security

| Command                    | What we do                         | What it protects                               |
| -------------------------- | ---------------------------------- | ---------------------------------------------- |
| `update_system`            | Keep system and packages updated   | Prevents exploitation of known vulnerabilities |
| `enable_gatekeeper`        | Enforce app signing/notarization   | Blocks malicious or unauthorized apps          |
| `configure_hibernate_mode` | Secure sleep/hibernation states    | Stops data exposure from RAM or sleep image    |
| `harden_kernel`            | Apply kernel security parameters   | Hardens against kernel exploitation            |
| `fix_system_permissions`   | Repair system file permissions     | Prevents privilege escalation                  |
| `fix_library_permissions`  | Secure user & system library paths | Stops code injection & abuse                   |

---

### Network Security

| Command                       | What we do                           | What it protects                   |
| ----------------------------- | ------------------------------------ | ---------------------------------- |
| `enable_firewall`             | Enable & enforce macOS firewall      | Blocks unauthorized network access |
| `disable_internet_sharing`    | Disable hotspot and sharing features | Prevents rogue access              |
| `disable_remote_apple_events` | Block remote AppleScript control     | Avoids remote code execution       |
| `disable_bonjour`             | Disable mDNS where not required      | Reduces network exposure radius    |
| `disable_wake_on_lan`         | Disable remote wake                  | Stops remote manipulation          |
| `disable_ipv6_on_interfaces`  | Disable IPv6 on unused interfaces    | Mitigates IPv6-based attacks       |

---

### Access Control

| Command                      | What we do                       | What it protects                          |
| ---------------------------- | -------------------------------- | ----------------------------------------- |
| `disable_automatic_login`    | Require login on boot            | Prevents local unauthorized access        |
| `require_password_wake`      | Password required after sleep    | Protects against physical access          |
| `configure_password_policy`  | Enforce strong password rules    | Stops weak password compromise            |
| `disable_guest_account`      | Disable guest login              | Prevents anonymous access                 |
| `disable_root_account`       | Lock root user                   | Prevents root login abuse                 |
| `configure_sudo_timeout`     | Reduce sudo session lifetime     | Limits privilege escalation               |
| `require_admin_system_prefs` | Admin needed for system settings | Prevents unauthorized system modification |

---

### Privacy & Data Protection

> ⚠️ **FileVault must be enabled manually** (System Settings → Privacy & Security → FileVault)

| Command                         | What we do                    | What it protects                 |
| ------------------------------- | ----------------------------- | -------------------------------- |
| `secure_home_folders`           | Secure access permissions     | Prevent cross-user data exposure |
| `configure_privacy_settings`    | Harden privacy preferences    | Minimize tracking & data leakage |
| `disable_location_services`     | Restrict geolocation services | Block location-based tracking    |
| `disable_spotlight_suggestions` | Disable online Suggestions    | Stop data sent externally        |
| `disable_diagnostics`           | Disable analytics upload      | Prevent telemetry exfiltration   |

---

### Lockdown Mode Protection (macOS 13+)

Specialized configuration for environments facing highly targeted attacks.

| Command                | What we do                                  | What it protects                                    |
| ---------------------- | ------------------------------------------- | --------------------------------------------------- |
| `enable_lockdown_mode` | Apply Lockdown Mode compatible restrictions | Reduces zero-click and spyware exploitation surface |

This includes:

✔ Harden Safari & WebKit
✔ Disable JIT & advanced web rendering (WebGL, plugins)
✔ Block external/remote content loading
✔ FaceTime protections
✔ Messages safety enhancements
✔ OS-level Lockdown preference flags

> ⚠️ When using `--lockdown`, **complete Lockdown Mode still must be manually activated**:
> **System Settings → Privacy & Security → Lockdown Mode → Turn On…**

---

## Repository Structure

```
macos-hardening/
├── README.md
├── main.sh
├── config/
│   ├── profiles.conf
│   └── settings.conf
├── modules/
│   ├── cis/
│   │   ├── system.sh
│   │   ├── network.sh
│   │   ├── services.sh
│   │   ├── permissions.sh
│   │   └── users.sh
│   └── internals/
│       ├── bluetooth.sh
│       ├── wifi.sh
│       ├── lockdown.sh
│       ├── privacy.sh
│       └── kernel.sh
├── utils/
│   ├── common.sh
│   ├── logging.sh
│   └── backup.sh
└── checks/
    ├── cis_checks.sh
    └── opsek_checks.sh
```

---

## Support

Found a bug? Have a request?
Please open an issue in the project repository.

