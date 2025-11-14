# 🛡️ Linux Hardening Script

A comprehensive Bash script to enhance system security across multiple Linux distributions (Debian/Ubuntu/CentOS/RHEL/Alma/Rocky/Fedora).
Must run as **root** for full effect.

---

## ⚠️ What cannot be fully automated
Some hardening steps require **manual user action** and are not included in automation:
- Setting up **Full Disk Encryption** during OS installation
- Configuring **BIOS/UEFI passwords** and security settings
- Implementing physical server security measures
- Regularly reviewing system and application logs for anomalies
- Application-specific hardening (e.g., web server, database configurations)

---

## 🚀 Usage

### Download and run manually
1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/linux-hardening.git
    cd linux-hardening
    ```
2.  Make the main script executable:
    ```bash
    chmod +x main.sh
    ```
3.  Execute the script as root:
    ```bash
    sudo ./main.sh --profile recommended
    ```

---

## 🔧 Automated Hardening Commands (Recommended Profile)

| Module | What we are doing | What it protects from |
|---|---|---|
| `updates.sh` | Ensure system is fully updated | Exploitation of known vulnerabilities |
| `kernel.sh` | Harden kernel parameters (`sysctl`) | Various network and memory-based attacks |
| `ssh.sh` | Secure SSH configuration | Brute-force attacks and unauthorized access |
| `firewall.sh` | Enable and configure `ufw`/`firewalld` | Unauthorized inbound/outbound network traffic |
| `users.sh` | Enforce strong password policies | Weak or compromised user credentials |
| `sudo.sh` | Secure `sudo` configuration | Privilege escalation via `sudo` misconfigurations |
| `filesystem.sh` | Harden filesystem mount options | Execution of unauthorized code from temp dirs |
| `permissions.sh` | Set secure permissions on critical files | Unauthorized file modification or access |
| `logging.sh` | Configure system-wide auditing | Helps in detecting and investigating breaches |
| `banners.sh` | Set legal/warning login banners | Discourages unauthorized access attempts |
| `network.sh` | Harden TCP/IP stack | Network-level attacks like IP spoofing, SYN floods |
| `services.sh` | Disable unnecessary services | Reducing the system's attack surface |
| `cron.sh` | Restrict `cron` and `at` usage | Unauthorized scheduled task execution |

---

## 🧩 Optional Modules (Paranoid Profile)

| Module | What we are doing | What it protects from |
|---|---|---|
| `fail2ban.sh` | Install and configure Fail2ban | Automated brute-force attacks on services (SSH, etc.) |
| *Stricter Rules* | Apply more restrictive SSH, firewall, and process limits | Advanced threats and determined attackers |
| *Enhanced Auditing* | Configure more verbose system auditing | Provides deeper insight for forensic analysis |

---

## ⚠️ Important Considerations

1.  **Backup**: Always **backup your system** before running the hardening script. Backups are stored in `/var/backups/linux-harden/`.
2.  **Testing**: Use the `--dry-run` option first to preview changes without applying them.
    ```bash
    sudo ./main.sh --profile recommended --dry-run
    ```
3.  **System Impact**: Some security measures, especially in the `paranoid` profile, may affect system functionality or application compatibility.
4.  **Root Access**: The script requires root privileges to apply system-level changes.
5.  **Recovery**: Review settings carefully. Some changes may be difficult to reverse without restoring from a backup.
