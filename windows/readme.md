# 🛡️ Windows hardening script

A PowerShell script to apply essential Windows hardening measures.  
Must run as **Administrator** for full effect.

---

## ⚠️ What cannot be fully automated
Some hardening steps require **manual user action** and are not included in automation:
- Switching your main account to **Standard User**
- Manually adding **Protected Folders** in Windows Security
- Setting up **Dynamic Lock** with your phone
- Installing optional features (e.g. **Windows Sandbox**) if not already installed
- Some **Group Policies** that have no `reg.exe` equivalent (possible with `LGPO.exe`)

---

## 🚀 Usage

### ⚠️ Security Warning - Read First!
**Never execute scripts directly from the internet without review!** Always:
1. Download the script first
2. Review the code to understand what it does
3. Only execute after you've verified it's safe

### Option 1 – Run directly from PowerShell

Open **PowerShell as Administrator** and paste this one-liner:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force ; irm 'https://raw.githubusercontent.com/Opsek/OSs-security/refs/heads/main/windows/hardening-windows.ps1' | iex
```

### Option 2 – Download and run manually
1. [Download windows-hardening.ps1](https://github.com/Opsek/OSs-security/blob/main/windows/hardening-windows.ps1)  
2. Right-click the downloaded file → **Run with PowerShell** (as Administrator).

---

## 🔧 Automated hardening commands


| Command | What we are doing | What it protects from | Edition Support |
|---------|------------------|------------------------|------------------|
| `Set-ItemProperty ... ConsentPromptBehaviorAdmin 2` | Force UAC to **Always Notify** | Prevents silent privilege escalation | All |
| `Set-NetFirewallProfile ...` | Enable Firewall (Domain, Public, Private) | Blocks unauthorized inbound/outbound traffic | All |
| `Set-ProcessMitigation ...` | Enable **DEP, ASLR, SEHOP** | Stops memory-based exploits | **Pro+** (skipped on Home) |
| `Set-MpPreference -PUAProtection Enabled` | Enable PUA protection | Blocks unwanted / malicious software | All |
| `Get-MpComputerStatus` | Verify Defender status | Detects if antivirus is disabled by GPO | All |
| `Set-Service wuauserv ...` | Ensure Windows Update is enabled | Protects against known vulnerabilities | All |
| `New-ItemProperty ... HypervisorEnforcedCodeIntegrity` | Enable **Memory Integrity** | Prevents kernel-level tampering | **Pro+** |
| `Get-BitLockerVolume / Enable-BitLocker` | Enable BitLocker with TPM protector | Protects data at rest from theft | **Pro+** (Home: Device Encryption) |
| `Get-Tpm` | Verify TPM presence before BitLocker | Ensures cryptographic strength | **Pro+** |
| `reg add ... DeviceGuard / LsaCfgFlags` | Enable **Credential Guard** (with CPU check) | Protects credentials from theft (Mimikatz, etc.) | **Pro+** (Home: skipped) |
| `reg add ... VBAWarnings=4` | Disable Office Word macros | Blocks macro-based malware | All |
| `powercfg /change monitor-timeout-ac 1` | Set screen timeout to 1 min | Reduces risk from unattended sessions | All |
| `reg add ... RunAsPPL=1` | Enable **LSA Protection** | Protects LSASS from credential dumping | All |
| `Set-ItemProperty ... fDenyTSConnections=1` | Disable Remote Desktop | Prevents RDP brute force attacks | All |
| `Disable-WindowsOptionalFeature -FeatureName SMB1Protocol` | Disable SMBv1 | Blocks exploitation via WannaCry/EternalBlue | All |
| `Confirm-SecureBootUEFI` | Check Secure Boot (UEFI only) | Protects boot chain from tampering | **UEFI systems** |
| `Set-ItemProperty ... HideFileExt=0` | Enable file extension visibility | Improves detection of suspicious files | All |
| `Set-ItemProperty ... TurnOffWindowsCopilot` | Disable Windows Copilot / AI | Reduces telemetry & data collection | All |
| `reg add ... DisableFileSyncNGSC=1` | Disable OneDrive cloud sync | Prevents forced cloud integration | All |
| Uninstall OneDrive client | remove OneDrive | Reduces bloatware & background processes | All |


---

## 🧩 Optional (User-confirmed) Modules

| Command | What we are doing | What it protects from | Notes |
|---------|------------------|------------------------|-------|
| `reg add ... DenyRemovableDevices=1` | Block USB removable device installation | Prevents USB malware / BadUSB | May break legitimate USB usage |
| `Set-DnsClientServerAddress ... 9.9.9.9` | Set secure DNS (Quad9) | Protects from DNS hijacking/malicious resolvers | With validation test |
| `Set-MpPreference -EnableControlledFolderAccess Enabled` | Enable Controlled Folder Access | Blocks ransomware from encrypting user data | May block legitimate apps |


## ⚡ Reboot Requirements

The following changes require a **system reboot** to take effect:

- ✅ Memory Integrity (Device Guard)
- ✅ Credential Guard
- ✅ LSA Protection (RunAsPPL)
- ✅ BitLocker encryption (initial setup)
- ✅ SMBv1 disable
- ✅ Most registry-based Group Policies

**The script will prompt you to reboot at the end.** Plan accordingly!

---

## 🔍 Troubleshooting

### Script fails with "Administrator privileges required"
- Run PowerShell as Administrator (right-click → "Run as administrator")

### BitLocker recovery key not displayed
- Check the audit log: `%TEMP%\Windows_Hardening_*.log`
- Recovery key is saved to the log file with [CRITICAL] severity

### Process mitigation fails on Home Edition
- This is expected. Home Edition doesn't support advanced process mitigation.
- The script automatically skips this with a message.

### DNS validation fails
- Check your internet connection
- Verify 9.9.9.9 (Quad9) is reachable in your network
- Check firewall rules for DNS (port 53)

### Credential Guard doesn't enable
- Check if CPU virtualization is enabled in BIOS
- Verify Windows edition is Pro or Enterprise
- Run: `systeminfo | findstr /C:"Hyper-V"`

## 📚 References

- [Windows Security Baselines (CIS)](https://www.cisecurity.org/benchmark/windows)
- [Microsoft Security Best Practices](https://docs.microsoft.com/en-us/security/)
- [BitLocker Deployment Guide](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-deployment-guide-planning)
- [Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
- [Windows Defender Guide](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/microsoft-defender-antivirus-in-windows-10)
- [Quad9 DNS](https://www.quad9.net/)
- [LSA Protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
