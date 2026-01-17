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

### Option 2 – Manual Download (Advanced)

1. [Download windows-hardening.ps1](https://github.com/Opsek/OSs-security/blob/main/windows/hardening-windows.ps1)  

2. Open **CMD as Administrator**

```cmd
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/Opsek/OSs-security/refs/heads/main/windows/hardening-windows.ps1' | iex"
```

### Option 3 – Download and run manually
1. [Download windows-hardening.ps1](https://github.com/Opsek/OSs-security/blob/main/windows/hardening-windows.ps1)  
2. Right-click the downloaded file → **Run with PowerShell** (as Administrator).

---

## 🔧 Automated hardening commands

| Command | What we are doing | What it protects from |
|---------|------------------|------------------------|
| `Set-ItemProperty ... ConsentPromptBehaviorAdmin 2` | Force UAC to **Always Notify** | Prevents silent privilege escalation |
| `Set-NetFirewallProfile ...` | Enable Firewall (Domain, Public, Private) | Blocks unauthorized inbound/outbound traffic |
| `Set-ProcessMitigation ...` | Enable **DEP, ASLR, SEHOP** | Stops memory-based exploits |
| `Set-MpPreference -PUAProtection Enabled` | Enable PUA protection | Blocks unwanted / malicious software |
| `Set-Service wuauserv ...` | Ensure Windows Update is enabled | Protects against known vulnerabilities |
| `New-ItemProperty ... HypervisorEnforcedCodeIntegrity` | Enable **Memory Integrity** | Prevents kernel-level tampering |
| `Enable-BitLocker -TpmProtector` | Enable BitLocker (if supported) | Protects data at rest from theft |
| `reg add ... DeviceGuard / LsaCfgFlags` | Enable **Credential Guard** | Protects credentials from theft (Mimikatz, etc.) |
| `reg add ... VBAWarnings=4` | Disable Office Word macros | Blocks macro-based malware |
| `powercfg /change monitor-timeout-ac 1` | Set screen timeout to 1 min | Reduces risk from unattended sessions |
| `reg add ... RunAsPPL=1` | Enable **LSA Protection** | Protects LSASS from credential dumping |
| `reg add ... DontDisplayLastUserName=1` | Hide last logged-in user | Mitigates username harvesting |
| `Set-ItemProperty ... fDenyTSConnections=1` | Disable Remote Desktop | Prevents RDP brute force attacks |
| `Disable-WindowsOptionalFeature -FeatureName SMB1Protocol` | Disable SMBv1 | Blocks exploitation via WannaCry/EternalBlue |
| `Confirm-SecureBootUEFI` | Check Secure Boot status | Protects boot chain from tampering |

---

## 🧩 Optional (User-confirmed) Modules

| Command | What we are doing | What it protects from |
|---------|------------------|------------------------|
| `reg add ... DenyRemovableDevices=1` | Block USB removable device installation | Prevents USB malware / BadUSB |
| `Set-DnsClientServerAddress ... 8.8.8.8` | Set secure DNS (Google) | Protects from DNS hijacking/malicious resolvers |
| `Set-MpPreference -EnableControlledFolderAccess Enabled` | Enable Controlled Folder Access | Blocks ransomware from encrypting user data |
