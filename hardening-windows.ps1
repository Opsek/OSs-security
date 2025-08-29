# Run as Administrator

# What CANNOT be fully automated without user interaction?
# Switching account to "standard"
# Manually adding protected folders
# Setting up Dynamic Lock with your phone
# Installing features like Windows Sandbox if not already present
# Some GPOs that have no reg.exe equivalent (possible with LGPO.exe)


$ErrorActionPreference = "Stop"

function Write-Log($msg) {
    Write-Host "[*] $msg" -ForegroundColor Cyan
}

function Ask-YesNo($question) {
    do {
        $response = Read-Host "$question [Y/N]"
    } while ($response -notmatch '^[YyNn]$')
    return $response -match '^[Yy]$'
}

Write-Host "`n==== Opsek Windows Hardening ====" -ForegroundColor Yellow

# --- Auto-applied modules ---

# --- UAC Always Notify (max level) ---
Write-Log "→ Enabling UAC (Always Notify)..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

# --- Enable Firewall ---
Write-Log "→ Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True

# --- Exploit protections (DEP, ASLR, SEHOP) ---
Write-Log "→ Enabling Exploit Protection (DEP, ASLR, SEHOP)..."
Set-MpPreference -PUAProtection Enabled
Set-ProcessMitigation -System -Enable DEP
Set-ProcessMitigation -System -Enable SEHOP
Set-ProcessMitigation -System -Enable BottomUp,ForceRelocateImages,HighEntropy

# --- Windows Update checks ---
Write-Log "→ Ensuring Windows Update is enabled..."
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# --- Enable Memory Integrity --- 
Write-Log "Enabling Memory Integrity..."
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
                 -Name "Enabled" -PropertyType DWord -Value 1 -Force

# --- Enable BitLocker if available ---
Write-Log "→ Checking for BitLocker support and system drive..."

try {
    $edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
    if ($edition -eq "Core") {
        Write-Log "→ BitLocker is not supported on Home edition."
    } elseif (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        Write-Log "→ BitLocker PowerShell module not found."
    } else {
        # --- BitLocker: Detect system drive ---
        $systemDrive = Get-WmiObject -Query "SELECT DeviceID FROM Win32_OperatingSystem" | ForEach-Object {
            $_.DeviceID.Replace(":", "")
        }

        $bitLockerStatus = Get-BitLockerVolume -MountPoint "$systemDrive`:"
        # --- Enable Bitlocker ---
        if ($bitLockerStatus.ProtectionStatus -eq 'Off') {
            Write-Log "→ Enabling BitLocker on $systemDrive`:..."
            Enable-BitLocker -MountPoint "$systemDrive`:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -Confirm:$false
        } else {
            Write-Log "→ BitLocker already enabled or in valid state."
        }
    }
} catch {
    Write-Log "BitLocker error: $_"
}

# --- Enable Credential Guard ---
Write-Log "→ Enabling Credential Guard..."
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f

# --- Disable Office macros (Word) ---
Write-Log "→ Disabling Office Word macros..."
$officeKey = "HKCU:\Software\Microsoft\Office\16.0\Word\Security"
New-Item -Path $officeKey -Force | Out-Null
New-ItemProperty -Path $officeKey -Name "VBAWarnings" -PropertyType DWord -Value 4 -Force | Out-Null

# --- Set Screen timeout ---
Write-Log "→ Setting screen timeout to 1 minute..."
powercfg /change monitor-timeout-ac 1
powercfg /change monitor-timeout-dc 1

# --- Enable LSA Protection (RunAsPPL ---
Write-Log "→ Enabling LSA Protection (RunAsPPL)..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

# --- Hide last logged-on user ---
Write-Log "→ Hiding last logged-on user at logon screen..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLastUserName /t REG_DWORD /d 1 /f

# --- Disable Remote Desktop ---
Write-Log "→ Disabling Remote Desktop..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1

# --- Check Secure Boot ---
try {
    if (Confirm-SecureBootUEFI) {
        Write-Log "Secure Boot is enabled."
    } else {
        Write-Log "Secure Boot is NOT enabled. Consider enabling it in UEFI settings."
    }
} catch {
    Write-Log "Secure Boot check not supported on this system."
}

# --- Disable SMBv1 ---
Write-Log "→ Disabling legacy SMBv1 protocol..."
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart


# --- User-interactive modules ---
Write-Log "`n2. Optional security features (user confirmation):"

# --- USB block ---
if (Ask-YesNo "Do you want to BLOCK installation of USB removable devices?") {
    Write-Log "→ Blocking USB removable device installation..."
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v DenyRemovableDevices /t REG_DWORD /d 1 /f
} else {
    Write-Log "→ Skipping USB block."
}

# --- Set DNS to 8.8.8.8 ---
if (Ask-YesNo "Do you want to set a secure DNS (8.8.8.8)?") {
    Write-Log "→ Setting secure DNS to 8.8.8.8..."
    Get-DnsClientServerAddress | ForEach-Object {
        Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses ("9.9.9.9")
    }
} else {
    Write-Log "→ Keeping current DNS configuration."
}

# --- Controlled Folder Access ---
if (Ask-YesNo "Enable Controlled Folder Access? (may block legitimate apps)") {
    Write-Log "→ Enabling Controlled Folder Access..."
    Set-MpPreference -EnableControlledFolderAccess Enabled
} else {
    Write-Log "→ Skipping Controlled Folder Access."
}

Write-Log "Hardening complete. Please reboot your system to apply all settings."
