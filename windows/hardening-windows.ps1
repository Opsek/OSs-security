# Run as Administrator

# What CANNOT be fully automated without user interaction?
# Switching account to "standard"
# Manually adding protected folders
# Setting up Dynamic Lock with your phone
# Installing features like Windows Sandbox if not already present
# Some GPOs that have no reg.exe equivalent (possible with LGPO.exe)

# Audit log
$LogFile = "$env:TEMP\Windows_Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Log-Event($Message, $Severity = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Severity] $Message" | Tee-Object -FilePath $LogFile -Append | Out-Host
}

function Write-Log($msg) {
    Write-Host "[*] $msg" -ForegroundColor Cyan
}

function Ask-YesNo($question) {
    do {
        $response = Read-Host "$question [Y/N]"
    } while ($response -notmatch '^[YyNn]$')
    return $response -match '^[Yy]$'
}

function Invoke-Safe {
    param(
        [string]$Message,
        [scriptblock]$Action
    )
    Write-Log $Message
    try {
        & $Action
    } catch {
        Write-Host "[!] $Message failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}


$ErrorActionPreference = "Stop"

# Verify elevation
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires administrative privileges. Please run PowerShell as Administrator."
    exit 1
}

# System information detection
$osVersion = [Environment]::OSVersion.Version
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
$osEdition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
$isVM = @("VirtualBox", "VMware", "Hyper-V", "QEMU") | ForEach-Object { if ((Get-CimInstance Win32_ComputerSystemProduct).Manufacturer -match $_) { $_ } }
$bootMode = (Get-CimInstance Win32_OperatingSystem).BootDevice
$isUEFI = Test-Path "HKLM:\System\CurrentControlSet\Control\SecureBoot\State"

Write-Log "OS: $osCaption (Edition: $osEdition, Build: $($osVersion.Build))"
Write-Log "VM Detected: $(if ($isVM) { "$isVM (Note: Some security features may be unavailable or behave differently)" } else { 'No' })"
Write-Log "Firmware: $(if ($isUEFI) { 'UEFI' } else { 'BIOS' })"


Write-Host "==== Opsek Windows Hardening ====" -ForegroundColor Yellow

# --- Auto-applied modules ---

Invoke-Safe "-> Enabling UAC (Always Notify)..." {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
}

Invoke-Safe "-> Enabling Windows Firewall..." {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
}

Invoke-Safe "-> Enabling Exploit Protection (DEP, ASLR, SEHOP)..." {
    if ($osEdition -eq "Core") {
        Write-Log "   (Skipped) Process mitigation not available on Home Edition."
    } else {
        try {
            Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
            Set-ProcessMitigation -System -Enable DEP -ErrorAction Stop
            Set-ProcessMitigation -System -Enable SEHOP -ErrorAction Stop
            Set-ProcessMitigation -System -Enable BottomUp,ForceRelocateImages,HighEntropy -ErrorAction Stop
        } catch {
            Log-Event "Process mitigation failed: $_" "WARNING"
        }
    }
}

Invoke-Safe "-> Ensuring Windows Update is enabled..." {
    try {
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction Stop
        Log-Event "Windows Update service enabled" "SUCCESS"
    } catch {
        Log-Event "Windows Update setup failed: $_" "WARNING"
    }
}

Invoke-Safe "-> Verifying Windows Defender health..." {
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        if ($defenderStatus.AntivirusEnabled) {
            Log-Event "Windows Defender: ENABLED" "SUCCESS"
        } else {
            Log-Event "Windows Defender: DISABLED (may be controlled by GPO)" "WARNING"
        }
    } catch {
        Log-Event "Defender status check not available on this system" "WARNING"
    }
}

Invoke-Safe "-> Enabling Memory Integrity..." {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Force | Out-Null
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -PropertyType DWord -Value 1 -Force | Out-Null
}

Invoke-Safe "-> Enabling Credential Guard (requires Hyper-V support)..." {
    # Credential Guard requires virtualization support
    if ($osEdition -eq "Core") {
        Write-Log "   (Skipped) Credential Guard not available on Home Edition."
    } else {
        try {
            $cpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
            if ($cpuInfo.VirtualizationFirmwareEnabled -eq $true) {
                reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f | Out-Null
                reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 1 /f | Out-Null
                reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f | Out-Null
                Log-Event "Credential Guard policy set (reboot required)" "SUCCESS"
            } else {
                Log-Event "CPU virtualization not enabled or not supported (Credential Guard cannot be enabled)" "WARNING"
            }
        } catch {
            Log-Event "Credential Guard setup failed: $_" "WARNING"
        }
    }
}

Invoke-Safe "-> Disabling Office Word macros for ALL local users..." {
    Write-Log "   WARNING: This setting affects ALL local user profiles."
    Write-Log "   Group Policy is recommended for enterprise environments."

    $profiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -and (Test-Path "$($_.LocalPath)\NTUSER.DAT") -and -not $_.Special }

    foreach ($profile in $profiles) {
        $sid = $profile.SID
        $hiveLoaded = Test-Path "Registry::HKEY_USERS\$sid"

        if (-not $hiveLoaded) {
            reg load "HKU\$sid" "$($profile.LocalPath)\NTUSER.DAT" | Out-Null
        }

        try {
            $officeKey = "Registry::HKEY_USERS\$sid\Software\Microsoft\Office\16.0\Word\Security"
            New-Item -Path $officeKey -Force | Out-Null
            New-ItemProperty -Path $officeKey -Name "VBAWarnings" -PropertyType DWord -Value 4 -Force | Out-Null

            Write-Log "Macros disabled for user SID: $sid"
        }
        finally {
            if (-not $hiveLoaded) {
                reg unload "HKU\$sid" | Out-Null
            }
        }
    }

    Log-Event "Office Word macros disabled for all local user profiles" "INFO"
}

Invoke-Safe "-> Setting screen timeout to 1 minute..." {
    powercfg /change monitor-timeout-ac 1
    powercfg /change monitor-timeout-dc 1
}

Invoke-Safe "-> Enabling LSA Protection (RunAsPPL)..." {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
}

Invoke-Safe "-> Disabling Remote Desktop..." {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
}

Invoke-Safe "-> Checking Secure Boot status..." {
    try {
        if (-not $isUEFI) {
            Write-Log "Secure Boot: Not available (BIOS firmware detected)."
        } elseif (Confirm-SecureBootUEFI) {
            Write-Log "Secure Boot: ENABLED"
        } else {
            Write-Log "Secure Boot: DISABLED. Consider enabling in UEFI settings."
        }
    } catch {
        Log-Event "Secure Boot check failed: $_" "WARNING"
    }
}

Invoke-Safe "-> Disabling legacy SMBv1 protocol..." {
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
}


Invoke-Safe "-> Disabling OneDrive via Group Policy..." {
    $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name "DisableFileSyncNGSC" -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Log "   Policy applied. A sign-out or reboot may be required for full effect."
}

if (Ask-YesNo "Do you want to UNINSTALL the OneDrive client?") {
    Invoke-Safe "-> Uninstalling OneDrive..." {
        Get-Process -Name OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $setupExes = @(
            "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
            "$env:SystemRoot\System32\OneDriveSetup.exe"
        )
        foreach ($exe in $setupExes) {
            if (Test-Path $exe) {
                Start-Process -FilePath $exe -ArgumentList "/uninstall" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Write-Log "   Executed: $exe /uninstall"
                break
            }
        }
    }
} else {
    Write-Log "-> Skipping OneDrive uninstall."
}

Invoke-Safe "-> Checking for Microsoft / online accounts..." {
    try {
        $users = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, PrincipalSource
        $onlineUsers = $users | Where-Object { $_.PrincipalSource -in @("MicrosoftAccount", "Domain", "Unknown") }

        if ($onlineUsers) {
            Write-Host "[!] Online / Microsoft-backed accounts detected:" -ForegroundColor Yellow
            $onlineUsers | Format-Table -AutoSize
            Write-Host "    Recommendation: migrate to local-only accounts." -ForegroundColor Yellow
        } else {
            Write-Log "No Microsoft / online accounts detected."
        }
    } catch {
        Write-Log "(Warning) Get-LocalUser not available on this system. Skipping account detection."
    }
}

Invoke-Safe "-> Enforcing password on wake / resume..." {
    # Require password on wake (machine policy)
    $key = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name "ACSettingIndex" -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $key -Name "DCSettingIndex" -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Log "   Machine-level power policy applied (AC and DC)."
    Write-Log "   WARNING: Screen saver password is user-level and requires per-user configuration."
    Write-Log "   Run 'control desk.cpl' as each user to set 'Password protected' screensaver."
}

Invoke-Safe "-> Enabling file extension visibility..." {
    try {
        # Apply to all users (machine policy)
        $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }

        # Use Set-ItemProperty when the value exists, fallback to New-ItemProperty when it does not
        if (Get-ItemProperty -Path $key -Name "HideFileExt" -ErrorAction SilentlyContinue) {
            Set-ItemProperty -Path $key -Name "HideFileExt" -Value 0 -ErrorAction Stop
        } else {
            New-ItemProperty -Path $key -Name "HideFileExt" -PropertyType DWord -Value 0 -Force | Out-Null
        }

        Write-Log "   Policy set: file extensions will be visible."
    } catch {
        Log-Event "Failed to set file extension visibility: $($_.Exception.Message)" "WARNING"
    }
}

Invoke-Safe "-> Disabling Windows Copilot / AI features..." {
    # Check if Copilot feature exists (Windows 11 23H2+)
    $copilotKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    
    try {
        # Disable Windows Copilot (machine policy)
        New-Item -Path $copilotKeyPath -Force | Out-Null
        New-ItemProperty -Path $copilotKeyPath -Name "TurnOffWindowsCopilot" -PropertyType DWord -Value 1 -Force | Out-Null
        Log-Event "Copilot disabled via machine policy" "SUCCESS"
    } catch {
        Log-Event "Copilot policy not available on this Windows version" "WARNING"
    }
    
    # Disable Copilot button (machine policy) - may not exist on older builds
    try {
        $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Shell\Copilot"
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name "IsCopilotAvailable" -PropertyType DWord -Value 0 -Force | Out-Null
    } catch {
        Write-Log "   Copilot button registry not available (older Windows version)"
    }
}

# --- User-interactive modules ---
Write-Log "2. Optional security features (user confirmation):"

if (Ask-YesNo "Enable disk encryption (BitLocker/Device Encryption)?") {
    Invoke-Safe "-> Checking for disk encryption options..." {
        $edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
        $systemDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive.TrimEnd(":")
        $hasEncryption = $false
        
        # Check for BitLocker (Pro/Enterprise)
        if ($edition -ne "Core" -and (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
            try {
                $bitLockerStatus = Get-BitLockerVolume -MountPoint "${systemDrive}:" -ErrorAction SilentlyContinue
                if ($bitLockerStatus.ProtectionStatus -eq 'On') {
                    Write-Log "BitLocker: ALREADY ENABLED on ${systemDrive}"
                    $hasEncryption = $true
                } 
                elseif ($bitLockerStatus.ProtectionStatus -eq 'Off') {
                    # Check TPM availability
                    try {
                        $tpmStatus = Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -ClassName Win32_Tpm -ErrorAction Stop
                        if ($tpmStatus) {
                            Write-Log "RECOMMENDED: BitLocker (with TPM protection)"
                            Write-Log "   TPM detected: Best encryption option for security"
                            
                            if (Ask-YesNo "Enable BitLocker on ${systemDrive}? (CRITICAL: Save recovery key)") {
                                Write-Log "-> Enabling BitLocker on ${systemDrive}:..."
                                Enable-BitLocker -MountPoint "${systemDrive}:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -Confirm:$false
                                
                                # Save recovery key
                                $recoveryKey = (Get-BitLockerVolume -MountPoint "${systemDrive}:" | Select-Object -ExpandProperty KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }).RecoveryPassword
                                if ($recoveryKey) {
                                    Log-Event "BitLocker Recovery Key: ${recoveryKey}" "CRITICAL"
                                    Write-Host "[!] SAVE THIS KEY IMMEDIATELY: ${recoveryKey}" -ForegroundColor Yellow
                                    $hasEncryption = $true
                                }
                            }
                        }
                    } catch {
                        Write-Log "WARNING: TPM not available; BitLocker can use password protector (less secure)"
                    }
                }
            } catch {
                Write-Log "BitLocker check failed"
            }
        } elseif ($edition -eq "Core") {
            Write-Log "BitLocker: Not available on Home Edition"
        }
        
        # Check for Device Encryption (Home Edition fallback)
        if (-not $hasEncryption) {
            try {
                $deStatus = Get-CimInstance -Namespace root\cimv2\security\microsoftvolumeencryption -ClassName Win32_EncryptableVolume -ErrorAction Stop
                if ($deStatus) {
                    Write-Log "Device Encryption: Available on this system"
                    Write-Log "   Settings - Privacy and Security - Device Encryption"
                    Write-Log "   Requires Microsoft account or PIN"
                    $hasEncryption = $true
                }
            } catch {
                Write-Log "No encryption feature detected on this system"
            }
        }
        
        if (-not $hasEncryption) {
            Write-Log "WARNING: No disk encryption is currently enabled!"
            Write-Log "   This leaves your data vulnerable if the device is lost or stolen."
        }
    }
} else {
    Write-Log "-> Skipping disk encryption configuration."
}

if (Ask-YesNo "Do you want to BLOCK installation of USB removable devices?") {
    Invoke-Safe "-> Blocking USB removable device installation..." {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v DenyRemovableDevices /t REG_DWORD /d 1 /f
    }
} else {
    Write-Log "-> Skipping USB block."
}

if (Ask-YesNo "Do you want to set a secure DNS (9.9.9.9)?") {
    Invoke-Safe "-> Setting secure DNS to 9.9.9.9..." {
        try {
            $dnsServers = Get-DnsClientServerAddress -ErrorAction Stop
            $updated = 0
            foreach ($dns in $dnsServers | Where-Object { $_.AddressFamily -eq 2 }) {  # IPv4 only
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $dns.InterfaceIndex -ServerAddresses "9.9.9.9" -ErrorAction Stop
                    $updated++
                } catch {
                    Log-Event "Failed to set DNS on interface $($dns.InterfaceIndex): $_" "WARNING"
                }
            }
            Log-Event "DNS updated on $updated interface(s)" "SUCCESS"
            Write-Log "   WARNING: DNS changes may not persist across network resets or VPN connections."
            Write-Log "   For persistent DNS: use Group Policy or configure static IP."
            
            # Validation
            $validationDNS = Resolve-DnsName -Name "example.com" -Server "9.9.9.9" -ErrorAction SilentlyContinue
            if ($validationDNS) {
                Log-Event "DNS validation successful" "SUCCESS"
            } else {
                Log-Event "DNS validation failed; verify connectivity" "WARNING"
            }
        } catch {
            Log-Event "DNS setup failed: $_" "ERROR"
        }
    }
} else {
    Write-Log "-> Keeping current DNS configuration."
}

if (Ask-YesNo "Enable Controlled Folder Access? (may block legitimate apps)") {
    Write-Log "   WARNING: Controlled Folder Access may block legitimate applications."
    Write-Log "   Protected folders: Documents, Desktop, Downloads, Pictures, Videos, Music."
    Write-Log "   You will need to manually allow apps in: Windows Security - Virus and threat protection"
    Write-Log "                                           - Manage settings - Allowed apps"
    
    if (Ask-YesNo "Do you really want to ENABLE Controlled Folder Access?") {
        Invoke-Safe "-> Enabling Controlled Folder Access..." {
            Set-MpPreference -EnableControlledFolderAccess Enabled
            Log-Event "Controlled Folder Access enabled" "SUCCESS"
            Write-Log "   Monitor Windows Security for blocked applications and whitelist as needed."
        }
    } else {
        Write-Log "-> Skipping Controlled Folder Access."
    }
} else {
    Write-Log "-> Skipping Controlled Folder Access."
}

Write-Log "Hardening complete. Please reboot your system to apply all settings."
Write-Host "========================================" -ForegroundColor Cyan
Log-Event "Script execution completed. Log file: ${LogFile}" "INFO"
Write-Host "Audit log saved to: ${LogFile}" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan


