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

Write-Host "`n==== Opsek Windows Hardening ====" -ForegroundColor Yellow

# --- Auto-applied modules ---

Invoke-Safe "→ Enabling UAC (Always Notify)..." {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                     -Name "ConsentPromptBehaviorAdmin" -Value 2
}

Invoke-Safe "→ Enabling Windows Firewall..." {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
}

Invoke-Safe "→ Enabling Exploit Protection (DEP, ASLR, SEHOP)..." {
    Set-MpPreference -PUAProtection Enabled
    Set-ProcessMitigation -System -Enable DEP
    Set-ProcessMitigation -System -Enable SEHOP
    Set-ProcessMitigation -System -Enable BottomUp,ForceRelocateImages,HighEntropy
}

Invoke-Safe "→ Ensuring Windows Update is enabled..." {
    Set-Service -Name wuauserv -StartupType Automatic
    Start-Service -Name wuauserv
}

Invoke-Safe "→ Enabling Memory Integrity..." {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Force | Out-Null
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
                     -Name "Enabled" -PropertyType DWord -Value 1 -Force | Out-Null
}

Invoke-Safe "→ Checking for BitLocker / Device Encryption support..." {
    $edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
    
    if ($edition -eq "Core") {
        Write-Log "(Warning) BitLocker is NOT available on Windows Home editions."
        
        # Device Encryption check
	# Bitlocker is not avaiable on Windows 11 Home Edition
        try {
            $deStatus = Get-CimInstance -Namespace root\cimv2\security\microsoftvolumeencryption `
                                        -ClassName Win32_EncryptableVolume `
                                        -ErrorAction Stop
            if ($deStatus) {
                Write-Log "This system may support 'Device Encryption' instead of BitLocker."
                Write-Log "   You can enable it in Settings → Update & Security → Device Encryption."
		Write-Log "   More details : https://support.microsoft.com/en-us/windows/device-encryption-in-windows-cf7e2b6f-3e70-4882-9532-18633605b7df"
            }
        } catch {
            Write-Log "No encryption feature detected on this edition."
        }
    }
    elseif (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        Write-Log "BitLocker PowerShell module not found."
    }
    else {
        # Retrieving system drive
        $systemDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive.TrimEnd(":")
        $bitLockerStatus = Get-BitLockerVolume -MountPoint "$systemDrive`:"
        
        if ($bitLockerStatus.ProtectionStatus -eq 'Off') {
            Write-Log "→ Enabling BitLocker on $systemDrive`:..."
            Enable-BitLocker -MountPoint "$systemDrive`:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -Confirm:$false
        } else {
            Write-Log "→ BitLocker already enabled or in valid state."
        }
    }
}

Invoke-Safe "→ Enabling Credential Guard..." {
    reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
    reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 1 /f
    reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f
}

Invoke-Safe "→ Disabling Office Word macros..." {
    $officeKey = "HKCU:\Software\Microsoft\Office\16.0\Word\Security"
    New-Item -Path $officeKey -Force | Out-Null
    New-ItemProperty -Path $officeKey -Name "VBAWarnings" -PropertyType DWord -Value 4 -Force | Out-Null
}

Invoke-Safe "→ Setting screen timeout to 1 minute..." {
    powercfg /change monitor-timeout-ac 1
    powercfg /change monitor-timeout-dc 1
}

Invoke-Safe "→ Enabling LSA Protection (RunAsPPL)..." {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
}

Invoke-Safe "→ Disabling Remote Desktop..." {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
}

Invoke-Safe "→ Checking Secure Boot status..." {
    try {
        if (Confirm-SecureBootUEFI) {
            Write-Log "Secure Boot is enabled."
        } else {
            Write-Log "Secure Boot is NOT enabled. Consider enabling it in UEFI settings."
        }
    } catch {
        Write-Log "Secure Boot check not supported on this system."
    }
}

Invoke-Safe "→ Disabling legacy SMBv1 protocol..." {
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
}

# --- User-interactive modules ---
Write-Log "`n2. Optional security features (user confirmation):"

if (Ask-YesNo "Do you want to BLOCK installation of USB removable devices?") {
    Invoke-Safe "→ Blocking USB removable device installation..." {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v DenyRemovableDevices /t REG_DWORD /d 1 /f
    }
} else {
    Write-Log "→ Skipping USB block."
}

if (Ask-YesNo "Do you want to set a secure DNS (9.9.9.9)?") {
    Invoke-Safe "→ Setting secure DNS to 9.9.9.9..." {
        Get-DnsClientServerAddress | ForEach-Object {
            Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses ("9.9.9.9")
        }
    }
} else {
    Write-Log "→ Keeping current DNS configuration."
}

if (Ask-YesNo "Enable Controlled Folder Access? (may block legitimate apps)") {
    Invoke-Safe "→ Enabling Controlled Folder Access..." {
        Set-MpPreference -EnableControlledFolderAccess Enabled
    }
} else {
    Write-Log "→ Skipping Controlled Folder Access."
}

Write-Log "Hardening complete. Please reboot your system to apply all settings."
