# ==========================================
# WINDOWS HARDENING SCRIPT
# Run as Administrator
# ==========================================

param(
    [switch]$Audit,
    [switch]$Harden,
    [string]$Module
)

# =========================
# HELP (DEFAULT)
# =========================
if (-not ($Audit -or $Harden -or $Module)) {
    Write-Host @"
Windows Hardening Script

Usage:
  hardening-windows.ps1 -Audit
      Audit only (no changes made)

  hardening-windows.ps1 -Harden
        Apply hardening changes

  hardening-windows.ps1 -Module <Name>
        Run specific module (e.g., Firewall, UAC, DefenderHealth)

Examples:
  hardening-windows.ps1 -Audit
  hardening-windows.ps1 -Harden
  hardening-windows.ps1 -Module Firewall
  hardening-windows.ps1 -Audit -Module UAC
"@ -ForegroundColor Cyan
    exit 0
}

# =========================
# MODE SELECTION
# =========================
if ($Audit -and $Harden) {
    Write-Error "Choose either -Audit or -Harden, not both."
    exit 1
}

$Global:RunMode = if ($Audit) { "AUDIT" } else { "HARDEN" }
$Global:AuditResults = @()

function Is-Audit { $Global:RunMode -eq "AUDIT" }

# =========================
# LOGGING
# =========================
$LogFile = "$env:TEMP\Windows_Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Log-Event($Message, $Severity = "INFO") {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts [$Severity] $Message" | Tee-Object -FilePath $LogFile -Append | Out-Host
}

function Write-Log($msg) {
    Write-Host "[*] $msg" -ForegroundColor Cyan
}

# =========================
# PRIVILEGE CHECK
# =========================
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "Run as Administrator."
    exit 1
}

# =========================
# SYSTEM INFO
# =========================
$os = Get-CimInstance Win32_OperatingSystem
$osEdition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
$isUEFI = Test-Path "HKLM:\System\CurrentControlSet\Control\SecureBoot\State"

Write-Log "Mode: $Global:RunMode"
Write-Log "OS: $($os.Caption) ($osEdition)"

# =========================
# CORE ENGINE
# =========================
function Invoke-Module {
    param(
        [string]$Name,
        [scriptblock]$Check,
        [scriptblock]$Apply
    )

    Write-Log $Name

    try {
        $r = & $Check

        $Global:AuditResults += [PSCustomObject]@{
            Module  = $Name
            Status  = $r.Status
            Message = $r.Message
        }

        switch ($r.Status) {
            "OK" {
                Write-Host "  $($r.Message)" -ForegroundColor Green
            }
            "WARN" {
                Write-Host "  $($r.Message)" -ForegroundColor Yellow
            }
            "FAIL" {
                Write-Host "  $($r.Message)" -ForegroundColor Red
                if (-not (Is-Audit)) {
                    Write-Log "  Applying remediation..."
                    & $Apply
                }
            }
        }

        Log-Event "$Name : $($r.Status) - $($r.Message)"
    }
    catch {
        Log-Event "$Name failed: ${_}" "ERROR"
    }
}


function Ask-YesNo($question) {
    do {
        $response = Read-Host "$question [Y/N]"
    } while ($response -notmatch '^[YyNn]$')
    return $response -match '^[Yy]$'
}



# =========================
# USER ACCOUNT CONTROL
# =========================

function Check-UAC {
    $v = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue
    if ($v.ConsentPromptBehaviorAdmin -eq 2) {
        return @{ Status="OK"; Message="UAC Always Notify enabled" }
    }
    return @{ Status="FAIL"; Message="UAC not set to Always Notify" }
}

function Apply-UAC {
    Set-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
}

# =========================
# FIREWALL
# =========================

function Check-Firewall {
    $profiles = Get-NetFirewallProfile

    $disabled = $profiles | Where-Object { -not ${_}.Enabled }
    if ($disabled) {
        return @{
            Status  = "FAIL"
            Message = "One or more firewall profiles are disabled"
        }
    }

    $public = $profiles | Where-Object { ${_}.Name -eq "Public" }
    if ($public.DefaultInboundAction -ne "Block") {
        return @{
            Status  = "FAIL"
            Message = "Public firewall inbound action is not set to Block"
        }
    }

    $noNotify = $profiles | Where-Object { -not ${_}.NotifyOnListen }
    if ($noNotify) {
        return @{
            Status  = "WARN"
            Message = "Firewall enabled but NotifyOnListen is disabled on some profiles"
        }
    }

    return @{
        Status  = "OK"
        Message = "Firewall fully enabled and hardened"
    }
}

function Apply-Firewall {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
}

# =========================
# EXPLOIT PROTECTION / ASLR, SEHOP
# =========================

function Check-ASLR {
    try {
        # Get system-level ASLR settings via Get-ProcessMitigation
        $mit = Get-ProcessMitigation -System -ErrorAction Stop
        $aslr = $mit.Aslr
        
        # Check all three critical ASLR components
        # Values: "ON"=enabled, "OFF"=disabled, "NOTSET"=using default (which is secure on Win10/11)
        $bottomUpOk = ($aslr.BottomUp -eq "ON" -or $aslr.BottomUp -eq 1 -or $aslr.BottomUp -eq "NOTSET" -or $aslr.BottomUp -eq 2)
        $forceRelocateOk = ($aslr.ForceRelocateImages -eq "ON" -or $aslr.ForceRelocateImages -eq 1 -or $aslr.ForceRelocateImages -eq "NOTSET" -or $aslr.ForceRelocateImages -eq 2)
        $highEntropyOk = ($aslr.HighEntropy -eq "ON" -or $aslr.HighEntropy -eq 1 -or $aslr.HighEntropy -eq "NOTSET" -or $aslr.HighEntropy -eq 2)
        
        # Build list of disabled components
        $disabled = @()
        if (-not $bottomUpOk) { $disabled += "BottomUp" }
        if (-not $forceRelocateOk) { $disabled += "ForceRelocateImages" }
        if (-not $highEntropyOk) { $disabled += "HighEntropy" }
        
        # Return status based on findings
        if ($disabled.Count -eq 0) {
            return @{
                Status  = "OK"
                Message = "ASLR is fully enabled (BottomUp, ForceRelocateImages, HighEntropy)"
            }
        } else {
            $fixMessage = if ($osEdition -eq "Core") {
                "ASLR is typically enabled by default on Windows 10/11. Manual verification: Windows Security > App & browser control (may be limited on Home edition)"
            } else {
                "To fix manually: Windows Security > App & browser control > Exploit protection settings > System settings > Randomize memory allocations (ASLR)"
            }
            
            return @{
                Status  = "FAIL"
                Message = "ASLR components disabled: $($disabled -join ', '). $fixMessage"
            }
        }
        
    } catch {
        # ASLR is enabled by default on Windows 10/11, so if check fails, assume it's enabled
        return @{
            Status  = "OK"
            Message = "Unable to verify ASLR status, but it is enabled by default on Windows 10/11"
        }
    }
}

function Apply-ASLR {
    try {
        # Enable all three ASLR components at system level
        Set-ProcessMitigation -System -Enable BottomUp,ForceRelocateImages,HighEntropy -ErrorAction Stop
        
        Write-Log "ASLR enabled (BottomUp, ForceRelocateImages, HighEntropy)"
        Log-Event "ASLR protection enabled" "SUCCESS"
        
    } catch {
        Write-Log "Failed to enable ASLR: ${_}"
        Log-Event "Failed to enable ASLR: ${_}" "WARNING"
        
        # Provide additional guidance
        if ($osEdition -eq "Core") {
            Write-Log "Note: ASLR is enabled by default on Windows 10/11 Home. Configuration options may be limited on Home edition"
        } else {
            Write-Log "Manual configuration: Windows Security > App & browser control > Exploit protection settings > System settings"
        }
    }
}




function Check-SEHOP {
    try {
        # Get system-level SEHOP settings via Get-ProcessMitigation
        $mit = Get-ProcessMitigation -System -ErrorAction Stop
        $sehop = $mit.SeHop
        
        # Check SEHOP status
        # Values: "ON"=enabled, "OFF"=disabled, "NOTSET"=using default
        $sehopEnabled = ($sehop.Enable -eq "ON" -or $sehop.Enable -eq 1 -or $sehop.Enable -eq "NOTSET" -or $sehop.Enable -eq 2)
        
        if ($sehopEnabled) {
            return @{
                Status  = "OK"
                Message = "SEHOP (Structured Exception Handling Overwrite Protection) is enabled"
            }
        } else {
            $fixMessage = if ($osEdition -eq "Core") {
                "SEHOP configuration is limited on Home edition. To verify: Windows Security > App & browser control > Exploit protection settings (may require Pro/Enterprise edition)"
            } else {
                "To fix manually: Windows Security > App & browser control > Exploit protection settings > System settings > Structured Exception Handling Overwrite Protection (SEHOP)"
            }
            
            return @{
                Status  = "FAIL"
                Message = "SEHOP is explicitly disabled. $fixMessage"
            }
        }
        
    } catch {
        # On Home edition or if check fails, provide informational message
        if ($osEdition -eq "Core") {
            return @{
                Status  = "WARN"
                Message = "Unable to verify SEHOP status. SEHOP configuration may be limited on Home edition"
            }
        } else {
            return @{
                Status  = "WARN"
                Message = "Unable to verify SEHOP status: ${_}"
            }
        }
    }
}

function Apply-SEHOP {
    try {
        # Enable SEHOP at system level
        Set-ProcessMitigation -System -Enable SEHOP -ErrorAction Stop
        
        Write-Log "SEHOP (Structured Exception Handling Overwrite Protection) enabled"
        Log-Event "SEHOP protection enabled" "SUCCESS"
        
    } catch {
        Write-Log "Failed to enable SEHOP: ${_}"
        
        # Provide edition-specific guidance
        if ($osEdition -eq "Core") {
            Write-Log "Note: SEHOP configuration may be limited on Windows Home edition. This feature is fully configurable on Pro/Enterprise editions"
            Log-Event "Failed to enable SEHOP (limited support on Home edition)" "WARNING"
        } else {
            Write-Log "Manual configuration: Windows Security > App & browser control > Exploit protection settings > System settings > SEHOP"
            Log-Event "Failed to enable SEHOP: ${_}" "WARNING"
        }
    }
}




# =========================
# Windows Defender Health
# =========================

function Check-DefenderHealth {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop

        if ($status.AntivirusEnabled -and $status.RealTimeProtectionEnabled) {
            return @{
                Status  = "OK"
                Message = "Windows Defender is enabled and fully active"
            }
        } elseif ($status.AntivirusEnabled) {
            return @{
                Status  = "WARN"
                Message = "Windows Defender enabled but real-time protection may be disabled"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "Windows Defender is disabled (may be controlled by GPO)"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Windows Defender status check unavailable on this system"
        }
    }
}

function Apply-DefenderHealth {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
        Log-Event "Windows Defender real-time protection enabled" "SUCCESS"
    } catch {
        Log-Event "Failed to enable Defender protection: ${_}" "WARNING"
    }
}

# =========================
# WINDOWS Update
# =========================


function Check-WindowsUpdate {
    try {
        $svc = Get-Service -Name wuauserv -ErrorAction Stop
        
        # Check if service is running
        $isRunning = ($svc.Status -eq "Running")
        
        # Check startup type - accept both "Automatic" and "AutomaticDelayedStart"
        $startupTypeOk = ($svc.StartType -eq "Automatic") -or ($svc.StartType -eq "AutomaticDelayedStart")
        
        if ($isRunning -and $startupTypeOk) {
            return @{
                Status  = "OK"
                Message = "Windows Update service is running and set to Automatic (StartType: $($svc.StartType))"
            }
        } elseif ($startupTypeOk -and -not $isRunning) {
            return @{
                Status  = "WARN"
                Message = "Windows Update service is set to Automatic but currently not running (Status: $($svc.Status)). To fix manually: Services > Windows Update > Start"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "Windows Update service not properly configured (Status: $($svc.Status), StartType: $($svc.StartType)). To fix manually: Services > Windows Update > Properties > Startup type: Automatic"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Windows Update service unavailable: ${_}"
        }
    }
}

function Apply-WindowsUpdate {
    try {
        # Set service to Automatic startup
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
        Write-Log "Windows Update service set to Automatic startup"
        
        # Start the service if it's not running
        $svc = Get-Service -Name wuauserv
        if ($svc.Status -ne "Running") {
            Start-Service -Name wuauserv -ErrorAction Stop
            Write-Log "Windows Update service started"
        }
        
        Log-Event "Windows Update service enabled and started" "SUCCESS"
        
    } catch {
        Write-Log "Failed to configure Windows Update service: ${_}"
        Log-Event "Windows Update setup failed: ${_}" "WARNING"
    }
}


# =========================
# MEMORY INTEGRITY (HVCI)
# =========================

function Check-MemoryIntegrity {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    try {
        $v = Get-ItemProperty -Path $key -Name Enabled -ErrorAction SilentlyContinue
        if ($v.Enabled -eq 1) {
            return @{
                Status  = "OK"
                Message = "Memory Integrity (HVCI) is enabled"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "Memory Integrity (HVCI) is disabled"
            }
        }
    } catch {
        return @{
            Status  = "FAIL"
            Message = "Memory Integrity (HVCI) not configured"
        }
    }
}

function Apply-MemoryIntegrity {
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
    $hvcPath  = "$basePath\HypervisorEnforcedCodeIntegrity"

    # Ensure parent keys exist
    New-Item -Path $basePath -Force | Out-Null
    New-Item -Path $hvcPath -Force | Out-Null

    # Enable Memory Integrity
    New-ItemProperty -Path $hvcPath `
        -Name "Enabled" -PropertyType DWord -Value 1 -Force | Out-Null
    Log-Event "Memory Integrity (HVCI) enabled" "SUCCESS"
}


# =========================
# Credential Guard
# =========================

function Check-CredentialGuard {

    if ($osEdition -eq "Core") {
        return @{
            Status  = "WARN"
            Message = "Credential Guard not available on Home edition"
        }
    }

    try {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        if (-not $cpu.VirtualizationFirmwareEnabled) {
            return @{
                Status  = "WARN"
                Message = "CPU virtualization not enabled (Credential Guard cannot run)"
            }
        }

        $vbs = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\DeviceGuard" -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue
        $lsa = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags -ErrorAction SilentlyContinue

        if ($vbs.EnableVirtualizationBasedSecurity -eq 1 -and $lsa.LsaCfgFlags -eq 1) {
            return @{
                Status  = "OK"
                Message = "Credential Guard configured (reboot may be required)"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "Credential Guard not configured"
            }
        }

    } catch {
        return @{
            Status  = "WARN"
            Message = "Unable to check Credential Guard: ${_}"
        }
    }
}

function Apply-CredentialGuard {

    if ($osEdition -eq "Core") {
        Write-Log "Credential Guard not supported on Home edition, skipping"
        return
    }

    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    if (-not $cpu.VirtualizationFirmwareEnabled) {
        Write-Log "CPU virtualization not enabled, Credential Guard cannot be applied" 
        return
    }

    try {
        # Enable Credential Guard
        reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f | Out-Null
        reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 1 /f | Out-Null
        reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f | Out-Null
        Log-Event "Credential Guard policy set (reboot required)" "SUCCESS"
    } catch {
        Log-Event "Credential Guard setup failed: ${_}" "WARNING"
    }
}


# =========================
# Disable Office Word Macros (all users)
# =========================

function Check-WordMacros {
    $profiles = Get-CimInstance Win32_UserProfile |
                Where-Object { ${_}.LocalPath -and (Test-Path "$(${_}.LocalPath)\NTUSER.DAT") -and -not ${_}.Special }

    $allGood = $true
    foreach ($profile in $profiles) {
        $sid = $profile.SID
        $hiveLoaded = Test-Path "Registry::HKEY_USERS\$sid"

        if (-not $hiveLoaded) {
            try {
                reg load "HKU\$sid" "$($profile.LocalPath)\NTUSER.DAT" | Out-Null
            } catch {
                Write-Log "Cannot load registry for SID $sid ${_}"
                $allGood = $false
                continue
            }
        }

        try {
            $officeKey = "Registry::HKEY_USERS\$sid\Software\Microsoft\Office\16.0\Word\Security"
            $vba = Get-ItemProperty -Path $officeKey -Name "VBAWarnings" -ErrorAction SilentlyContinue
            if ($vba.VBAWarnings -ne 4) {
                $allGood = $false
            }
        } finally {
            if (-not $hiveLoaded) {
                reg unload "HKU\$sid" | Out-Null
            }
        }
    }

    if ($allGood) {
        return @{
            Status  = "OK"
            Message = "Word macros disabled for all local users"
        }
    } else {
        return @{
            Status  = "FAIL"
            Message = "Word macros not properly disabled for some users"
        }
    }
}

function Apply-WordMacros {
    Write-Log "WARNING: This setting affects ALL local user profiles."
    Write-Log "Group Policy is recommended for enterprise environments."

    $profiles = Get-CimInstance Win32_UserProfile |
                Where-Object { ${_}.LocalPath -and (Test-Path "$(${_}.LocalPath)\NTUSER.DAT") -and -not ${_}.Special }

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
        } finally {
            if (-not $hiveLoaded) {
                reg unload "HKU\$sid" | Out-Null
            }
        }
    }

    Log-Event "Office Word macros disabled for all local user profiles" "INFO"
}


# =========================
# Screen Timeout Policy
# =========================

function Check-ScreenTimeout {
    try {
        # Registry path for active power scheme
        $powerKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"
        
        # Get active power scheme GUID
        $activeSchemePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"
        $activeScheme = (Get-ItemProperty -Path $activeSchemePath -Name "ActivePowerScheme" -ErrorAction Stop).ActivePowerScheme
        
        # Construct path to video timeout settings
        # SUB_VIDEO = 7516b95f-f776-4464-8c53-06167f40cc99
        # VIDEOIDLE = 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e
        $videoPath = "$powerKey\$activeScheme\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"
        
        if (-not (Test-Path $videoPath)) {
            throw "Video timeout registry path not found"
        }
        
        # Read AC and DC values (in seconds)
        $acValue = (Get-ItemProperty -Path $videoPath -Name "ACSettingIndex" -ErrorAction Stop).ACSettingIndex
        $dcValue = (Get-ItemProperty -Path $videoPath -Name "DCSettingIndex" -ErrorAction Stop).DCSettingIndex
        
        # Convert to minutes for display
        $acMinutes = [math]::Round($acValue / 60, 1)
        $dcMinutes = [math]::Round($dcValue / 60, 1)
        
        # Check if both are set to 60 seconds (1 minute)
        if ($acValue -eq 60 -and $dcValue -eq 60) {
            return @{
                Status  = "OK"
                Message = "Screen timeout set to 1 minute for AC and DC"
            }
        } else {
            return @{
                Status  = "WARN"
                Message = "Screen timeout not optimal (AC: $acMinutes min, DC: $dcMinutes min). You need to fix it manually: Settings > System > Power & battery > Screen and sleep > When plugged in/On battery power, turn off my screen after > set both to 1 minute"
            }
        }
        
    } catch {
        return @{
            Status  = "WARN"
            Message = "Unable to check screen timeout via registry: ${_}"
        }
    }
}



# =========================
# LSA Protection (RunAsPPL)
# =========================

function Check-LSAProtection {
    try {
        $lsa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue
        if ($lsa.RunAsPPL -eq 1) {
            return @{
                Status  = "OK"
                Message = "LSA Protection (RunAsPPL) is enabled"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "LSA Protection (RunAsPPL) is disabled"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Unable to check LSA Protection: ${_}"
        }
    }
}

function Apply-LSAProtection {
    try {
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
        Log-Event "LSA Protection (RunAsPPL) enabled" "SUCCESS"
    } catch {
        Log-Event "Failed to enable LSA Protection (RunAsPPL): ${_}" "WARNING"
    }
}

# =========================
# Secure Boot
# =========================

function Check-SecureBoot {
    try {
        if (-not $isUEFI) {
            return @{
                Status  = "WARN"
                Message = "Secure Boot not available (Legacy BIOS detected)"
            }
        } elseif (Confirm-SecureBootUEFI) {
            return @{
                Status  = "OK"
                Message = "Secure Boot is enabled"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "Secure Boot is disabled. Enable in UEFI settings"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Secure Boot check failed: ${_}"
        }
    }
}

function Apply-SecureBoot {
    Write-Log "Cannot apply Secure Boot via script. Please enable in UEFI firmware settings."
}

# =========================
# Disable SMBv1 Protocol
# =========================

function Check-SMBv1 {
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
        if ($feature.State -eq "Disabled") {
            return @{
                Status  = "OK"
                Message = "SMBv1 protocol is disabled"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "SMBv1 protocol is enabled"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Unable to check SMBv1 status: ${_}"
        }
    }
}

function Apply-SMBv1 {
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
        Log-Event "SMBv1 protocol disabled" "SUCCESS"
    } catch {
        Log-Event "Failed to disable SMBv1 protocol: ${_}" "WARNING"
    }
}

# =========================
# Microsoft / Online Accounts Check
# =========================

function Check-OnlineAccounts {
    try {
        $users = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, PrincipalSource
        $onlineUsers = $users | Where-Object { ${_}.PrincipalSource -in @("MicrosoftAccount", "Domain", "Unknown") }

        if ($onlineUsers) {
            $msg = "Online / Microsoft-backed accounts detected: " + ($onlineUsers | ForEach-Object { ${_}.Name } | Join-String ", ")
            return @{
                Status  = "WARN"
                Message = $msg
            }
        } else {
            return @{
                Status  = "OK"
                Message = "No Microsoft / online accounts detected"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Get-LocalUser unavailable on this system. Skipping account detection"
        }
    }
}

function Apply-OnlineAccounts {
    Write-Log "No automatic remediation possible for Microsoft / online accounts. Consider migrating to local-only accounts."
}


# =========================
# Enforce Password on Wake / Resume
# =========================

function Check-PasswordOnWake {
    try {
        $key = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
        $ac = (Get-ItemProperty -Path $key -Name "ACSettingIndex" -ErrorAction SilentlyContinue).ACSettingIndex
        $dc = (Get-ItemProperty -Path $key -Name "DCSettingIndex" -ErrorAction SilentlyContinue).DCSettingIndex

        if ($ac -eq 1 -and $dc -eq 1) {
            return @{
                Status  = "OK"
                Message = "Machine-level password on wake/resume enforced (AC & DC)"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "Password on wake/resume not fully enforced"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Unable to check wake/resume password policy: ${_}"
        }
    }
}

function Apply-PasswordOnWake {
    try {
        $key = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name "ACSettingIndex" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $key -Name "DCSettingIndex" -PropertyType DWord -Value 1 -Force | Out-Null

        Write-Log "Machine-level power policy applied (AC and DC)"
        Write-Log "WARNING: Screen saver password is user-level and requires per-user configuration."
        Write-Log "Run 'control desk.cpl' as each user to set 'Password protected' screensaver."

        Log-Event "Password on wake/resume enforced (machine-level)" "SUCCESS"
    } catch {
        Log-Event "Failed to enforce password on wake/resume: ${_}" "WARNING"
    }
}

# =========================
# Show File Extensions
# =========================

function Check-FileExtensions {
    try {
        $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $value = (Get-ItemProperty -Path $key -Name "HideFileExt" -ErrorAction SilentlyContinue).HideFileExt

        if ($value -eq 0) {
            return @{
                Status  = "OK"
                Message = "File extensions are visible"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "File extensions are hidden"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Unable to check file extension visibility: ${_}"
        }
    }
}

function Apply-FileExtensions {
    try {
        $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }

        if (Get-ItemProperty -Path $key -Name "HideFileExt" -ErrorAction SilentlyContinue) {
            Set-ItemProperty -Path $key -Name "HideFileExt" -Value 0 -ErrorAction Stop
        } else {
            New-ItemProperty -Path $key -Name "HideFileExt" -PropertyType DWord -Value 0 -Force | Out-Null
        }

        Write-Log "Policy set: file extensions will be visible"
        Log-Event "File extension visibility enabled" "SUCCESS"
    } catch {
        Log-Event "Failed to set file extension visibility: $(${_}.Exception.Message)" "WARNING"
    }
}



# =========================
# Disable Windows Copilot / AI Features
# =========================

function Check-WindowsCopilot {
    $copilotKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    $shellKeyPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Shell\Copilot"

    $statusList = @()

    try {
        $copilot = Get-ItemProperty -Path $copilotKeyPath -Name "TurnOffWindowsCopilot" -ErrorAction SilentlyContinue
        if ($copilot.TurnOffWindowsCopilot -eq 1) {
            $statusList += "Copilot machine policy disabled"
        } else {
            $statusList += "Copilot machine policy enabled"
        }
    } catch {
        $statusList += "Copilot machine policy unavailable"
    }

    try {
        $button = Get-ItemProperty -Path $shellKeyPath -Name "IsCopilotAvailable" -ErrorAction SilentlyContinue
        if ($button.IsCopilotAvailable -eq 0) {
            $statusList += "Copilot button disabled"
        } else {
            $statusList += "Copilot button enabled"
        }
    } catch {
        $statusList += "Copilot button registry not available"
    }

    $fail = $statusList | Where-Object { ${_} -match "enabled" }
    if ($fail) {
        return @{
            Status  = "FAIL"
            Message = $statusList -join " | "
        }
    } else {
        return @{
            Status  = "OK"
            Message = $statusList -join " | "
        }
    }
}

function Apply-WindowsCopilot {
    $copilotKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    $shellKeyPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Shell\Copilot"

    try {
        New-Item -Path $copilotKeyPath -Force | Out-Null
        New-ItemProperty -Path $copilotKeyPath -Name "TurnOffWindowsCopilot" -PropertyType DWord -Value 1 -Force | Out-Null
        Log-Event "Copilot disabled via machine policy" "SUCCESS"
    } catch {
        Log-Event "Copilot policy not available on this Windows version" "WARNING"
    }

    try {
        New-Item -Path $shellKeyPath -Force | Out-Null
        New-ItemProperty -Path $shellKeyPath -Name "IsCopilotAvailable" -PropertyType DWord -Value 0 -Force | Out-Null
    } catch {
        Write-Log "Copilot button registry not available (older Windows version)"
    }
}


# =========================
# USER CONFIRMATION REQUIRED FUNCTIONS
# =========================


# =========================
# OneDrive Removal / Disable
# =========================

function Check-OneDrive {
    try {
        $oneDriveRunning = Get-Process -Name OneDrive -ErrorAction SilentlyContinue
        $oneDrivePolicy  = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue).DisableFileSyncNGSC

        $statusList = @()
        if ($oneDriveRunning) { $statusList += "OneDrive process running" }
        if ($oneDrivePolicy -ne 1) { $statusList += "OneDrive file sync not disabled via policy" }

        if ($statusList) {
            return @{
                Status  = "FAIL"
                Message = $statusList -join " | "
            }
        } else {
            return @{
                Status  = "OK"
                Message = "OneDrive uninstalled / disabled"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Unable to check OneDrive status: ${_}"
        }
    }
}

function Apply-OneDrive {
    # Ask user before uninstall
    if (Ask-YesNo "Do you want to UNINSTALL the OneDrive client?") {
        try {
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
        } catch {
            Write-Log "Failed to uninstall OneDrive: ${_}"
        }
    } else {
        Write-Log "-> Skipping OneDrive uninstall."
    }


    try {
        $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name "DisableFileSyncNGSC" -PropertyType DWord -Value 1 -Force | Out-Null
    } catch {
        Write-Log "Failed to apply OneDrive policy: ${_}"
    }

}



# =========================
# Disk Encryption (BitLocker / Device Encryption)
# =========================

function Check-DiskEncryption {
    $edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
    $systemDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive.TrimEnd(":")
    $statusMessage = @()
    $encryptionEnabled = $false

    # Check BitLocker (Pro / Enterprise)
    if ($edition -ne "Core" -and (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        try {
            $bitLockerStatus = Get-BitLockerVolume -MountPoint "${systemDrive}:" -ErrorAction SilentlyContinue
            switch ($bitLockerStatus.ProtectionStatus) {
                'On'  { $statusMessage += "BitLocker enabled on ${systemDrive}"; $encryptionEnabled = $true }
                'Off' { 
                    try {
                        $tpmStatus = Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -ClassName Win32_Tpm -ErrorAction Stop
                        if ($tpmStatus) { $statusMessage += "BitLocker recommended: TPM detected" }
                    } catch { $statusMessage += "BitLocker available but TPM not detected (less secure)" }
                }
                default { $statusMessage += "BitLocker status unknown" }
            }
        } catch { $statusMessage += "BitLocker check failed" }
    } else {
        $statusMessage += "BitLocker not available on Home Edition"
    }

    # Check Device Encryption (Home fallback)
    if (-not $encryptionEnabled) {
        try {
            $deStatus = Get-CimInstance -Namespace root\cimv2\security\microsoftvolumeencryption -ClassName Win32_EncryptableVolume -ErrorAction Stop
            if ($deStatus) {
                $statusMessage += "Device Encryption available on this system"
                $encryptionEnabled = $true
            }
        } catch { $statusMessage += "No encryption feature detected" }
    }

    # Final warning if no encryption
    if (-not $encryptionEnabled) {
        $statusMessage += "WARNING: No disk encryption is currently enabled! Data may be vulnerable."
    }

    $overallStatus = if ($encryptionEnabled) { "OK" } else { "FAIL" }

    return @{
        Status  = $overallStatus
        Message = $statusMessage -join " | "
    }
}

function Apply-DiskEncryption {
    $edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
    $systemDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive.TrimEnd(":")

    # Only ask user if BitLocker is available
    if ($edition -ne "Core" -and (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        try {
            $bitLockerStatus = Get-BitLockerVolume -MountPoint "${systemDrive}:" -ErrorAction SilentlyContinue
            if ($bitLockerStatus.ProtectionStatus -ne 'On') {
                $tpmStatus = $null
                try {
                    $tpmStatus = Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -ClassName Win32_Tpm -ErrorAction Stop
                } catch { }

                if ($tpmStatus) {
                    if (Ask-YesNo "Enable BitLocker on ${systemDrive}? (CRITICAL: Save recovery key)") {
                        Write-Log "-> Enabling BitLocker on ${systemDrive}..."
                        Enable-BitLocker -MountPoint "${systemDrive}:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -Confirm:$false

                        # Save recovery key
                        $recoveryKey = (Get-BitLockerVolume -MountPoint "${systemDrive}:" |
                            Select-Object -ExpandProperty KeyProtector |
                            Where-Object { ${_}.KeyProtectorType -eq 'RecoveryPassword' }).RecoveryPassword
                        if ($recoveryKey) {
                            Log-Event "BitLocker Recovery Key: ${recoveryKey}" "CRITICAL"
                            Write-Host "[!] SAVE THIS KEY IMMEDIATELY: ${recoveryKey}" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Log "-> Skipping BitLocker enablement"
                    }
                } else {
                    Write-Log "WARNING: TPM not available; BitLocker can use password protector (less secure)"
                }
            } else {
                Write-Log "BitLocker already enabled on ${systemDrive}"
            }
        } catch { Write-Log "BitLocker setup failed: ${_}" }
    } else {
        Write-Log "BitLocker not available on Home Edition, checking Device Encryption..."

        try {
            $deStatus = Get-CimInstance -Namespace root\cimv2\security\microsoftvolumeencryption -ClassName Win32_EncryptableVolume -ErrorAction Stop
            if ($deStatus) {
                Write-Log "Device Encryption available (configure via Settings > Privacy & Security > Device Encryption)"
            } else {
                Write-Log "No disk encryption feature detected on this system"
            }
        } catch { Write-Log "Device Encryption check failed" }
    }
}


# =========================
# Block USB Removable Device Installation
# =========================

function Check-BlockUSB {
    try {
        $value = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyRemovableDevices" -ErrorAction SilentlyContinue).DenyRemovableDevices
        if ($value -eq 1) {
            return @{
                Status  = "OK"
                Message = "USB removable device installation is blocked"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "USB removable device installation is allowed"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Unable to check USB device installation policy: ${_}"
        }
    }
}

function Apply-BlockUSB {
    if (Ask-YesNo "Do you want to BLOCK installation of USB removable devices?") {
        try {
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v DenyRemovableDevices /t REG_DWORD /d 1 /f
            Log-Event "USB removable device installation blocked" "SUCCESS"
        } catch {
            Log-Event "Failed to block USB device installation: ${_}" "WARNING"
        }
    } else {
        Write-Log "-> Skipping USB block."
    }
}


# =========================
# Set Secure DNS (9.9.9.9)
# =========================

function Check-SecureDNS {
    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4

        $dnsServers | ForEach-Object {
            Write-Log "Interface $($_.InterfaceAlias) DNS: $($_.ServerAddresses -join ", ")"
        }

        $matching = @($dnsServers | Where-Object {
            ($_.ServerAddresses | Where-Object { $_.Trim() -eq "9.9.9.9" }).Count -gt 0
        })
        Write-Host "$($matching.Count)"
        if ($matching.Count -gt 0) {
            return @{
                Status  = "OK"
                Message = "At least one IPv4 interface is configured with secure DNS 9.9.9.9"
            }
        }
        else {
            return @{
                Status  = "FAIL"
                Message = "No IPv4 interface is configured with secure DNS 9.9.9.9"
            }
        }

    } catch {
        return @{
            Status  = "WARN"
            Message = "Unable to check DNS settings: $_"
        }
    }
}

function Apply-SecureDNS {

    # Ask user if they want to configure secure DNS
    if (-not (Ask-YesNo "Do you want to configure secure DNS (9.9.9.9)?")) {
        Write-Log "-> Keeping current DNS configuration."
        return
    }

    try {
        # Retrieve all IPv4 DNS client interfaces
        $dnsAdapters = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop

        # Retrieve full network adapter details
        $netAdapters = Get-NetAdapter -ErrorAction Stop

        foreach ($dns in $dnsAdapters) {

            # Match DNS entry with its corresponding network adapter
            $adapter = $netAdapters | Where-Object { $_.InterfaceIndex -eq $dns.InterfaceIndex }

            # Skip if adapter not found or not active
            if (-not $adapter -or $adapter.Status -ne "Up") { continue }

            # Log adapter information
            Write-Log ""
            Write-Log "Detected network interface:"
            Write-Log "   Name        : $($adapter.Name)"
            Write-Log "   Description : $($adapter.InterfaceDescription)"
            Write-Log "   Media Type  : $($adapter.MediaType)"
            Write-Log ""

            # Detect potential VPN, virtual, or tunnel adapters
            if ($adapter.InterfaceDescription -match "VPN|TAP|Tunnel|PPP|Virtual|Hyper-V") {
                Write-Log "WARNING: This interface appears to be a VPN or tunnel adapter." "WARNING"
                Write-Log "Overriding DNS may break internal name resolution." "WARNING"
                Write-Log "You may lose access to internal or corporate resources." "WARNING"
                Write-Log ""
            }

            # Prompt user for this interface
            if (Ask-YesNo "Apply secure DNS to this interface?") {
                try {
                    # Apply Quad9 DNS
                    Set-DnsClientServerAddress `
                        -InterfaceIndex $adapter.InterfaceIndex `
                        -ServerAddresses "9.9.9.9" `
                        -ErrorAction Stop

                    Log-Event "DNS successfully applied to interface $($adapter.Name)" "SUCCESS"
                } catch {
                    Log-Event "Failed to configure DNS on $($adapter.Name): $_" "WARNING"
                }
            } else {
                Write-Log "-> Interface skipped."
            }
        }

        # Validate DNS resolution against Quad9
        Write-Log ""
        Write-Log "Validating DNS resolution..."
        $validation = Resolve-DnsName -Name "example.com" -Server "9.9.9.9" -ErrorAction SilentlyContinue

        if ($validation) {
            Log-Event "DNS validation successful." "SUCCESS"
        } else {
            Log-Event "DNS validation failed - check connectivity." "WARNING"
        }

    } catch {
        # Catch global failure
        Log-Event "DNS configuration failed: $_" "ERROR"
    }
}



# =========================
# Controlled Folder Access (CFA)
# =========================

function Check-CFA {
    try {
        $cfaStatus = Get-MpPreference | Select-Object -ExpandProperty EnableControlledFolderAccess
        
        # $cfaStatus 0=Disabled, 1=Enabled, 2=AuditMode
        if ($cfaStatus -eq 1) {
            return @{
                Status  = "OK"
                Message = "Controlled Folder Access is enabled"
            }
        } elseif ($cfaStatus -eq 2) {
            return @{
                Status  = "WARN"
                Message = "Controlled Folder Access is in Audit Mode"
            }
        } else {
            return @{
                Status  = "FAIL"
                Message = "Controlled Folder Access is disabled"
            }
        }
    } catch {
        return @{
            Status  = "WARN"
            Message = "Unable to check Controlled Folder Access status: ${_}"
        }
    }
}

function Apply-CFA {
    Write-Log "   WARNING: Controlled Folder Access may block legitimate applications."
    Write-Log "   Protected folders: Documents, Desktop, Downloads, Pictures, Videos, Music."
    Write-Log "   You will need to manually allow apps in: Windows Security -> Virus and threat protection -> Manage settings -> Allowed apps"

    if (Ask-YesNo "Do you really want to ENABLE Controlled Folder Access?") {
        try {
            Set-MpPreference -EnableControlledFolderAccess Enabled
            Write-Log "Controlled Folder Access enabled. REBOOT may be required for full effect."
            Log-Event "Controlled Folder Access enabled" "SUCCESS"
        } catch {
            Log-Event "Failed to enable Controlled Folder Access: ${_}" "WARNING"
        }
    } else {
        Write-Log "-> Skipping Controlled Folder Access."
    }
}


# =========================
# MODULE REGISTRY
# =========================
$Modules = @(
    @{
        Name  = "User Account Control (Always Notify)"
        Check = { Check-UAC }
        Apply = { Apply-UAC }
    },
    @{
        Name  = "Windows Firewall"
        Check = { Check-Firewall }
        Apply = { Apply-Firewall }
    },
        @{
        Name  = "ASLR Enforcement"
        Check = { Check-ASLR }
        Apply = { Apply-ASLR }
    },
        @{
        Name  = "SEHOP Enforcement"
        Check = { Check-SEHOP }
        Apply = { Apply-SEHOP }
    },
    @{
        Name  = "Windows Defender Health"
        Check = { Check-DefenderHealth }
        Apply = { Apply-DefenderHealth }
    },
    @{
        Name  = "Windows Update Service"
        Check = { Check-WindowsUpdate }
        Apply = { Apply-WindowsUpdate }
    },
    @{
        Name  = "Memory Integrity (HVCI)"
        Check = { Check-MemoryIntegrity }
        Apply = { Apply-MemoryIntegrity }
    },
    @{
        Name  = "Credential Guard"
        Check = { Check-CredentialGuard }
        Apply = { Apply-CredentialGuard }
    },
    @{
        Name  = "Disable Office Word Macros (All Users)"
        Check = { Check-WordMacros }
        Apply = { Apply-WordMacros }
    },
    @{
        Name  = "Screen Timeout Policy (1 minute)"
        Check = { Check-ScreenTimeout }
        Apply = {  }
    },
    @{
        Name  = "LSA Protection (RunAsPPL)"
        Check = { Check-LSAProtection }
        Apply = { Apply-LSAProtection }
    },
    @{
        Name  = "Secure Boot"
        Check = { Check-SecureBoot }
        Apply = { Apply-SecureBoot }
    },
    @{
        Name  = "Disable SMBv1 Protocol"
        Check = { Check-SMBv1 }
        Apply = { Apply-SMBv1 }
    },
    @{
        Name  = "Microsoft / Online Accounts Detection"
        Check = { Check-OnlineAccounts }
        Apply = { Apply-OnlineAccounts }
    },
    @{
        Name  = "Enforce Password on Wake / Resume"
        Check = { Check-PasswordOnWake }
        Apply = { Apply-PasswordOnWake }
    },
    @{
        Name  = "Show File Extensions"
        Check = { Check-FileExtensions }
        Apply = { Apply-FileExtensions }
    },
    @{
        Name  = "Disable Windows Copilot / AI Features"
        Check = { Check-WindowsCopilot }
        Apply = { Apply-WindowsCopilot }
    },
    @{
        Name  = "OneDrive Removal / Disable"
        Check = { Check-OneDrive }
        Apply = { Apply-OneDrive }
    },
    @{
        Name  = "Disk Encryption (BitLocker / Device Encryption)"
        Check = { Check-DiskEncryption }
        Apply = { Apply-DiskEncryption }
    },
    @{
        Name  = "Block USB Removable Device Installation"
        Check = { Check-BlockUSB }
        Apply = { Apply-BlockUSB }
    },
    @{
        Name  = "Set Secure DNS (9.9.9.9)"
        Check = { Check-SecureDNS }
        Apply = { Apply-SecureDNS }
    },
    @{
        Name  = "Controlled Folder Access (CFA)"
        Check = { Check-CFA }
        Apply = { Apply-CFA }
    }
)

# =========================
# MODULE FILTER
# =========================
# =========================
# MODULE FILTER & EXECUTION
# =========================


if ($Module) {
    $filtered = $Modules | Where-Object { $_.Name -match $Module }

    if (-not $filtered) {
        Write-Error "Module '$Module' not found."
        exit 1
    }

    foreach ($m in $filtered) {
        Write-Log "Running Apply: $($m.Name)"
        $applyBlock = $m.Apply
        if ($applyBlock -and $applyBlock.ToString().Trim() -ne "") {
            & $applyBlock
        } else {
            Write-Log "No Apply function defined for: $($m.Name)"
        }
    }
    exit 1
}

# =========================
# EXECUTION
# =========================
Write-Host "==== OPSEK WINDOWS HARDENING ====" -ForegroundColor Yellow

foreach ($m in $Modules) {
    Invoke-Module `
        -Name  $m.Name `
        -Check $m.Check `
        -Apply $m.Apply
}

# =========================
# AUDIT SUMMARY
# =========================
if (Is-Audit) {
    Write-Host "`n==== AUDIT SUMMARY ====" -ForegroundColor Cyan
    $Global:AuditResults | Format-Table -AutoSize
}

Write-Log "Execution completed"
Write-Host "Log file: $LogFile" -ForegroundColor Yellow
