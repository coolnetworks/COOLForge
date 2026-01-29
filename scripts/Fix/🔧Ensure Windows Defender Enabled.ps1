<#
.SYNOPSIS
    Ensures Windows Defender is enabled and running on all Windows variants.

.DESCRIPTION
    This script checks if Windows Defender/Microsoft Defender Antivirus is
    enabled and running. If not, it attempts to enable and start the service,
    and enables real-time protection.

    Supports: Windows 7, 8, 8.1, 10, 11 (and Server variants)

    FORCED POLICY: This script always enforces Defender to be enabled.
    No tag-based policy logic - always ensure Defender is running.

.NOTES
    Version:          2026.01.18.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success (Defender running) | 1 = Alert (Failed to enable)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Ensure Windows Defender Enabled
# Version: 2026.01.18.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)

$ErrorActionPreference = "Stop"

# ============================================================
# LAUNCHER VARIABLE DETECTION
# ============================================================
$RunningFromLauncher = $null -ne (Get-Variable -Name "LauncherVariables" -ValueOnly -ErrorAction SilentlyContinue)

if ($RunningFromLauncher) {
    $MspScratchFolder = $LauncherVariables.MspScratchFolder
    $DeviceHostname = $LauncherVariables.DeviceHostname
    $DeviceTags = $LauncherVariables.DeviceTags
    $DebugScripts = $LauncherVariables.DebugScripts
    $LevelApiKey = $LauncherVariables.LevelApiKey
    $PolicyDefender = $LauncherVariables.PolicyDefender
} else {
    $MspScratchFolder = if ($env:CF_SCRATCH) { $env:CF_SCRATCH } else { "C:\ProgramData\MSP" }
    $DeviceHostname = $env:COMPUTERNAME
    $DeviceTags = ""
    $DebugScripts = $false
    $LevelApiKey = $null
    $PolicyDefender = "enforce"  # Default to enforce when running standalone
}

# Normalize policy value - default to "enforce" if empty or not set
if ([string]::IsNullOrWhiteSpace($PolicyDefender) -or $PolicyDefender -like "{{*}}") {
    $PolicyDefender = "enforce"
}
$PolicyDefender = $PolicyDefender.ToLower().Trim()

# Exclusion tag - U+274C Cross Mark
$ExclusionTag = [char]0x274C

# Reboot tag - U+1F64F Pray + U+1F504 Arrows + "REBOOT TONIGHT"
$RebootTag = [char]::ConvertFromUtf32(0x1F64F) + [char]::ConvertFromUtf32(0x1F504) + "REBOOT TONIGHT"

# Track if reboot is needed
$Script:RebootRequired = $false

# ============================================================
# HELPER FUNCTIONS
# ============================================================
function Write-DefenderLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )

    $Prefix = switch ($Level) {
        "INFO"    { "[*]" }
        "WARN"    { "[!]" }
        "ERROR"   { "[X]" }
        "SUCCESS" { "[+]" }
        "DEBUG"   { "[D]" }
    }

    if ($Level -eq "DEBUG" -and -not $DebugScripts) { return }

    Write-Host "$Prefix $Message"
}

function Get-WindowsVersion {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $OS) {
        $OS = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
    }

    $Version = [System.Environment]::OSVersion.Version
    $BuildNumber = $OS.BuildNumber

    # Determine Windows version
    $WinVersion = switch ($Version.Major) {
        10 {
            if ([int]$BuildNumber -ge 22000) { "Windows 11" }
            else { "Windows 10" }
        }
        6 {
            switch ($Version.Minor) {
                3 { "Windows 8.1" }
                2 { "Windows 8" }
                1 { "Windows 7" }
                0 { "Windows Vista" }
                default { "Windows 6.x" }
            }
        }
        default { "Windows $($Version.Major).$($Version.Minor)" }
    }

    # Check if Server
    if ($OS.ProductType -ne 1) {
        $WinVersion = "$WinVersion Server"
    }

    return @{
        Version     = $WinVersion
        Major       = $Version.Major
        Minor       = $Version.Minor
        Build       = $BuildNumber
        IsServer    = ($OS.ProductType -ne 1)
        Caption     = $OS.Caption
    }
}

function Test-ThirdPartyAV {
    # Check if a third-party AV is installed and active
    # This may legitimately disable Defender

    try {
        $AVProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue

        if ($AVProducts) {
            $ThirdPartyAV = $AVProducts | Where-Object {
                $_.displayName -notmatch "Windows Defender|Microsoft Defender"
            }

            if ($ThirdPartyAV) {
                return @{
                    Installed = $true
                    Products  = @($ThirdPartyAV | ForEach-Object { $_.displayName })
                }
            }
        }
    }
    catch {
        Write-DefenderLog "Could not query SecurityCenter2 (may be Server OS)" -Level "DEBUG"
    }

    return @{ Installed = $false; Products = @() }
}

function Get-DefenderStatus {
    $Status = @{
        ServiceExists     = $false
        ServiceRunning    = $false
        ServiceStartType  = "Unknown"
        RealTimeEnabled   = $false
        AMEngineVersion   = $null
        SignatureAge      = $null
        ThirdPartyAV      = $null
        CanManage         = $false
    }

    # Check for WinDefend service (Windows 8+)
    $DefenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue

    if (-not $DefenderService) {
        # Try older service name (Windows 7)
        $DefenderService = Get-Service -Name "MsMpSvc" -ErrorAction SilentlyContinue
    }

    if ($DefenderService) {
        $Status.ServiceExists = $true
        $Status.ServiceRunning = ($DefenderService.Status -eq "Running")
        $Status.ServiceStartType = $DefenderService.StartType
    }

    # Check third-party AV
    $Status.ThirdPartyAV = Test-ThirdPartyAV

    # Try to get detailed status via PowerShell cmdlets (Windows 8+)
    try {
        $MpStatus = Get-MpComputerStatus -ErrorAction Stop
        $Status.CanManage = $true
        $Status.RealTimeEnabled = $MpStatus.RealTimeProtectionEnabled
        $Status.AMEngineVersion = $MpStatus.AMEngineVersion

        if ($MpStatus.AntivirusSignatureLastUpdated) {
            $Status.SignatureAge = (Get-Date) - $MpStatus.AntivirusSignatureLastUpdated
        }
    }
    catch {
        Write-DefenderLog "Get-MpComputerStatus not available (older Windows or Defender disabled)" -Level "DEBUG"

        # Fallback: check registry for real-time protection status
        try {
            $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
            $DisableRealtime = Get-ItemProperty -Path $RegPath -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue

            if ($DisableRealtime) {
                $Status.RealTimeEnabled = ($DisableRealtime.DisableRealtimeMonitoring -eq 0)
            }
        }
        catch {
            Write-DefenderLog "Could not check registry for real-time status" -Level "DEBUG"
        }
    }

    return $Status
}

function Enable-DefenderService {
    param([string]$ServiceName = "WinDefend")

    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $Service) {
        Write-DefenderLog "Service $ServiceName not found" -Level "ERROR"
        return $false
    }

    # Check if service is disabled
    if ($Service.StartType -eq "Disabled") {
        Write-DefenderLog "Service is disabled - attempting to enable..." -Level "INFO"

        try {
            Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction Stop
            Write-DefenderLog "Service startup type set to Automatic" -Level "SUCCESS"
        }
        catch {
            Write-DefenderLog "Failed to change service startup type: $($_.Exception.Message)" -Level "ERROR"

            # Try via registry as fallback
            try {
                $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
                Set-ItemProperty -Path $RegPath -Name "Start" -Value 2 -ErrorAction Stop
                Write-DefenderLog "Service enabled via registry" -Level "SUCCESS"
            }
            catch {
                Write-DefenderLog "Registry fallback also failed" -Level "ERROR"
                return $false
            }
        }
    }

    # Start the service if not running
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($Service.Status -ne "Running") {
        Write-DefenderLog "Starting $ServiceName service..." -Level "INFO"

        try {
            Start-Service -Name $ServiceName -ErrorAction Stop
            Start-Sleep -Seconds 3

            $Service = Get-Service -Name $ServiceName
            if ($Service.Status -eq "Running") {
                Write-DefenderLog "Service started successfully" -Level "SUCCESS"
                return $true
            }
            else {
                Write-DefenderLog "Service failed to start (status: $($Service.Status))" -Level "ERROR"
                return $false
            }
        }
        catch {
            Write-DefenderLog "Failed to start service: $($_.Exception.Message)" -Level "ERROR"
            return $false
        }
    }

    Write-DefenderLog "Service already running" -Level "DEBUG"
    return $true
}

function Enable-RealTimeProtection {
    Write-DefenderLog "Enabling real-time protection..." -Level "INFO"

    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-DefenderLog "Real-time protection enabled" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-DefenderLog "Failed to enable via Set-MpPreference: $($_.Exception.Message)" -Level "WARN"

        # Try via registry
        try {
            $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
            if (-not (Test-Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }
            Set-ItemProperty -Path $RegPath -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord -ErrorAction Stop
            Write-DefenderLog "Real-time protection enabled via registry" -Level "SUCCESS"
            return $true
        }
        catch {
            Write-DefenderLog "Registry fallback also failed: $($_.Exception.Message)" -Level "ERROR"
            return $false
        }
    }
}

function Update-DefenderSignatures {
    Write-DefenderLog "Updating Defender signatures..." -Level "INFO"

    try {
        Update-MpSignature -ErrorAction Stop
        Write-DefenderLog "Signature update initiated" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-DefenderLog "Signature update failed: $($_.Exception.Message)" -Level "WARN"
        return $false
    }
}

function Repair-DefenderComponents {
    # Self-healing: Attempt to repair Windows Defender components
    Write-DefenderLog "Attempting self-healing repair of Defender components..." -Level "INFO"

    $RepairSuccess = $false

    # Method 1: Re-register Defender DLLs
    Write-DefenderLog "Re-registering Defender components..." -Level "INFO"
    $DllsToRegister = @(
        "$env:ProgramFiles\Windows Defender\MpClient.dll",
        "$env:ProgramFiles\Windows Defender\MpCmdRun.exe",
        "$env:ProgramFiles\Windows Defender\MsMpEng.exe"
    )

    foreach ($Dll in $DllsToRegister) {
        if (Test-Path $Dll) {
            if ($Dll -match '\.dll$') {
                $RegResult = Start-Process regsvr32.exe -ArgumentList "/s `"$Dll`"" -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
                if ($RegResult.ExitCode -eq 0) {
                    Write-DefenderLog "Registered: $(Split-Path $Dll -Leaf)" -Level "DEBUG"
                }
            }
        }
    }

    # Method 2: Reset Windows Security via PowerShell (Windows 10+)
    try {
        $WinSecApp = Get-AppxPackage -Name "Microsoft.SecHealthUI" -ErrorAction SilentlyContinue
        if ($WinSecApp) {
            Write-DefenderLog "Resetting Windows Security app..." -Level "INFO"
            Get-AppxPackage -Name "Microsoft.SecHealthUI" | Reset-AppxPackage -ErrorAction SilentlyContinue
            Write-DefenderLog "Windows Security app reset initiated" -Level "SUCCESS"
            $RepairSuccess = $true
        }
    }
    catch {
        Write-DefenderLog "Windows Security reset not available: $($_.Exception.Message)" -Level "DEBUG"
    }

    # Method 3: Enable Defender via Group Policy registry keys
    Write-DefenderLog "Checking Group Policy settings..." -Level "INFO"
    $GPOPaths = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiVirus"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; Value = 0 }
    )

    foreach ($Setting in $GPOPaths) {
        try {
            if (-not (Test-Path $Setting.Path)) {
                New-Item -Path $Setting.Path -Force -ErrorAction SilentlyContinue | Out-Null
            }

            $CurrentValue = Get-ItemProperty -Path $Setting.Path -Name $Setting.Name -ErrorAction SilentlyContinue

            if ($CurrentValue -and $CurrentValue.$($Setting.Name) -ne $Setting.Value) {
                Write-DefenderLog "Fixing GPO setting: $($Setting.Name)" -Level "INFO"
                Set-ItemProperty -Path $Setting.Path -Name $Setting.Name -Value $Setting.Value -Type DWord -Force
                $RepairSuccess = $true
            }
        }
        catch {
            Write-DefenderLog "Could not modify $($Setting.Name): $($_.Exception.Message)" -Level "DEBUG"
        }
    }

    # Method 4: Remove DisableAntiSpyware if set (common malware tactic)
    try {
        $DefenderKey = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
        $DisableAS = Get-ItemProperty -Path $DefenderKey -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue

        if ($DisableAS -and $DisableAS.DisableAntiSpyware -eq 1) {
            Write-DefenderLog "Found DisableAntiSpyware=1 - removing (possible malware remnant)" -Level "WARN"
            Remove-ItemProperty -Path $DefenderKey -Name "DisableAntiSpyware" -Force -ErrorAction Stop
            $RepairSuccess = $true
        }
    }
    catch {
        Write-DefenderLog "Could not remove DisableAntiSpyware: $($_.Exception.Message)" -Level "DEBUG"
    }

    # Method 5: Restart dependent services
    Write-DefenderLog "Restarting security services..." -Level "INFO"
    $SecurityServices = @("wscsvc", "SecurityHealthService", "Sense")

    foreach ($SvcName in $SecurityServices) {
        $Svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
        if ($Svc) {
            try {
                if ($Svc.Status -ne "Running") {
                    Start-Service -Name $SvcName -ErrorAction SilentlyContinue
                    Write-DefenderLog "Started $SvcName service" -Level "DEBUG"
                }
                else {
                    Restart-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
                    Write-DefenderLog "Restarted $SvcName service" -Level "DEBUG"
                }
            }
            catch {
                Write-DefenderLog "Could not manage $SvcName service" -Level "DEBUG"
            }
        }
    }

    # Method 6: Run DISM health check (Windows 8+)
    Write-DefenderLog "Running system health check..." -Level "INFO"
    try {
        $DismResult = Start-Process dism.exe -ArgumentList "/Online /Cleanup-Image /RestoreHealth /NoRestart" -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
        if ($DismResult.ExitCode -eq 0) {
            Write-DefenderLog "DISM health restore completed - reboot recommended" -Level "SUCCESS"
            $RepairSuccess = $true
            $Script:RebootRequired = $true
        }
        elseif ($DismResult.ExitCode -eq 3010) {
            Write-DefenderLog "DISM completed - reboot required" -Level "SUCCESS"
            $RepairSuccess = $true
            $Script:RebootRequired = $true
        }
        else {
            Write-DefenderLog "DISM returned exit code: $($DismResult.ExitCode)" -Level "DEBUG"
        }
    }
    catch {
        Write-DefenderLog "DISM not available: $($_.Exception.Message)" -Level "DEBUG"
    }

    # Method 7: SFC scan for corrupted system files
    Write-DefenderLog "Running system file check..." -Level "INFO"
    try {
        $SfcResult = Start-Process sfc.exe -ArgumentList "/scannow" -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
        if ($SfcResult.ExitCode -eq 0) {
            Write-DefenderLog "SFC scan completed" -Level "SUCCESS"
            # SFC often needs reboot to complete repairs
            $Script:RebootRequired = $true
        }
    }
    catch {
        Write-DefenderLog "SFC not available: $($_.Exception.Message)" -Level "DEBUG"
    }

    return $RepairSuccess
}

function Add-RebootTag {
    # Tag device for reboot using Level.io API
    param([string]$TagName)

    if (-not $LevelApiKey) {
        Write-DefenderLog "Cannot tag for reboot - no API key available" -Level "WARN"
        return $false
    }

    # Check if tag already exists on device
    if ($DeviceTags -match [regex]::Escape($TagName)) {
        Write-DefenderLog "Device already has reboot tag" -Level "DEBUG"
        return $true
    }

    Write-DefenderLog "Tagging device for reboot: $TagName" -Level "INFO"

    try {
        # Use the library's tagging function if available
        if (Get-Command "Add-LevelDeviceTag" -ErrorAction SilentlyContinue) {
            $Result = Add-LevelDeviceTag -ApiKey $LevelApiKey -TagName $TagName
            if ($Result) {
                Write-DefenderLog "Device tagged for reboot" -Level "SUCCESS"
                return $true
            }
        }
        else {
            Write-DefenderLog "Add-LevelDeviceTag not available - reboot tag not applied" -Level "WARN"
        }
    }
    catch {
        Write-DefenderLog "Failed to tag device: $($_.Exception.Message)" -Level "ERROR"
    }

    return $false
}

function Test-DefenderHealth {
    # Quick health check to see if Defender needs repair
    $HealthIssues = @()

    # Check if main executable exists
    $MsMpEngPath = "$env:ProgramFiles\Windows Defender\MsMpEng.exe"
    if (-not (Test-Path $MsMpEngPath)) {
        $HealthIssues += "MsMpEng.exe missing"
    }

    # Check if Defender is disabled by policy
    $PolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $DisableAS = Get-ItemProperty -Path $PolicyPath -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    if ($DisableAS -and $DisableAS.DisableAntiSpyware -eq 1) {
        $HealthIssues += "Disabled by Group Policy"
    }

    # Check for malware-style disable
    $DefenderKey = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
    $DisableAS2 = Get-ItemProperty -Path $DefenderKey -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    if ($DisableAS2 -and $DisableAS2.DisableAntiSpyware -eq 1) {
        $HealthIssues += "DisableAntiSpyware registry key present"
    }

    # Check service health
    $WinDefend = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($WinDefend) {
        if ($WinDefend.StartType -eq "Disabled") {
            $HealthIssues += "Service disabled"
        }
    }
    else {
        $HealthIssues += "WinDefend service missing"
    }

    return @{
        Healthy = ($HealthIssues.Count -eq 0)
        Issues  = $HealthIssues
    }
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.18.01"
$ExitCode = 0

Write-DefenderLog "Windows Defender Enforcement (v$ScriptVersion)"
Write-DefenderLog "Host: $DeviceHostname"
Write-DefenderLog "Policy: $PolicyDefender" -Level "DEBUG"

# Check for exclusion tag (U+274C Cross Mark) - highest priority
if ($DeviceTags -match [regex]::Escape($ExclusionTag)) {
    Write-DefenderLog "Device has exclusion tag - skipping enforcement" -Level "INFO"
    Write-Host "OK: Device excluded from Defender enforcement"
    exit 0
}

# Check if Huntress is installed - Huntress requires working Defender
$HuntressService = Get-Service "HuntressAgent" -ErrorAction SilentlyContinue
$HuntressInstalled = $null -ne $HuntressService

if ($HuntressInstalled -and $PolicyDefender -ne "enforce") {
    Write-DefenderLog "Huntress detected - forcing Defender enforcement (was: $PolicyDefender)" -Level "INFO"
    $PolicyDefender = "enforce"
}

# Check policy setting
if ($PolicyDefender -ne "enforce") {
    Write-DefenderLog "Policy is '$PolicyDefender' (not 'enforce') - skipping" -Level "INFO"
    Write-Host "OK: Defender management skipped (policy=$PolicyDefender)"
    exit 0
}

# Get Windows version info
$WinInfo = Get-WindowsVersion
Write-DefenderLog "OS: $($WinInfo.Caption) (Build $($WinInfo.Build))" -Level "INFO"

# Check if this is a very old Windows that doesn't have proper Defender
if ($WinInfo.Major -lt 6 -or ($WinInfo.Major -eq 6 -and $WinInfo.Minor -eq 0)) {
    Write-DefenderLog "Windows Vista or older - Defender not fully supported" -Level "WARN"
    Write-Host "Alert: Windows version too old for Defender management"
    exit 1
}

# Get current Defender status
$Status = Get-DefenderStatus

# Check for third-party AV
if ($Status.ThirdPartyAV.Installed) {
    $AVList = $Status.ThirdPartyAV.Products -join ", "
    Write-DefenderLog "Third-party AV detected: $AVList" -Level "WARN"
    Write-DefenderLog "Defender may be legitimately disabled by third-party AV" -Level "INFO"

    # On Windows 10+, Defender can run alongside other AV in limited mode
    if ($WinInfo.Major -ge 10) {
        Write-DefenderLog "Windows 10+ detected - Defender can run in passive mode alongside other AV" -Level "INFO"
    }
    else {
        Write-DefenderLog "Older Windows - third-party AV typically disables Defender completely" -Level "INFO"
        Write-Host "OK: Third-party AV ($AVList) is managing endpoint protection"
        exit 0
    }
}

# Report initial status
Write-DefenderLog "Initial Status:" -Level "INFO"
Write-DefenderLog "  Service Exists: $($Status.ServiceExists)" -Level "DEBUG"
Write-DefenderLog "  Service Running: $($Status.ServiceRunning)" -Level "DEBUG"
Write-DefenderLog "  Service StartType: $($Status.ServiceStartType)" -Level "DEBUG"
Write-DefenderLog "  Real-Time Protection: $($Status.RealTimeEnabled)" -Level "DEBUG"

# Step 0: Health check and self-healing if needed
$HealthCheck = Test-DefenderHealth
if (-not $HealthCheck.Healthy) {
    Write-DefenderLog "Health issues detected:" -Level "WARN"
    foreach ($Issue in $HealthCheck.Issues) {
        Write-DefenderLog "  - $Issue" -Level "WARN"
    }

    # Attempt self-healing repair
    if (Repair-DefenderComponents) {
        Write-DefenderLog "Self-healing repair completed - rechecking status..." -Level "INFO"
        Start-Sleep -Seconds 5
        $Status = Get-DefenderStatus
    }
}

if (-not $Status.ServiceExists) {
    Write-DefenderLog "Defender service not found - may be removed or corrupted" -Level "ERROR"
    Write-Host "Alert: Windows Defender service not found on $DeviceHostname"
    exit 1
}

$ActionsTaken = @()
$Success = $true

# Step 1: Ensure service is enabled and running
if (-not $Status.ServiceRunning -or $Status.ServiceStartType -eq "Disabled") {
    $ServiceName = if (Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue) { "WinDefend" } else { "MsMpSvc" }

    if (Enable-DefenderService -ServiceName $ServiceName) {
        $ActionsTaken += "Enabled/started $ServiceName service"
    }
    else {
        # Try self-healing if enable fails
        Write-DefenderLog "Standard enable failed - attempting self-healing..." -Level "WARN"
        if (Repair-DefenderComponents) {
            Start-Sleep -Seconds 3
            if (Enable-DefenderService -ServiceName $ServiceName) {
                $ActionsTaken += "Enabled service after self-healing repair"
            }
            else {
                $Success = $false
            }
        }
        else {
            $Success = $false
        }
    }
}
else {
    Write-DefenderLog "Defender service already running" -Level "SUCCESS"
}

# Step 2: Enable real-time protection
if ($Status.CanManage -and -not $Status.RealTimeEnabled) {
    if (Enable-RealTimeProtection) {
        $ActionsTaken += "Enabled real-time protection"
    }
    else {
        $Success = $false
    }
}
elseif ($Status.RealTimeEnabled) {
    Write-DefenderLog "Real-time protection already enabled" -Level "SUCCESS"
}

# Step 3: Check signature age and update if stale (>7 days)
if ($Status.CanManage -and $Status.SignatureAge -and $Status.SignatureAge.TotalDays -gt 7) {
    Write-DefenderLog "Signatures are $([math]::Round($Status.SignatureAge.TotalDays, 1)) days old" -Level "WARN"
    if (Update-DefenderSignatures) {
        $ActionsTaken += "Initiated signature update"
    }
}

# Final status check
Start-Sleep -Seconds 2
$FinalStatus = Get-DefenderStatus

Write-DefenderLog "" -Level "INFO"
Write-DefenderLog "Final Status:" -Level "INFO"
Write-DefenderLog "  Service Running: $($FinalStatus.ServiceRunning)" -Level "INFO"
Write-DefenderLog "  Real-Time Protection: $($FinalStatus.RealTimeEnabled)" -Level "INFO"

if ($FinalStatus.AMEngineVersion) {
    Write-DefenderLog "  Engine Version: $($FinalStatus.AMEngineVersion)" -Level "INFO"
}

if ($ActionsTaken.Count -gt 0) {
    Write-DefenderLog "" -Level "INFO"
    Write-DefenderLog "Actions taken:" -Level "INFO"
    foreach ($Action in $ActionsTaken) {
        Write-DefenderLog "  - $Action" -Level "SUCCESS"
    }
}

# Handle reboot tagging if self-healing was performed
if ($Script:RebootRequired) {
    Write-DefenderLog "Reboot recommended to complete repairs" -Level "WARN"
    if (Add-RebootTag -TagName $RebootTag) {
        $ActionsTaken += "Tagged device for reboot tonight"
    }
}

# Determine exit status
if ($FinalStatus.ServiceRunning -and ($FinalStatus.RealTimeEnabled -or -not $FinalStatus.CanManage)) {
    if ($Script:RebootRequired) {
        Write-Host "OK: Windows Defender enabled on $DeviceHostname (reboot recommended)"
    }
    elseif ($ActionsTaken.Count -gt 0) {
        Write-Host "OK: Windows Defender enabled on $DeviceHostname"
    }
    else {
        Write-Host "OK: Windows Defender already running on $DeviceHostname"
    }
    $ExitCode = 0
}
else {
    # ALERT: Could not fix Defender
    $FailureReasons = @()
    if (-not $FinalStatus.ServiceRunning) {
        $FailureReasons += "Service not running"
    }
    if (-not $FinalStatus.RealTimeEnabled -and $FinalStatus.CanManage) {
        $FailureReasons += "Real-time protection disabled"
    }

    Write-Host "Alert: Failed to enable Windows Defender on $DeviceHostname"
    foreach ($Reason in $FailureReasons) {
        Write-Host "  - $Reason"
    }

    # Tag for reboot anyway - maybe reboot will help
    if (-not $Script:RebootRequired) {
        Write-DefenderLog "Tagging for reboot - may resolve issue" -Level "INFO"
        Add-RebootTag -TagName $RebootTag | Out-Null
    }

    $ExitCode = 1
}

exit $ExitCode
