# Install-ScreenConnect-Standalone.ps1 - Force install ScreenConnect client
# Standalone version - no Level.io custom fields required
# Base URL: https://support.cool.net.au
# Instance ID: 983fa4f3c185dd21
#
# Usage: Run as Administrator (or use the .cmd launcher)
# Can also be run from USB - will copy itself to C:\ProgramData\COOLNETWORKS\tools\

$ErrorActionPreference = 'Stop'

# ============================================================
# CONFIGURATION
# ============================================================
$BaseUrl = "https://support.cool.net.au"
$InstanceId = "983fa4f3c185dd21"
$Hostname = $env:COMPUTERNAME
$TempFolder = $env:TEMP
$PermanentDir = "C:\ProgramData\COOLNETWORKS\tools"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot }
             elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
             else { Get-Location | Select-Object -ExpandProperty Path }
$logDir = Join-Path $scriptDir "logs"
$logFile = Join-Path $logDir "$Hostname-screenconnect.log"

# ============================================================
# SETUP
# ============================================================

# Create logs directory
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# If running from USB, copy to permanent location
$myPath = if ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } elseif ($PSCommandPath) { $PSCommandPath } else { $null }
if ($myPath) {
    $myDrive = (Get-Item $myPath).PSDrive
    $driveInfo = Get-Volume -DriveLetter $myDrive.Name -ErrorAction SilentlyContinue
    if ($driveInfo -and $driveInfo.DriveType -eq 'Removable') {
        Write-Host "Running from USB - updating permanent copy at $PermanentDir..."
        if (-not (Test-Path $PermanentDir)) { New-Item -ItemType Directory -Path $PermanentDir -Force | Out-Null }
        Copy-Item $myPath -Destination "$PermanentDir\Install-ScreenConnect-Standalone.ps1" -Force
        $cmdPath = Join-Path $scriptDir "Install-ScreenConnect-Standalone.cmd"
        if (Test-Path $cmdPath) { Copy-Item $cmdPath -Destination "$PermanentDir\Install-ScreenConnect-Standalone.cmd" -Force }
        Write-Host "Permanent copy updated."
    }
}

# ============================================================
# LOGGING
# ============================================================

function Log {
    param([string]$msg, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "INFO"    { "[INFO]" }
        "WARN"    { "[WARN]" }
        "ERROR"   { "[ERROR]" }
        "OK"      { "[OK]" }
        default   { "[INFO]" }
    }
    $color = switch ($Level) {
        "INFO"    { "White" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "OK"      { "Green" }
        default   { "White" }
    }
    $line = "$ts $prefix $msg"
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $logFile -Value $line -ErrorAction SilentlyContinue
}

# ============================================================
# FUNCTIONS
# ============================================================

function Test-ScreenConnectInstalled {
    param([string]$Id)
    $services = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like "*ScreenConnect Client*$Id*" }
    return ($null -ne $services -and $services.Count -gt 0)
}

function Get-ScreenConnectService {
    param([string]$Id)
    return Get-Service | Where-Object { $_.DisplayName -like "*ScreenConnect*$Id*" } | Select-Object -First 1
}

function Uninstall-ExistingScreenConnect {
    param([string]$Id)

    Log "Checking for existing ScreenConnect installation..."

    # Stop services
    $services = Get-Service | Where-Object { $_.DisplayName -like "*ScreenConnect*$Id*" }
    foreach ($svc in $services) {
        Log "Stopping service: $($svc.DisplayName)" "WARN"
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
    }

    # Find and run uninstaller
    $scFolders = Get-Item -Path "${env:ProgramFiles}\ScreenConnect Client*$Id*" -ErrorAction SilentlyContinue
    foreach ($folder in $scFolders) {
        $uninstaller = Join-Path $folder.FullName "ScreenConnect.ClientService.exe"
        if (Test-Path $uninstaller) {
            Log "Running uninstaller: $uninstaller"
            Start-Process -FilePath $uninstaller -ArgumentList "?e=Uninstall" -Wait -ErrorAction SilentlyContinue
        }
    }

    # Also try MSI uninstall via registry
    $uninstallKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
        Get-ItemProperty | Where-Object { $_.DisplayName -like "*ScreenConnect*" -and $_.DisplayName -like "*$Id*" }
    foreach ($key in $uninstallKeys) {
        if ($key.UninstallString) {
            Log "MSI uninstall: $($key.DisplayName)"
            $uninstallCmd = $key.UninstallString -replace '/I', '/X'
            if ($uninstallCmd -notlike '*/qn*') { $uninstallCmd += ' /qn' }
            Start-Process cmd.exe -ArgumentList "/c $uninstallCmd" -Wait -ErrorAction SilentlyContinue
        }
    }

    Start-Sleep -Seconds 3
    Log "Existing installation removed" "OK"
}

function Install-ScreenConnect {
    param(
        [string]$Url,
        [string]$Company
    )

    # URL encode company name for custom property
    $CP1 = [uri]::EscapeDataString($Company)

    # Build MSI download URL
    # c= parameters: CP1(company), CP2, CP3, CP4, CP5, CP6, CP7, CP8
    $MsiUrl = "$Url/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=$CP1&c=&c=&c=&c=&c=&c=&c="

    Log "Download URL: $MsiUrl"
    Log "Company (CP1): $Company"

    $MsiPath = Join-Path $TempFolder "ScreenConnect.ClientSetup.msi"

    # Download
    Log "Downloading ScreenConnect MSI..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing -TimeoutSec 120
        $ProgressPreference = 'Continue'
        $fileSize = [math]::Round((Get-Item $MsiPath).Length / 1MB, 1)
        Log "Downloaded: $MsiPath ($fileSize MB)" "OK"
    } catch {
        Log "Download failed: $($_.Exception.Message)" "ERROR"
        return $false
    }

    # Install
    Log "Installing ScreenConnect..."
    try {
        $proc = Start-Process -FilePath "msiexec.exe" `
            -ArgumentList "/i `"$MsiPath`" /qn /norestart" `
            -Wait -PassThru

        if ($proc.ExitCode -eq 0) {
            Log "ScreenConnect installed successfully" "OK"
            return $true
        } else {
            Log "MSI install returned exit code: $($proc.ExitCode)" "ERROR"
            return $false
        }
    } catch {
        Log "Install failed: $($_.Exception.Message)" "ERROR"
        return $false
    } finally {
        if (Test-Path $MsiPath) {
            Remove-Item $MsiPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# ============================================================
# MAIN
# ============================================================

Log "=========================================="
Log "ScreenConnect Force Install - $Hostname"
Log "=========================================="
Log "Base URL: $BaseUrl"
Log "Instance ID: $InstanceId"
Log ""

# Step 1: Check current state
Log "--- Step 1: Check current state ---"
$isInstalled = Test-ScreenConnectInstalled -Id $InstanceId
$scService = Get-ScreenConnectService -Id $InstanceId

if ($isInstalled) {
    Log "ScreenConnect IS installed for instance $InstanceId" "WARN"
    if ($scService) {
        Log "Service: $($scService.DisplayName) - Status: $($scService.Status)"
    }
} else {
    Log "ScreenConnect is NOT installed for instance $InstanceId"
}

# Check for any other ScreenConnect instances
$allSC = Get-Service | Where-Object { $_.DisplayName -like "*ScreenConnect*" }
if ($allSC) {
    Log "All ScreenConnect services found:"
    foreach ($s in $allSC) {
        $isOurs = if ($s.DisplayName -like "*$InstanceId*") { " [OURS]" } else { " [OTHER]" }
        Log "  $($s.DisplayName) - $($s.Status)$isOurs"
    }
}

# Step 2: Uninstall existing if present
if ($isInstalled) {
    Log ""
    Log "--- Step 2: Remove existing installation ---"
    Uninstall-ExistingScreenConnect -Id $InstanceId
}

# Step 3: Install fresh
Log ""
Log "--- Step 3: Install ScreenConnect ---"
$success = Install-ScreenConnect -Url $BaseUrl -Company $Hostname

if (-not $success) {
    Log "Installation FAILED" "ERROR"
    exit 1
}

# Step 4: Verify
Log ""
Log "--- Step 4: Verify installation ---"
Start-Sleep -Seconds 10

$verified = Test-ScreenConnectInstalled -Id $InstanceId
$scService = Get-ScreenConnectService -Id $InstanceId

if ($verified -and $scService) {
    Log "ScreenConnect verified and running" "OK"
    Log "  Service: $($scService.DisplayName)"
    Log "  Status: $($scService.Status)"
} elseif ($verified) {
    Log "ScreenConnect installed but service not yet found - may need a moment" "WARN"
} else {
    Log "Installation verification FAILED - service not found" "ERROR"
}

# Step 5: Network connectivity check
Log ""
Log "--- Step 5: Connectivity check ---"
try {
    $result = Test-NetConnection -ComputerName "support.cool.net.au" -Port 443 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($result.TcpTestSucceeded) {
        Log "support.cool.net.au:443 - OK" "OK"
    } else {
        Log "support.cool.net.au:443 - FAILED" "ERROR"
    }
} catch {
    Log "Connectivity test failed: $($_.Exception.Message)" "ERROR"
}

Log ""
Log "=========================================="
Log "DONE - Log saved to $logFile"
Log "=========================================="
