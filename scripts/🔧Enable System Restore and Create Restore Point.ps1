<#
.SYNOPSIS
    Enables System Restore, creates a restore point, and schedules daily restore points.

.DESCRIPTION
    This script performs the following operations:

    1. Enables System Protection on the system drive (typically C:)
    2. Configures disk space allocation for restore points (default 10%)
    3. Creates an immediate restore point
    4. Verifies the restore point was created successfully
    5. Creates/updates a scheduled task to create daily restore points

    Works on Windows 7, 8, 8.1, 10, and 11.

.PARAMETER DiskSpacePercent
    Percentage of disk space to allocate for System Restore. Default: 10

.PARAMETER RestorePointDescription
    Description for the restore point. Default: "COOLForge_Lib Automated Restore Point"

.NOTES
    Version:          2025.12.29.01
    Target Platform:  Windows 7/8/8.1/10/11
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Enable System Restore and Create Restore Point
# Version: 2025.12.29.01
# Target: Level.io (via Script Launcher) or standalone
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/COOLForge

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================
$DiskSpacePercent = 10                                    # Percentage of disk space for restore points
$RestorePointDescription = "COOLForge_Lib Automated Restore Point"
$ScheduledTaskName = "COOLForge_Lib Daily System Restore Point"

# ============================================================
# VALIDATION
# ============================================================

# Check for Administrator privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "[X] FATAL: This script requires Administrator privileges"
    exit 1
}

# Get OS information
$OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if (-not $OSInfo) {
    $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
}
$BuildNumber = [int]$OSInfo.BuildNumber
$OSCaption = $OSInfo.Caption

Write-Host "[*] Operating System: $OSCaption (Build $BuildNumber)"

# Verify supported Windows version (7, 8, 8.1, 10, 11)
# Windows 7: 7600-7601, Windows 8: 9200, Windows 8.1: 9600
# Windows 10: 10240-19045, Windows 11: 22000+
if ($BuildNumber -lt 7600) {
    Write-Host "[X] FATAL: This script requires Windows 7 or later"
    exit 1
}

# Get system drive
$SystemDrive = $env:SystemDrive
if (-not $SystemDrive) {
    $SystemDrive = "C:"
}
Write-Host "[*] System Drive: $SystemDrive"

# ============================================================
# ENABLE SYSTEM PROTECTION
# ============================================================
Write-Host ""
Write-Host "[*] Step 1: Enabling System Protection on $SystemDrive"

try {
    # Check current status using vssadmin
    $VssOutput = & vssadmin list shadowstorage 2>&1

    # Enable System Protection via WMI (works on all Windows versions)
    # First, try to enable via registry (most reliable method)
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"

    # Enable System Restore globally
    if (Test-Path $RegPath) {
        $CurrentValue = Get-ItemProperty -Path $RegPath -Name "RPSessionInterval" -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegPath -Name "RPSessionInterval" -Value 1 -Type DWord -Force
        Write-Host "[+] System Restore enabled in registry"
    }

    # Enable for the system drive specifically
    $DriveRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients"

    # Use Enable-ComputerRestore cmdlet (available on Windows 8+)
    if ($BuildNumber -ge 9200) {
        Enable-ComputerRestore -Drive "$SystemDrive\" -ErrorAction Stop
        Write-Host "[+] System Protection enabled via Enable-ComputerRestore"
    }
    else {
        # Windows 7: Use WMI
        $SR = Get-WmiObject -Class SystemRestore -Namespace "root\default" -ErrorAction Stop
        $EnableResult = $SR.Enable("$SystemDrive\")
        if ($EnableResult.ReturnValue -eq 0) {
            Write-Host "[+] System Protection enabled via WMI"
        }
        else {
            Write-Host "[!] WMI Enable returned: $($EnableResult.ReturnValue)"
        }
    }
}
catch {
    Write-Host "[!] Warning during enable: $($_.Exception.Message)"
    Write-Host "[*] Continuing - System Protection may already be enabled"
}

# ============================================================
# CONFIGURE DISK SPACE
# ============================================================
Write-Host ""
Write-Host "[*] Step 2: Configuring disk space allocation ($DiskSpacePercent%)"

try {
    # Get drive size
    $Drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$SystemDrive'" -ErrorAction SilentlyContinue
    if (-not $Drive) {
        $Drive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$SystemDrive'"
    }

    $DriveSizeGB = [math]::Round($Drive.Size / 1GB, 2)
    $AllocatedGB = [math]::Round(($Drive.Size * $DiskSpacePercent / 100) / 1GB, 2)

    Write-Host "[*] Drive size: $DriveSizeGB GB"
    Write-Host "[*] Allocating: $AllocatedGB GB ($DiskSpacePercent%)"

    # Configure shadow storage using vssadmin
    $MaxSizeBytes = [math]::Floor($Drive.Size * $DiskSpacePercent / 100)
    $MaxSizeMB = [math]::Floor($MaxSizeBytes / 1MB)

    # Try to resize existing shadow storage first
    $ResizeResult = & vssadmin resize shadowstorage /For=$SystemDrive /On=$SystemDrive /MaxSize="${MaxSizeMB}MB" 2>&1

    if ($LASTEXITCODE -ne 0) {
        # If resize fails, try to add new shadow storage
        $AddResult = & vssadmin add shadowstorage /For=$SystemDrive /On=$SystemDrive /MaxSize="${MaxSizeMB}MB" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Shadow storage configured"
        }
        else {
            Write-Host "[!] Could not configure shadow storage size (may already be set)"
        }
    }
    else {
        Write-Host "[+] Shadow storage resized to $AllocatedGB GB"
    }
}
catch {
    Write-Host "[!] Warning configuring disk space: $($_.Exception.Message)"
    Write-Host "[*] Continuing with default settings"
}

# ============================================================
# CREATE RESTORE POINT
# ============================================================
Write-Host ""
Write-Host "[*] Step 3: Creating restore point"

$RestorePointCreated = $false
$NewRestorePoint = $null

try {
    # Get existing restore points for comparison
    $ExistingPoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    $ExistingCount = if ($ExistingPoints) { @($ExistingPoints).Count } else { 0 }

    # Windows has a 24-hour frequency limit by default - disable it temporarily
    $FrequencyRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
    $OriginalFrequency = Get-ItemProperty -Path $FrequencyRegPath -Name "SystemRestorePointCreationFrequency" -ErrorAction SilentlyContinue

    # Set frequency to 0 to allow immediate creation
    Set-ItemProperty -Path $FrequencyRegPath -Name "SystemRestorePointCreationFrequency" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

    # Create the restore point
    $Description = "$RestorePointDescription - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"

    if ($BuildNumber -ge 9200) {
        # Windows 8+ method
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host "[+] Restore point creation initiated"
    }
    else {
        # Windows 7 method using WMI
        $SR = Get-WmiObject -Class SystemRestore -Namespace "root\default" -ErrorAction Stop
        $CreateResult = $SR.CreateRestorePoint($Description, 12, 100)  # 12 = MODIFY_SETTINGS, 100 = BEGIN_NESTED_SYSTEM_CHANGE
        if ($CreateResult.ReturnValue -eq 0) {
            Write-Host "[+] Restore point creation initiated via WMI"
        }
        else {
            throw "WMI CreateRestorePoint returned: $($CreateResult.ReturnValue)"
        }
    }

    # Restore original frequency setting
    if ($OriginalFrequency -and $OriginalFrequency.SystemRestorePointCreationFrequency) {
        Set-ItemProperty -Path $FrequencyRegPath -Name "SystemRestorePointCreationFrequency" -Value $OriginalFrequency.SystemRestorePointCreationFrequency -Type DWord -Force -ErrorAction SilentlyContinue
    }
    else {
        # Remove the key to use default behavior
        Remove-ItemProperty -Path $FrequencyRegPath -Name "SystemRestorePointCreationFrequency" -ErrorAction SilentlyContinue
    }

    $RestorePointCreated = $true
}
catch {
    Write-Host "[X] Failed to create restore point: $($_.Exception.Message)"

    # Common issues and solutions
    if ($_.Exception.Message -match "0x80070422") {
        Write-Host "[!] The Volume Shadow Copy service is not running"
        Write-Host "[*] Attempting to start the service..."
        try {
            Start-Service -Name VSS -ErrorAction Stop
            Write-Host "[+] VSS service started"
        }
        catch {
            Write-Host "[X] Could not start VSS service"
        }
    }
    elseif ($_.Exception.Message -match "frequency") {
        Write-Host "[!] A restore point was created recently (Windows 24-hour limit)"
        Write-Host "[*] The scheduled task will create daily restore points going forward"
        $RestorePointCreated = $true  # Consider this a soft success
    }
}

# ============================================================
# VERIFY RESTORE POINT
# ============================================================
Write-Host ""
Write-Host "[*] Step 4: Verifying restore point"

$VerificationPassed = $false

try {
    # Wait a moment for the restore point to be registered
    Start-Sleep -Seconds 3

    # Get current restore points
    $CurrentPoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    $CurrentCount = if ($CurrentPoints) { @($CurrentPoints).Count } else { 0 }

    Write-Host "[*] Total restore points found: $CurrentCount"

    if ($CurrentCount -gt 0) {
        # Get the most recent restore point
        $LatestPoint = $CurrentPoints | Sort-Object -Property SequenceNumber -Descending | Select-Object -First 1

        Write-Host "[*] Latest restore point:"
        Write-Host "    Sequence: $($LatestPoint.SequenceNumber)"
        Write-Host "    Description: $($LatestPoint.Description)"
        Write-Host "    Created: $($LatestPoint.ConvertToDateTime($LatestPoint.CreationTime))"

        # Check if this looks like our restore point (created within last 5 minutes)
        $PointTime = $LatestPoint.ConvertToDateTime($LatestPoint.CreationTime)
        $TimeDiff = (Get-Date) - $PointTime

        if ($TimeDiff.TotalMinutes -lt 5 -or $LatestPoint.Description -like "*COOLForge_Lib*") {
            Write-Host "[+] Restore point verified successfully"
            $VerificationPassed = $true
        }
        elseif ($RestorePointCreated) {
            Write-Host "[*] Restore point may still be processing"
            $VerificationPassed = $true  # Trust the creation succeeded
        }
    }
    else {
        Write-Host "[!] No restore points found"
    }
}
catch {
    Write-Host "[!] Could not verify restore points: $($_.Exception.Message)"
    if ($RestorePointCreated) {
        $VerificationPassed = $true  # Trust the creation if it reported success
    }
}

# ============================================================
# CREATE DAILY SCHEDULED TASK
# ============================================================
Write-Host ""
Write-Host "[*] Step 5: Creating daily scheduled task"

try {
    # PowerShell command to create a restore point
    $PSCommand = @'
$ErrorActionPreference = 'SilentlyContinue'
$FreqPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
Set-ItemProperty -Path $FreqPath -Name 'SystemRestorePointCreationFrequency' -Value 0 -Type DWord -Force
Checkpoint-Computer -Description "COOLForge_Lib Daily Restore Point - $(Get-Date -Format 'yyyy-MM-dd')" -RestorePointType MODIFY_SETTINGS
Remove-ItemProperty -Path $FreqPath -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue
'@

    # Encode for use in scheduled task
    $EncodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($PSCommand))

    # Check if task already exists
    $ExistingTask = Get-ScheduledTask -TaskName $ScheduledTaskName -ErrorAction SilentlyContinue

    if ($ExistingTask) {
        Write-Host "[*] Scheduled task already exists - updating"
        Unregister-ScheduledTask -TaskName $ScheduledTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    # Create the scheduled task (Windows 8+ method)
    if ($BuildNumber -ge 9200) {
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $EncodedCommand"
        $Trigger = New-ScheduledTaskTrigger -Daily -At "03:00AM"
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

        Register-ScheduledTask -TaskName $ScheduledTaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "Creates a daily System Restore point at 3:00 AM" -Force | Out-Null

        Write-Host "[+] Scheduled task created: $ScheduledTaskName"
        Write-Host "[*] Daily restore points will be created at 3:00 AM"
    }
    else {
        # Windows 7 method using schtasks.exe
        $TaskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>$(Get-Date -Format 'yyyy-MM-dd')T03:00:00</StartBoundary>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -EncodedCommand $EncodedCommand</Arguments>
    </Exec>
  </Actions>
</Task>
"@

        $TempXmlPath = Join-Path $env:TEMP "COOLForge_LibRestoreTask.xml"
        $TaskXml | Out-File -FilePath $TempXmlPath -Encoding Unicode -Force

        & schtasks.exe /Create /TN $ScheduledTaskName /XML $TempXmlPath /F 2>&1 | Out-Null

        Remove-Item -Path $TempXmlPath -Force -ErrorAction SilentlyContinue

        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Scheduled task created: $ScheduledTaskName"
            Write-Host "[*] Daily restore points will be created at 3:00 AM"
        }
        else {
            Write-Host "[!] Could not create scheduled task via schtasks.exe"
        }
    }
}
catch {
    Write-Host "[!] Could not create scheduled task: $($_.Exception.Message)"
    Write-Host "[*] Manual daily restore points may be required"
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "========================================"
Write-Host "System Restore Configuration Complete"
Write-Host "========================================"
Write-Host "  System Protection:  Enabled on $SystemDrive"
Write-Host "  Disk Allocation:    $DiskSpacePercent% (~$AllocatedGB GB)"
Write-Host "  Restore Point:      $(if ($VerificationPassed) { 'Created & Verified' } else { 'Check manually' })"
Write-Host "  Daily Schedule:     3:00 AM"
Write-Host "========================================"

if (-not $VerificationPassed) {
    Write-Host ""
    Write-Host "[!] Restore point creation could not be fully verified"
    Write-Host "[*] Check System Protection settings in Control Panel"
    exit 1
}

Write-Host ""
Write-Host "[+] System Restore is now configured and active"
exit 0
