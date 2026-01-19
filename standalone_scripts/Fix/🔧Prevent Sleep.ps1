<#
.SYNOPSIS
    Temporarily prevents the device from sleeping for a configurable duration.

.DESCRIPTION
    This script temporarily disables sleep and hibernate modes on a Windows device.
    It performs the following operations:

    1. Reads the timeout duration from CoolForge_nosleep_duration_min custom field
    2. Backs up current power settings to registry (with verification)
    3. Disables sleep/hibernate on AC and DC power
    4. Stores the expiry time in registry
    5. Creates a scheduled task to automatically restore settings after timeout

    The backup includes:
    - Monitor timeout (AC/DC)
    - Standby timeout (AC/DC)
    - Hibernate timeout (AC/DC)
    - Current power scheme GUID

    Settings are stored in: HKLM:\SOFTWARE\<MSPName>\COOLForge\NoSleep

.PARAMETER TimeoutMinutes
    Override the timeout from custom field. If not specified, uses CoolForge_nosleep_duration_min.
    Default: 60 minutes if custom field not set.

.NOTES
    Version:          2025.12.30.01
    Target Platform:  Windows 7/8/8.1/10/11
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Custom Fields Used:
    - CoolForge_nosleep_duration_min : Duration in minutes to prevent sleep (default: 60)
    - CoolForge_msp_scratch_folder   : MSP scratch folder (used to derive MSP name)

    License:          AGPL-3.0 (see LICENSE)
    Copyright (c) 2025-2026 COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Prevent Sleep
# Version: 2025.12.30.01
# Target: Level.io (via Script Launcher) or standalone
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================
# These can be overridden by Level.io custom fields
$DefaultTimeoutMinutes = 60
$ScheduledTaskName = "COOLForge_RestoreSleepSettings"
$RevertScriptName = "🔧Restore Sleep Settings.ps1"

# ============================================================
# LEVEL.IO CUSTOM FIELDS
# ============================================================
# When run via launcher, these will be populated
$MspScratchFolder = "{{cf_coolforge_msp_scratch_folder}}"
# Fallback for local testing
if ([string]::IsNullOrWhiteSpace($MspScratchFolder) -or $MspScratchFolder -like "{{*}}") {
    $MspScratchFolder = "C:\ProgramData\MSP"
}

$NoSleepDuration = "{{cf_coolforge_nosleep_duration_min}}"
if ([string]::IsNullOrWhiteSpace($NoSleepDuration) -or $NoSleepDuration -eq "{{cf_coolforge_nosleep_duration_min}}" -or $NoSleepDuration -like "{{*}}") {
    $NoSleepDuration = $DefaultTimeoutMinutes
}

# Convert to integer
try {
    $TimeoutMinutes = [int]$NoSleepDuration
    if ($TimeoutMinutes -le 0) {
        $TimeoutMinutes = $DefaultTimeoutMinutes
    }
} catch {
    $TimeoutMinutes = $DefaultTimeoutMinutes
}

# Derive MSP name from scratch folder
$MspName = Split-Path $MspScratchFolder -Leaf
if ([string]::IsNullOrWhiteSpace($MspName)) {
    $MspName = "MSP"
}

# Registry paths
$RegistryBasePath = "HKLM:\SOFTWARE\$MspName\COOLForge\NoSleep"

# ============================================================
# VALIDATION
# ============================================================

# Check for Administrator privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "[Alert] This script requires Administrator privileges"
    exit 1
}

Write-Host "[*] Prevent Sleep Script v2025.12.30.01"
Write-Host "[*] MSP Name: $MspName"
Write-Host "[*] Registry Path: $RegistryBasePath"
Write-Host ""

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Get-PowerSettingValue {
    param(
        [string]$SettingName,
        [string]$PowerSource  # AC or DC
    )

    $index = if ($PowerSource -eq "AC") { "/SETACVALUEINDEX" } else { "/SETDCVALUEINDEX" }
    $queryIndex = if ($PowerSource -eq "AC") { "AC" } else { "DC" }

    # Get current power scheme
    $schemeOutput = & powercfg /getactivescheme 2>&1
    if ($schemeOutput -match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})") {
        $schemeGuid = $Matches[1]
    } else {
        return $null
    }

    # Query the specific setting
    switch ($SettingName) {
        "MonitorTimeout" {
            $subgroup = "7516b95f-f776-4464-8c53-06167f40cc99"  # Display
            $setting = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"   # Turn off display after
        }
        "StandbyTimeout" {
            $subgroup = "238c9fa8-0aad-41ed-83f4-97be242c8f20"  # Sleep
            $setting = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"   # Sleep after
        }
        "HibernateTimeout" {
            $subgroup = "238c9fa8-0aad-41ed-83f4-97be242c8f20"  # Sleep
            $setting = "9d7815a6-7ee4-497e-8888-515a05f02364"   # Hibernate after
        }
        default { return $null }
    }

    $output = & powercfg /query $schemeGuid $subgroup $setting 2>&1
    $pattern = if ($PowerSource -eq "AC") { "Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)" } else { "Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)" }

    if ($output -match $pattern) {
        return [Convert]::ToInt32($Matches[1], 16)
    }
    return $null
}

function Set-PowerSettingValue {
    param(
        [string]$SettingName,
        [string]$PowerSource,
        [int]$Value
    )

    $indexParam = if ($PowerSource -eq "AC") { "/SETACVALUEINDEX" } else { "/SETDCVALUEINDEX" }

    # Get current power scheme
    $schemeOutput = & powercfg /getactivescheme 2>&1
    if ($schemeOutput -match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})") {
        $schemeGuid = $Matches[1]
    } else {
        throw "Could not determine active power scheme"
    }

    switch ($SettingName) {
        "MonitorTimeout" {
            $subgroup = "7516b95f-f776-4464-8c53-06167f40cc99"
            $setting = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"
        }
        "StandbyTimeout" {
            $subgroup = "238c9fa8-0aad-41ed-83f4-97be242c8f20"
            $setting = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
        }
        "HibernateTimeout" {
            $subgroup = "238c9fa8-0aad-41ed-83f4-97be242c8f20"
            $setting = "9d7815a6-7ee4-497e-8888-515a05f02364"
        }
        default { throw "Unknown setting: $SettingName" }
    }

    $result = & powercfg $indexParam $schemeGuid $subgroup $setting $Value 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set $SettingName ($PowerSource): $result"
    }

    # Apply the change
    & powercfg /setactive $schemeGuid | Out-Null
}

# ============================================================
# STEP 1: CHECK IF ALREADY ACTIVE (IDEMPOTENT)
# ============================================================
Write-Host "[*] Step 1: Checking for existing no-sleep session..."

$AlreadyActive = $false
$ExistingExpiryTime = $null

if (Test-Path $RegistryBasePath) {
    $existingExpiry = Get-ItemProperty -Path $RegistryBasePath -Name "ExpiryTime" -ErrorAction SilentlyContinue
    if ($existingExpiry) {
        try {
            $ExistingExpiryTime = [DateTime]::Parse($existingExpiry.ExpiryTime)
            if ($ExistingExpiryTime -gt (Get-Date)) {
                $AlreadyActive = $true
                Write-Host "[!] No-sleep is ALREADY ACTIVE"
                Write-Host "    Current expiry: $($ExistingExpiryTime.ToString('yyyy-MM-dd HH:mm:ss'))"

                # Calculate new expiry time
                $NewExpiryTime = (Get-Date).AddMinutes($TimeoutMinutes)

                if ($NewExpiryTime -gt $ExistingExpiryTime) {
                    Write-Host "[*] Extending timeout to $TimeoutMinutes minutes from now..."
                    Write-Host "    New expiry: $($NewExpiryTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                } else {
                    Write-Host "[*] Current timeout extends further - no change needed"
                    Write-Host ""
                    Write-Host "============================================================"
                    Write-Host "[+] DEVICE SHOULD NOT SLEEP BEFORE:"
                    Write-Host "    $($ExistingExpiryTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                    Write-Host "============================================================"
                    Write-Host ""
                    exit 0
                }
            } else {
                Write-Host "[*] Previous no-sleep session has expired"
            }
        } catch {
            Write-Host "[*] Could not parse existing expiry time"
        }
    }
}

# ============================================================
# STEP 2: BACKUP CURRENT SETTINGS (skip if already active)
# ============================================================
Write-Host ""

# Get active power scheme (needed for both backup and setting changes)
$schemeOutput = & powercfg /getactivescheme 2>&1
if ($schemeOutput -match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})") {
    $ActiveSchemeGuid = $Matches[1]
} else {
    Write-Host "[Alert] Could not determine active power scheme"
    exit 1
}

if ($AlreadyActive) {
    # Already active - skip backup, just extend the timeout
    Write-Host "[*] Step 2: Skipping backup (using existing backup from previous run)"
    Write-Host "    Active Power Scheme: $ActiveSchemeGuid"

    # Load existing backup for reference
    $Backup = Get-ItemProperty -Path $RegistryBasePath -ErrorAction SilentlyContinue
    Write-Host "[+] Using existing backup from: $($Backup.BackupTime)"
} else {
    Write-Host "[*] Step 2: Backing up current power settings..."
    Write-Host "    Active Power Scheme: $ActiveSchemeGuid"

    # Collect current settings
    $Backup = @{
        SchemeGuid = $ActiveSchemeGuid
        MonitorTimeoutAC = Get-PowerSettingValue -SettingName "MonitorTimeout" -PowerSource "AC"
        MonitorTimeoutDC = Get-PowerSettingValue -SettingName "MonitorTimeout" -PowerSource "DC"
        StandbyTimeoutAC = Get-PowerSettingValue -SettingName "StandbyTimeout" -PowerSource "AC"
        StandbyTimeoutDC = Get-PowerSettingValue -SettingName "StandbyTimeout" -PowerSource "DC"
        HibernateTimeoutAC = Get-PowerSettingValue -SettingName "HibernateTimeout" -PowerSource "AC"
        HibernateTimeoutDC = Get-PowerSettingValue -SettingName "HibernateTimeout" -PowerSource "DC"
        BackupTime = (Get-Date).ToString("o")
    }

    Write-Host "    Monitor Timeout (AC): $($Backup.MonitorTimeoutAC) seconds"
    Write-Host "    Monitor Timeout (DC): $($Backup.MonitorTimeoutDC) seconds"
    Write-Host "    Standby Timeout (AC): $($Backup.StandbyTimeoutAC) seconds"
    Write-Host "    Standby Timeout (DC): $($Backup.StandbyTimeoutDC) seconds"
    Write-Host "    Hibernate Timeout (AC): $($Backup.HibernateTimeoutAC) seconds"
    Write-Host "    Hibernate Timeout (DC): $($Backup.HibernateTimeoutDC) seconds"

    # Create registry path if needed
    if (-not (Test-Path $RegistryBasePath)) {
        New-Item -Path $RegistryBasePath -Force | Out-Null
        Write-Host "    Created registry path: $RegistryBasePath"
    }

    # Save backup to registry
    Set-ItemProperty -Path $RegistryBasePath -Name "SchemeGuid" -Value $Backup.SchemeGuid -Type String
    Set-ItemProperty -Path $RegistryBasePath -Name "MonitorTimeoutAC" -Value $Backup.MonitorTimeoutAC -Type DWord
    Set-ItemProperty -Path $RegistryBasePath -Name "MonitorTimeoutDC" -Value $Backup.MonitorTimeoutDC -Type DWord
    Set-ItemProperty -Path $RegistryBasePath -Name "StandbyTimeoutAC" -Value $Backup.StandbyTimeoutAC -Type DWord
    Set-ItemProperty -Path $RegistryBasePath -Name "StandbyTimeoutDC" -Value $Backup.StandbyTimeoutDC -Type DWord
    Set-ItemProperty -Path $RegistryBasePath -Name "HibernateTimeoutAC" -Value $Backup.HibernateTimeoutAC -Type DWord
    Set-ItemProperty -Path $RegistryBasePath -Name "HibernateTimeoutDC" -Value $Backup.HibernateTimeoutDC -Type DWord
    Set-ItemProperty -Path $RegistryBasePath -Name "BackupTime" -Value $Backup.BackupTime -Type String

    Write-Host "[+] Backup saved to registry"

    # ============================================================
    # STEP 3: VERIFY BACKUP
    # ============================================================
    Write-Host ""
    Write-Host "[*] Step 3: Verifying backup..."

    $VerifyBackup = Get-ItemProperty -Path $RegistryBasePath -ErrorAction SilentlyContinue
    $BackupValid = $true

    if ($VerifyBackup.SchemeGuid -ne $Backup.SchemeGuid) { $BackupValid = $false; Write-Host "[!] SchemeGuid mismatch" }
    if ($VerifyBackup.MonitorTimeoutAC -ne $Backup.MonitorTimeoutAC) { $BackupValid = $false; Write-Host "[!] MonitorTimeoutAC mismatch" }
    if ($VerifyBackup.MonitorTimeoutDC -ne $Backup.MonitorTimeoutDC) { $BackupValid = $false; Write-Host "[!] MonitorTimeoutDC mismatch" }
    if ($VerifyBackup.StandbyTimeoutAC -ne $Backup.StandbyTimeoutAC) { $BackupValid = $false; Write-Host "[!] StandbyTimeoutAC mismatch" }
    if ($VerifyBackup.StandbyTimeoutDC -ne $Backup.StandbyTimeoutDC) { $BackupValid = $false; Write-Host "[!] StandbyTimeoutDC mismatch" }
    if ($VerifyBackup.HibernateTimeoutAC -ne $Backup.HibernateTimeoutAC) { $BackupValid = $false; Write-Host "[!] HibernateTimeoutAC mismatch" }
    if ($VerifyBackup.HibernateTimeoutDC -ne $Backup.HibernateTimeoutDC) { $BackupValid = $false; Write-Host "[!] HibernateTimeoutDC mismatch" }

    if (-not $BackupValid) {
        Write-Host "[Alert] Backup verification failed - aborting to protect current settings"
        exit 1
    }

    Write-Host "[+] Backup verified successfully"
}

# ============================================================
# STEP 3/4: DISABLE SLEEP/HIBERNATE
# ============================================================
Write-Host ""
$StepNum = if ($AlreadyActive) { "3" } else { "4" }
Write-Host "[*] Step ${StepNum}: Disabling sleep and hibernate..."

try {
    # Set all sleep timeouts to 0 (never)
    # Keep monitor timeout at a reasonable value (30 min) to save power
    Set-PowerSettingValue -SettingName "StandbyTimeout" -PowerSource "AC" -Value 0
    Write-Host "    Standby (AC): Disabled"

    Set-PowerSettingValue -SettingName "StandbyTimeout" -PowerSource "DC" -Value 0
    Write-Host "    Standby (DC): Disabled"

    Set-PowerSettingValue -SettingName "HibernateTimeout" -PowerSource "AC" -Value 0
    Write-Host "    Hibernate (AC): Disabled"

    Set-PowerSettingValue -SettingName "HibernateTimeout" -PowerSource "DC" -Value 0
    Write-Host "    Hibernate (DC): Disabled"

    Write-Host "[+] Sleep and hibernate disabled"
} catch {
    Write-Host "[Alert] Failed to disable sleep: $($_.Exception.Message)"
    Write-Host "[*] Attempting to restore backup..."
    # Try to restore
    try {
        Set-PowerSettingValue -SettingName "StandbyTimeout" -PowerSource "AC" -Value $Backup.StandbyTimeoutAC
        Set-PowerSettingValue -SettingName "StandbyTimeout" -PowerSource "DC" -Value $Backup.StandbyTimeoutDC
        Set-PowerSettingValue -SettingName "HibernateTimeout" -PowerSource "AC" -Value $Backup.HibernateTimeoutAC
        Set-PowerSettingValue -SettingName "HibernateTimeout" -PowerSource "DC" -Value $Backup.HibernateTimeoutDC
        Write-Host "[+] Backup restored"
    } catch {
        Write-Host "[X] Failed to restore backup: $($_.Exception.Message)"
    }
    exit 1
}

# ============================================================
# STEP 4/5: SET EXPIRY TIME
# ============================================================
Write-Host ""
$StepNum = if ($AlreadyActive) { "4" } else { "5" }
Write-Host "[*] Step ${StepNum}: Setting expiry time..."

$ExpiryTime = (Get-Date).AddMinutes($TimeoutMinutes)
Set-ItemProperty -Path $RegistryBasePath -Name "ExpiryTime" -Value $ExpiryTime.ToString("o") -Type String
Set-ItemProperty -Path $RegistryBasePath -Name "TimeoutMinutes" -Value $TimeoutMinutes -Type DWord

Write-Host "    Expiry: $($ExpiryTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "[+] Expiry time set"

# ============================================================
# STEP 5/6: CREATE SCHEDULED TASK FOR REVERSION
# ============================================================
Write-Host ""
$StepNum = if ($AlreadyActive) { "5" } else { "6" }
Write-Host "[*] Step ${StepNum}: Creating scheduled task for automatic restoration..."

# Build the revert script path
$ScriptsFolder = Join-Path $MspScratchFolder "Scripts"
$RevertScriptPath = Join-Path $ScriptsFolder $RevertScriptName

# Create a simple inline revert script that will be run by the scheduled task
$RevertScriptContent = @"

# Auto-generated revert script for COOLForge NoSleep
# This script checks if the no-sleep period has expired and restores settings

`$RegistryPath = "$RegistryBasePath"
`$TaskName = "$ScheduledTaskName"

# Check if registry path exists
if (-not (Test-Path `$RegistryPath)) {
    # Nothing to do - clean up task
    Unregister-ScheduledTask -TaskName `$TaskName -Confirm:`$false -ErrorAction SilentlyContinue
    exit 0
}

# Get expiry time
`$ExpiryTimeStr = (Get-ItemProperty -Path `$RegistryPath -Name "ExpiryTime" -ErrorAction SilentlyContinue).ExpiryTime
if ([string]::IsNullOrEmpty(`$ExpiryTimeStr)) {
    exit 0
}

`$ExpiryTime = [DateTime]::Parse(`$ExpiryTimeStr)
`$Now = Get-Date

if (`$Now -lt `$ExpiryTime) {
    # Not expired yet
    exit 0
}

# Time to restore!
Write-Host "[*] No-sleep period expired - restoring power settings..."

try {
    `$Backup = Get-ItemProperty -Path `$RegistryPath -ErrorAction Stop

    # Get scheme GUID
    `$SchemeGuid = `$Backup.SchemeGuid

    # Restore standby timeouts
    & powercfg /SETACVALUEINDEX `$SchemeGuid 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da `$Backup.StandbyTimeoutAC
    & powercfg /SETDCVALUEINDEX `$SchemeGuid 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da `$Backup.StandbyTimeoutDC

    # Restore hibernate timeouts
    & powercfg /SETACVALUEINDEX `$SchemeGuid 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 `$Backup.HibernateTimeoutAC
    & powercfg /SETDCVALUEINDEX `$SchemeGuid 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 `$Backup.HibernateTimeoutDC

    # Apply changes
    & powercfg /setactive `$SchemeGuid

    Write-Host "[+] Power settings restored"

    # Clean up registry
    Remove-Item -Path `$RegistryPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Registry cleaned up"

    # Remove scheduled task
    Unregister-ScheduledTask -TaskName `$TaskName -Confirm:`$false -ErrorAction SilentlyContinue
    Write-Host "[+] Scheduled task removed"

} catch {
    Write-Host "[X] Error restoring settings: `$(`$_.Exception.Message)"
    exit 1
}

exit 0
"@

# Ensure scripts folder exists
if (-not (Test-Path $ScriptsFolder)) {
    New-Item -Path $ScriptsFolder -ItemType Directory -Force | Out-Null
}

# Write the revert script
$RevertScriptContent | Set-Content -Path $RevertScriptPath -Encoding UTF8 -Force
Write-Host "    Revert script: $RevertScriptPath"

# Create scheduled task to run every 5 minutes
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$RevertScriptPath`""
$TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# Remove existing task if present
Unregister-ScheduledTask -TaskName $ScheduledTaskName -Confirm:$false -ErrorAction SilentlyContinue

# Register the task
Register-ScheduledTask -TaskName $ScheduledTaskName -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Settings $TaskSettings -Description "Automatically restores power settings after COOLForge no-sleep period expires" | Out-Null

Write-Host "[+] Scheduled task created: $ScheduledTaskName"
Write-Host "    Runs every 5 minutes to check expiry"

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "============================================================"
Write-Host "[+] SUCCESS: Sleep prevention is now active"
Write-Host "============================================================"
Write-Host ""
Write-Host "DEVICE SHOULD NOT SLEEP BEFORE:"
Write-Host "    $($ExpiryTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host ""
Write-Host "Duration: $TimeoutMinutes minutes from now"
if ($AlreadyActive) {
    Write-Host "Mode: Extended existing session"
} else {
    Write-Host "Mode: New session started"
}
Write-Host ""
Write-Host "Settings will automatically restore after expiry."
Write-Host ""
Write-Host "To manually restore settings before timeout, run:"
Write-Host "    $RevertScriptPath"
Write-Host ""

exit 0
