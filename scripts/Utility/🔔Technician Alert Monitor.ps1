<#
.SYNOPSIS
    Monitors for technician alerts and displays Windows toast notifications.

.DESCRIPTION
    This script runs on technician workstations (tagged with U+1F9D1 U+200D U+1F4BB technician).
    It polls the Level.io API for alerts in cf_coolforge_technician_alerts and displays Windows
    toast notifications when new alerts arrive.

    Alert Flow:
    1. Client scripts detect issues requiring tech attention
    2. Client scripts call Send-TechnicianAlert (or write to cf_coolforge_technician_alerts directly)
    3. This script polls for new alerts and shows toast notifications
    4. Technician acknowledges or alerts auto-expire

.NOTES
    Version: 2026.01.14.01

    Level.io Tags Required:
    - U+1F9D1 U+200D U+1F4BB technician : Tag workstation as technician (e.g., "technician" or "technicianJohn")

    Level.io Custom Fields Required:
    - cf_coolforge_technician_alerts : Text - JSON array of pending alerts
    - cf_apikey                      : Level.io API key

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags
    - $LevelApiKey        : Level.io API key for API calls

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    # Deploy via Level.io automation to run every 30 seconds
    # Use tag filter to only run on devices with technician tag
#>

# Technician Alert Monitor
# Version: 2026.01.14.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# CONFIGURATION
# ============================================================
$AlertCacheFile = "$MspScratchFolder\TechAlerts\seen_alerts.json"

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Test-TechnicianWorkstation {
    param([string]$Tags)

    if ([string]::IsNullOrWhiteSpace($Tags) -or $Tags -match '^\{\{.*\}\}$') {
        return $false
    }

    $EmojiMap = Get-EmojiMap
    $TagArray = $Tags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    foreach ($Tag in $TagArray) {
        foreach ($Emoji in $EmojiMap.Keys) {
            if ($EmojiMap[$Emoji] -eq "Technician" -and $Tag.StartsWith($Emoji)) {
                return $true
            }
        }
    }
    return $false
}

function Get-TechnicianName {
    param([string]$Tags)

    if ([string]::IsNullOrWhiteSpace($Tags) -or $Tags -match '^\{\{.*\}\}$') {
        return ""
    }

    $EmojiMap = Get-EmojiMap
    $TagArray = $Tags -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    foreach ($Tag in $TagArray) {
        foreach ($Emoji in $EmojiMap.Keys) {
            if ($EmojiMap[$Emoji] -eq "Technician" -and $Tag.StartsWith($Emoji)) {
                $Name = $Tag.Substring($Emoji.Length).Trim()
                return $Name
            }
        }
    }
    return ""
}

function Get-SeenAlerts {
    if (Test-Path $AlertCacheFile) {
        try {
            $content = Get-Content $AlertCacheFile -Raw | ConvertFrom-Json
            return @($content)
        }
        catch {
            return @()
        }
    }
    return @()
}

function Save-SeenAlerts {
    param([array]$AlertIds)

    $folder = Split-Path $AlertCacheFile -Parent
    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    # Keep only last 100 alert IDs to prevent file bloat
    $toSave = $AlertIds | Select-Object -Last 100
    $toSave | ConvertTo-Json | Set-Content $AlertCacheFile -Force
}

function Show-ToastNotification {
    param(
        [string]$Title,
        [string]$Message,
        [string]$ClientName = "",
        [string]$DeviceName = "",
        [string]$Priority = "Normal"
    )

    # Build full message
    $fullMessage = $Message
    if ($DeviceName) {
        $fullMessage = "[$DeviceName] $Message"
    }

    # Use BurntToast module if available, otherwise fall back to basic notification
    if (Get-Module -ListAvailable -Name BurntToast) {
        Import-Module BurntToast -ErrorAction SilentlyContinue

        $textElements = @(
            (New-BTText -Text $Title)
            (New-BTText -Text $fullMessage)
        )

        if ($ClientName) {
            $textElements += (New-BTText -Text "Client: $ClientName")
        }

        New-BurntToastNotification -Text $textElements -AppLogo $null
    }
    else {
        # Fallback: Use Windows Forms notification
        Add-Type -AssemblyName System.Windows.Forms

        $balloon = New-Object System.Windows.Forms.NotifyIcon
        $balloon.Icon = [System.Drawing.SystemIcons]::Information
        $balloon.BalloonTipIcon = switch ($Priority) {
            "Critical" { [System.Windows.Forms.ToolTipIcon]::Error }
            "High"     { [System.Windows.Forms.ToolTipIcon]::Warning }
            default    { [System.Windows.Forms.ToolTipIcon]::Info }
        }
        $balloon.BalloonTipTitle = $Title
        $balloon.BalloonTipText = if ($ClientName) { "$fullMessage`nClient: $ClientName" } else { $fullMessage }
        $balloon.Visible = $true
        $balloon.ShowBalloonTip(10000)

        # Clean up after display
        Start-Sleep -Seconds 1
        $balloon.Dispose()
    }
}

function Get-AllGroupAlerts {
    param([string]$TechName)

    $allAlerts = @()

    # Get the alerts custom field definition
    $fieldsResult = Invoke-LevelApiCall -ApiKey $LevelApiKey -Endpoint "/custom_fields"
    if (-not $fieldsResult.Success) {
        Write-LevelLog "Failed to get custom fields: $($fieldsResult.Error)" -Level "ERROR"
        return @()
    }

    $alertsField = $fieldsResult.Data.data | Where-Object { $_.name -eq "cf_coolforge_technician_alerts" } | Select-Object -First 1
    if (-not $alertsField) {
        Write-LevelLog "cf_coolforge_technician_alerts custom field not found" -Level "DEBUG"
        return @()
    }

    # Get all groups
    $groupsResult = Invoke-LevelApiCall -ApiKey $LevelApiKey -Endpoint "/groups?limit=100"
    if (-not $groupsResult.Success) {
        Write-LevelLog "Failed to get groups: $($groupsResult.Error)" -Level "ERROR"
        return @()
    }

    # Check each group for alerts
    foreach ($group in $groupsResult.Data.data) {
        $groupResult = Invoke-LevelApiCall -ApiKey $LevelApiKey -Endpoint "/groups/$($group.id)"
        if (-not $groupResult.Success) {
            continue
        }

        if ($groupResult.Data.custom_field_values) {
            $alertsValue = $groupResult.Data.custom_field_values | Where-Object { $_.custom_field_id -eq $alertsField.id } | Select-Object -First 1
            if ($alertsValue -and $alertsValue.value) {
                try {
                    $groupAlerts = @($alertsValue.value | ConvertFrom-Json)
                    $now = Get-Date

                    foreach ($alert in $groupAlerts) {
                        # Skip expired alerts
                        try {
                            if ([datetime]$alert.expires -lt $now) {
                                continue
                            }
                        }
                        catch {
                            continue
                        }

                        # Skip acknowledged alerts
                        if ($alert.acknowledged) {
                            continue
                        }

                        # Check technician routing
                        if ($alert.technician -and $TechName -and $alert.technician -ne $TechName) {
                            continue
                        }

                        $allAlerts += $alert
                    }
                }
                catch {
                    # Invalid JSON, skip
                }
            }
        }
    }

    return $allAlerts
}

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-LevelLog "Technician Alert Monitor starting..."
Write-LevelLog "Hostname: $DeviceHostname"

# Validate this is a technician workstation
if (-not (Test-TechnicianWorkstation -Tags $DeviceTags)) {
    Write-LevelLog "This device is not tagged as a technician workstation" -Level "WARN"
    Write-LevelLog "Add the technician tag (U+1F9D1 U+200D U+1F4BB) to enable alerts" -Level "INFO"
    exit 0
}

$TechnicianName = Get-TechnicianName -Tags $DeviceTags
if ($TechnicianName) {
    Write-LevelLog "Technician: $TechnicianName" -Level "SUCCESS"
}
else {
    Write-LevelLog "Technician: (all alerts)" -Level "INFO"
}

# Validate configuration
if (-not $LevelApiKey) {
    Write-LevelLog "Level API key not configured" -Level "ERROR"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($MspScratchFolder) -or $MspScratchFolder -match '^\{\{.*\}\}$') {
    $MspScratchFolder = "C:\ProgramData\COOLForge"
    $AlertCacheFile = "$MspScratchFolder\TechAlerts\seen_alerts.json"
}

# Get previously seen alerts
$seenAlerts = Get-SeenAlerts
Write-LevelLog "Loaded $($seenAlerts.Count) previously seen alert IDs" -Level "DEBUG"

# Check for new alerts across all groups
$pendingAlerts = Get-AllGroupAlerts -TechName $TechnicianName

$newAlerts = @()
foreach ($alert in $pendingAlerts) {
    if ($alert.id -notin $seenAlerts) {
        $newAlerts += $alert
    }
}

if ($newAlerts.Count -eq 0) {
    Write-LevelLog "No new alerts" -Level "DEBUG"
    exit 0
}

Write-LevelLog "Found $($newAlerts.Count) new alert(s)" -Level "SUCCESS"

# Display notifications for new alerts
foreach ($alert in $newAlerts) {
    Write-LevelLog "Alert: $($alert.title) - $($alert.message)" -Level "INFO"

    Show-ToastNotification `
        -Title $alert.title `
        -Message $alert.message `
        -ClientName $alert.client `
        -DeviceName $alert.device `
        -Priority $alert.priority

    # Mark as seen
    $seenAlerts += $alert.id
}

# Save updated seen alerts
Save-SeenAlerts -AlertIds $seenAlerts

Write-LevelLog "Alert monitor complete" -Level "SUCCESS"
exit 0
