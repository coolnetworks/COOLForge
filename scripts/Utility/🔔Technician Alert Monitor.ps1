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
    Version: 2026.01.08.02

    Level.io Tags Required:
    - U+1F9D1 U+200D U+1F4BB technician : Tag workstation as technician (e.g., "technician" or "technicianJohn")

    Level.io Custom Fields Required:
    - cf_coolforge_technician_alerts : Text - JSON array of pending alerts
    - cf_apikey                      : Level.io API key

    Level.io Variables Used:
    - level_device_hostname          : Device hostname
    - level_tag_names                : Device tags (to detect technician tag)

.EXAMPLE
    # Deploy via Level.io automation to run every 30 seconds
    # Use tag filter to only run on devices with technician tag
#>

# ============================================================
# LEVEL.IO VARIABLES
# ============================================================
$LevelApiKey = "{{cf_apikey}}"
$DeviceHostname = "{{level_device_hostname}}"
$DeviceTags = "{{level_tag_names}}"
$MspScratchFolder = "{{cf_coolforge_msp_scratch_folder}}"

# ============================================================
# CONFIGURATION
# ============================================================
$LevelApiBaseUrl = "https://api.level.io/v2"
$AlertCacheFile = "$MspScratchFolder\TechAlerts\seen_alerts.json"

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "INFO"    { "[*]" }
        "SUCCESS" { "[+]" }
        "WARN"    { "[!]" }
        "ERROR"   { "[X]" }
        "DEBUG"   { "[D]" }
    }

    Write-Host "$timestamp $prefix $Message"
}

function Test-LevelVariable {
    param([string]$Value, [string]$VariableName)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '^\{\{.*\}\}$') {
        return $false
    }
    return $true
}

function Get-EmojiMap {
    # Simplified emoji map for technician detection
    return @{
        "🧑‍💻" = "Technician"  # U+1F9D1 U+200D U+1F4BB - Technician workstation
    }
}

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

function Invoke-LevelApiCall {
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [ValidateSet("GET", "POST", "PATCH", "DELETE")]
        [string]$Method = "GET",

        [hashtable]$Body = $null
    )

    $uri = "$LevelApiBaseUrl$Endpoint"

    $headers = @{
        "Authorization" = $LevelApiKey
        "Content-Type" = "application/json"
        "Accept" = "application/json"
    }

    try {
        $params = @{
            Uri = $uri
            Method = $Method
            Headers = $headers
            UseBasicParsing = $true
        }

        if ($Body -and $Method -ne "GET") {
            $jsonBody = $Body | ConvertTo-Json -Depth 10
            $params.Body = $jsonBody
        }

        $response = Invoke-RestMethod @params

        return @{
            Success = $true
            Data = $response
            Error = $null
        }
    }
    catch {
        return @{
            Success = $false
            Data = $null
            Error = $_.Exception.Message
        }
    }
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
    $fieldsResult = Invoke-LevelApiCall -Endpoint "/custom_fields"
    if (-not $fieldsResult.Success) {
        Write-Log "Failed to get custom fields: $($fieldsResult.Error)" -Level "ERROR"
        return @()
    }

    $alertsField = $fieldsResult.Data.data | Where-Object { $_.name -eq "cf_coolforge_technician_alerts" } | Select-Object -First 1
    if (-not $alertsField) {
        Write-Log "cf_coolforge_technician_alerts custom field not found" -Level "DEBUG"
        return @()
    }

    # Get all groups
    $groupsResult = Invoke-LevelApiCall -Endpoint "/groups?limit=100"
    if (-not $groupsResult.Success) {
        Write-Log "Failed to get groups: $($groupsResult.Error)" -Level "ERROR"
        return @()
    }

    # Check each group for alerts
    foreach ($group in $groupsResult.Data.data) {
        $groupResult = Invoke-LevelApiCall -Endpoint "/groups/$($group.id)"
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

Write-Log "Technician Alert Monitor starting..."
Write-Log "Hostname: $DeviceHostname"

# Validate this is a technician workstation
if (-not (Test-TechnicianWorkstation -Tags $DeviceTags)) {
    Write-Log "This device is not tagged as a technician workstation" -Level "WARN"
    Write-Log "Add the technician tag (U+1F9D1 U+200D U+1F4BB) to enable alerts" -Level "INFO"
    exit 0
}

$TechnicianName = Get-TechnicianName -Tags $DeviceTags
if ($TechnicianName) {
    Write-Log "Technician: $TechnicianName" -Level "SUCCESS"
}
else {
    Write-Log "Technician: (all alerts)" -Level "INFO"
}

# Validate configuration
if (-not (Test-LevelVariable $LevelApiKey "cf_apikey")) {
    Write-Log "Level API key not configured" -Level "ERROR"
    exit 1
}

if (-not (Test-LevelVariable $MspScratchFolder "cf_coolforge_msp_scratch_folder")) {
    $MspScratchFolder = "C:\ProgramData\COOLForge"
    $AlertCacheFile = "$MspScratchFolder\TechAlerts\seen_alerts.json"
}

# Get previously seen alerts
$seenAlerts = Get-SeenAlerts
Write-Log "Loaded $($seenAlerts.Count) previously seen alert IDs" -Level "DEBUG"

# Check for new alerts across all groups
$pendingAlerts = Get-AllGroupAlerts -TechName $TechnicianName

$newAlerts = @()
foreach ($alert in $pendingAlerts) {
    if ($alert.id -notin $seenAlerts) {
        $newAlerts += $alert
    }
}

if ($newAlerts.Count -eq 0) {
    Write-Log "No new alerts" -Level "DEBUG"
    exit 0
}

Write-Log "Found $($newAlerts.Count) new alert(s)" -Level "SUCCESS"

# Display notifications for new alerts
foreach ($alert in $newAlerts) {
    Write-Log "Alert: $($alert.title) - $($alert.message)" -Level "INFO"

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

Write-Log "Alert monitor complete" -Level "SUCCESS"
exit 0
