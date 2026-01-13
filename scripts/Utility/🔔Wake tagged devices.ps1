<#
.SYNOPSIS
    Policy monitor that wakes peer devices tagged with a wake request.

.DESCRIPTION
    This script runs as a policy monitor on managed devices (every 2 minutes). It:
    1. Finds the current device's parent folder group in Level.io
    2. Checks for peer devices with the wake tag (U+1F514 WAKEME)
    3. Sends WOL magic packets from the local network
    4. Tracks wake attempts in a state file
    5. Creates an alert if devices don't come online after wait period
    6. Removes the wake tag when device comes online

    TAG MODEL:
    - U+1F514 WAKEME = Request wake (transient - removed when device comes online)

    State is persisted to the MSP scratch folder so the script can track
    progress across multiple runs without blocking.

.NOTES
    Version:          2026.01.13.04
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags
    - $LevelApiKey        : API key for tag management

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Wake Tagged Devices Monitor
# Version: 2026.01.13.04
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# CONFIGURATION
# ============================================================
$ScriptName = "WakeTaggedDevices"
$WakeTagSuffix = "WAKEME"

# WOL configuration
$WolAttempts = 3       # Number of WOL packets to send per method
$WolDelayMs = 100      # Delay between WOL packet attempts (milliseconds)

# Wake verification
$WaitMinutes = 5       # Minutes to wait before alerting if device still offline
$AlertOnFailure = $true # Create alert if device doesn't come online

# Folder scope
$LevelsUp = 1          # 0 = current folder only, 1 = parent folder (recommended)

# State folder (set after initialization)
$StateFolder = $null

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName $ScriptName `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

# Set state folder now that we have MspScratchFolder
$StateFolder = Join-Path $MspScratchFolder "WakeState"

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Get-DeviceMacAddress {
    param([object]$Device)

    if (-not $Device.network_interfaces) {
        return $null
    }

    $ValidInterface = $Device.network_interfaces |
        Where-Object { $_.mac_address -and $_.mac_address -ne "00:00:00:00:00:00" } |
        Select-Object -First 1

    return $ValidInterface.mac_address
}

function Test-HasWakeTag {
    param([object]$Device)

    if (-not $Device.tags) {
        return $false
    }

    $Emojis = Get-EmojiLiterals
    $BellEmoji = $Emojis.Alert

    foreach ($Tag in $Device.tags) {
        $TagName = $Tag.name
        if ($TagName -like "*$WakeTagSuffix*") {
            if ($TagName.StartsWith($BellEmoji) -or
                $TagName.StartsWith($Emojis.CorruptedAlert)) {
                return $true
            }
        }
    }
    return $false
}

function Get-WakeTagId {
    param([object]$Device)

    if (-not $Device.tags) {
        return $null
    }

    $Emojis = Get-EmojiLiterals
    $BellEmoji = $Emojis.Alert

    foreach ($Tag in $Device.tags) {
        $TagName = $Tag.name
        if ($TagName -like "*$WakeTagSuffix*") {
            if ($TagName.StartsWith($BellEmoji) -or
                $TagName.StartsWith($Emojis.CorruptedAlert)) {
                return $Tag.id
            }
        }
    }
    return $null
}

function Get-AncestorGroupId {
    param(
        [string]$GroupId,
        [int]$LevelsUp,
        [array]$AllGroups
    )

    $CurrentGroupId = $GroupId
    $LevelsTraversed = 0

    while ($LevelsTraversed -lt $LevelsUp) {
        $Group = $AllGroups | Where-Object { $_.id -eq $CurrentGroupId }

        if (-not $Group -or -not $Group.parent_id) {
            return $CurrentGroupId
        }

        $CurrentGroupId = $Group.parent_id
        $LevelsTraversed++
    }

    return $CurrentGroupId
}

function Get-DescendantGroupIds {
    param(
        [string]$ParentGroupId,
        [array]$AllGroups
    )

    $GroupIds = @($ParentGroupId)
    $DirectChildren = $AllGroups | Where-Object { $_.parent_id -eq $ParentGroupId }

    foreach ($Child in $DirectChildren) {
        $GroupIds += Get-DescendantGroupIds -ParentGroupId $Child.id -AllGroups $AllGroups
    }

    return $GroupIds
}

function Get-WakeState {
    param([string]$DeviceId)

    $StateFile = Join-Path $StateFolder "$DeviceId.json"
    if (Test-Path $StateFile) {
        try {
            return Get-Content $StateFile -Raw | ConvertFrom-Json
        }
        catch {
            return $null
        }
    }
    return $null
}

function Set-WakeState {
    param(
        [string]$DeviceId,
        [string]$DeviceName,
        [string]$MacAddress,
        [datetime]$WolSentAt,
        [bool]$AlertSent = $false
    )

    if (-not (Test-Path $StateFolder)) {
        New-Item -Path $StateFolder -ItemType Directory -Force | Out-Null
    }

    $State = @{
        DeviceId   = $DeviceId
        DeviceName = $DeviceName
        MacAddress = $MacAddress
        WolSentAt  = $WolSentAt.ToString("o")
        AlertSent  = $AlertSent
    }

    $StateFile = Join-Path $StateFolder "$DeviceId.json"
    $State | ConvertTo-Json | Set-Content $StateFile -Force
}

function Remove-WakeState {
    param([string]$DeviceId)

    $StateFile = Join-Path $StateFolder "$DeviceId.json"
    if (Test-Path $StateFile) {
        Remove-Item $StateFile -Force
    }
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.13.04"
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Wake Tagged Devices Monitor (v$ScriptVersion)"

    $LocalHostname = $env:COMPUTERNAME

    # Ensure state folder exists
    if (-not (Test-Path $StateFolder)) {
        New-Item -Path $StateFolder -ItemType Directory -Force | Out-Null
    }

    # ============================================================
    # AUTO-BOOTSTRAP: Create wake tag if needed
    # ============================================================
    if ($LevelApiKey) {
        $Emojis = Get-EmojiLiterals
        $WakeTagName = "$($Emojis.Alert)$WakeTagSuffix"

        # Check if wake tag exists
        $ExistingTag = Find-LevelTag -ApiKey $LevelApiKey -TagName $WakeTagName
        if (-not $ExistingTag) {
            Write-LevelLog "Creating wake tag: $WakeTagName" -Level "INFO"
            $NewTag = New-LevelTag -ApiKey $LevelApiKey -TagName $WakeTagName -Color "orange"
            if ($NewTag) {
                Write-LevelLog "Wake tag created" -Level "SUCCESS"
            }
        }
    }

    # ============================================================
    # FIND CURRENT DEVICE
    # ============================================================
    Write-LevelLog "Finding current device..."
    $CurrentDevice = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $LocalHostname

    if (-not $CurrentDevice) {
        Write-LevelLog "Device not found in Level.io: $LocalHostname" -Level "ERROR"
        $script:ExitCode = 1
        return 1
    }

    # ============================================================
    # GET FOLDER HIERARCHY
    # ============================================================
    $GroupId = $CurrentDevice.group_id
    if (-not $GroupId) {
        Write-LevelLog "Device is not assigned to any folder" -Level "WARN"
        return 0
    }

    $AllGroups = Get-LevelGroups -ApiKey $LevelApiKey
    $CurrentGroup = $AllGroups | Where-Object { $_.id -eq $GroupId }
    $CurrentGroupName = if ($CurrentGroup.name) { $CurrentGroup.name } else { $GroupId }
    Write-LevelLog "Current folder: $CurrentGroupName"

    # Traverse up to target folder
    $TargetGroupId = Get-AncestorGroupId -GroupId $GroupId -LevelsUp $LevelsUp -AllGroups $AllGroups
    $TargetGroup = $AllGroups | Where-Object { $_.id -eq $TargetGroupId }
    $TargetGroupName = if ($TargetGroup.name) { $TargetGroup.name } else { $TargetGroupId }

    if ($LevelsUp -gt 0 -and $TargetGroupId -ne $GroupId) {
        Write-LevelLog "Target folder: $TargetGroupName (parent)"
    }

    # Get all descendant folders
    $AllGroupIds = Get-DescendantGroupIds -ParentGroupId $TargetGroupId -AllGroups $AllGroups
    Write-LevelLog "Scanning $($AllGroupIds.Count) folder(s)"

    # ============================================================
    # FETCH ALL PEER DEVICES
    # ============================================================
    Write-LevelLog "Fetching peer devices..."
    $PeerDevices = @()
    foreach ($GrpId in $AllGroupIds) {
        $Devices = Get-LevelDevices -ApiKey $LevelApiKey -GroupId $GrpId -IncludeNetworkInterfaces -ErrorAction SilentlyContinue
        if ($Devices) {
            $PeerDevices += $Devices
        }
    }

    if (-not $PeerDevices -or $PeerDevices.Count -eq 0) {
        Write-LevelLog "No devices found in folder hierarchy" -Level "WARN"
        return 0
    }

    Write-LevelLog "Found $($PeerDevices.Count) device(s) in folder hierarchy"

    # ============================================================
    # PROCESS EXISTING WAKE STATES
    # ============================================================
    Write-LevelLog ""
    Write-LevelLog "[Checking pending wake requests]"

    $StateFiles = Get-ChildItem -Path $StateFolder -Filter "*.json" -ErrorAction SilentlyContinue
    $CameOnline = 0
    $StillWaiting = 0
    $NeedAlert = @()

    foreach ($StateFile in $StateFiles) {
        $State = Get-Content $StateFile.FullName -Raw | ConvertFrom-Json
        $WolSentAt = [datetime]::Parse($State.WolSentAt)
        $MinutesSince = ((Get-Date) - $WolSentAt).TotalMinutes

        # Find current device status
        $TargetDevice = $PeerDevices | Where-Object { $_.id -eq $State.DeviceId }

        if (-not $TargetDevice) {
            Write-LevelLog "  $($State.DeviceName): No longer in folder, removing state" -Level "SKIP"
            Remove-WakeState -DeviceId $State.DeviceId
            continue
        }

        # Check if device still has wake tag
        if (-not (Test-HasWakeTag -Device $TargetDevice)) {
            Write-LevelLog "  $($State.DeviceName): Tag removed, cleaning up state" -Level "SUCCESS"
            Remove-WakeState -DeviceId $State.DeviceId
            continue
        }

        if ($TargetDevice.online -eq $true) {
            Write-LevelLog "  $($State.DeviceName): ONLINE - removing tag" -Level "SUCCESS"
            Remove-WakeState -DeviceId $State.DeviceId
            $CameOnline++

            # Remove the wake tag since device is now online
            if ($LevelApiKey) {
                $TagId = Get-WakeTagId -Device $TargetDevice
                if ($TagId) {
                    Remove-LevelTagFromDevice -ApiKey $LevelApiKey -DeviceId $TargetDevice.id -TagId $TagId -ErrorAction SilentlyContinue
                    Write-LevelLog "    Tag removed from $($State.DeviceName)"
                }
            }
        }
        elseif ($MinutesSince -ge $WaitMinutes) {
            if (-not $State.AlertSent) {
                Write-LevelLog "  $($State.DeviceName): Still offline after $([math]::Round($MinutesSince, 1)) min - needs alert" -Level "WARN"
                $NeedAlert += $State
            }
            else {
                Write-LevelLog "  $($State.DeviceName): Still offline (alert already sent)" -Level "SKIP"
            }
        }
        else {
            $Remaining = [math]::Round($WaitMinutes - $MinutesSince, 1)
            Write-LevelLog "  $($State.DeviceName): Waiting ($Remaining min remaining)" -Level "INFO"
            $StillWaiting++
        }
    }

    # ============================================================
    # CREATE ALERTS FOR FAILED WAKES
    # ============================================================
    if ($NeedAlert.Count -gt 0 -and $AlertOnFailure) {
        Write-LevelLog ""
        Write-LevelLog "[Creating alert for failed wake]" -Level "WARN"

        $OfflineNames = ($NeedAlert | ForEach-Object { $_.DeviceName }) -join ", "
        $AlertMessage = "Wake-on-LAN failed for: $OfflineNames. These devices need to be manually powered on."

        $AlertResult = New-LevelAlert -ApiKey $LevelApiKey -DeviceHostname $LocalHostname -Title "WOL Failed - Manual Power-On Required" -Message $AlertMessage

        if ($AlertResult.Success) {
            Write-LevelLog "Alert created: $($AlertResult.AlertId)" -Level "SUCCESS"

            # Mark alerts as sent
            foreach ($State in $NeedAlert) {
                Set-WakeState -DeviceId $State.DeviceId -DeviceName $State.DeviceName -MacAddress $State.MacAddress -WolSentAt ([datetime]::Parse($State.WolSentAt)) -AlertSent $true
            }
        }
        else {
            Write-LevelLog "Failed to create alert: $($AlertResult.Error)" -Level "ERROR"
        }
    }

    # ============================================================
    # FIND NEW WAKE REQUESTS
    # ============================================================
    Write-LevelLog ""
    Write-LevelLog "[Checking for new wake requests]"

    $NewWakeRequests = 0
    $WolSent = 0

    foreach ($Device in $PeerDevices) {
        # Skip self
        if ($Device.hostname -eq $LocalHostname) { continue }

        # Check for wake tag
        if (-not (Test-HasWakeTag -Device $Device)) { continue }

        # Skip if already online
        if ($Device.online -eq $true) {
            $DeviceName = if ($Device.nickname) { $Device.nickname } else { $Device.hostname }
            Write-LevelLog "  ${DeviceName}: Already online - removing tag" -Level "SUCCESS"

            # Remove the wake tag
            if ($LevelApiKey) {
                $TagId = Get-WakeTagId -Device $Device
                if ($TagId) {
                    Remove-LevelTagFromDevice -ApiKey $LevelApiKey -DeviceId $Device.id -TagId $TagId -ErrorAction SilentlyContinue
                }
            }
            continue
        }

        # Skip if already tracking
        $ExistingState = Get-WakeState -DeviceId $Device.id
        if ($ExistingState) { continue }

        # New wake request found
        $NewWakeRequests++
        $DeviceName = if ($Device.nickname) { $Device.nickname } else { $Device.hostname }
        $MacAddress = Get-DeviceMacAddress -Device $Device

        if (-not $MacAddress) {
            Write-LevelLog "  ${DeviceName}: No valid MAC address" -Level "SKIP"
            continue
        }

        # Send WOL packets
        $Success = Send-LevelWakeOnLan -MacAddress $MacAddress -Attempts $WolAttempts -DelayMs $WolDelayMs

        if ($Success) {
            Write-LevelLog "  ${DeviceName}: WOL sent ($MacAddress)" -Level "SUCCESS"
            $WolSent++

            # Save state for tracking
            Set-WakeState -DeviceId $Device.id -DeviceName $DeviceName -MacAddress $MacAddress -WolSentAt (Get-Date)
        }
        else {
            Write-LevelLog "  ${DeviceName}: Failed to send WOL" -Level "ERROR"
        }
    }

    if ($NewWakeRequests -eq 0) {
        Write-LevelLog "  No new wake requests" -Level "SKIP"
    }

    # ============================================================
    # SUMMARY
    # ============================================================
    Write-LevelLog ""
    Write-LevelLog "========================================"
    Write-LevelLog "Summary"
    Write-LevelLog "========================================"
    Write-LevelLog "New WOL Sent:   $WolSent"
    Write-LevelLog "Came Online:    $CameOnline"
    Write-LevelLog "Still Waiting:  $StillWaiting"
    Write-LevelLog "Alerts Created: $($NeedAlert.Count)"
    Write-LevelLog "========================================"

    return 0
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams

exit $ExitCode
