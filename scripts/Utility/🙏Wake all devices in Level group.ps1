<#
.SYNOPSIS
    Sends Wake-on-LAN (WOL) packets to all devices within a Level.io folder hierarchy.

.DESCRIPTION
    This script retrieves the current device's folder assignment from Level.io, traverses
    up the folder hierarchy by a configurable number of levels, then sends WOL magic packets
    to all devices in that folder and its subfolders.

    WOL packets are sent using multiple methods for maximum reliability:
    - UDP broadcast on port 9 (standard WOL port)
    - UDP broadcast on port 7 (echo port, fallback)
    - Directed subnet broadcasts from all local network interfaces
    - Global broadcast (255.255.255.255)

    Use cases:
    - Wake up all devices in a client site before maintenance
    - Remotely power on devices for updates or deployments
    - Prepare an entire folder hierarchy of devices for administrative tasks

.PARAMETER LevelsUp
    Number of folder levels to traverse upward from the current device's folder.
    - 0 = Current folder only
    - 1 = Parent folder (default)
    - 2 = Grandparent folder
    - etc.

.NOTES
    File Name      : Wake all devices in Level group.ps1
    Prerequisite   : Level.io API key with device read permissions
    API Version    : Level.io API v2
    Requires       : COOLForge-Common module

.EXAMPLE
    # Wake all devices in parent folder (default behavior)
    .\Wake all devices in parent to level.io folder.ps1

.EXAMPLE
    # Modify $LevelsUp variable to wake devices in grandparent folder
    $LevelsUp = 2
#>

#region Configuration
$ApiKey = "{{cf_apikey}}"
$LevelsUp = 1  # 0 = current folder, 1 = parent, 2 = grandparent, etc.

# WOL packets are now sent via multiple methods (ports 9 and 7, all subnet broadcasts)
# so fewer attempts per method are needed
$WolAttempts = 3       # Number of WOL packets to send per method
$WolDelayMs = 100      # Delay between WOL packet attempts (milliseconds)
#endregion Configuration

#region Module Import
# Import the COOLForge-Common module (assumes it's already available)
$ModulePath = "{{cf_coolforge_msp_scratch_folder}}\Libraries\COOLForge-Common.psm1"
if (Test-Path $ModulePath) {
    Import-Module $ModulePath -Force
} else {
    Write-Error "COOLForge-Common module not found at: $ModulePath"
    exit 1
}
#endregion Module Import

#region Helper Functions

<#
.SYNOPSIS
    Traverses up the folder hierarchy by a specified number of levels.

.PARAMETER GroupId
    The starting group ID.

.PARAMETER LevelsUp
    Number of levels to traverse upward.

.PARAMETER AllGroups
    Pre-fetched array of all groups for lookup.

.OUTPUTS
    [string] The group ID after traversing up the specified levels.
#>
function Get-AncestorGroupId {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [int]$LevelsUp,

        [Parameter(Mandatory = $true)]
        [array]$AllGroups
    )

    $CurrentGroupId = $GroupId
    $LevelsTraversed = 0

    while ($LevelsTraversed -lt $LevelsUp) {
        $Group = $AllGroups | Where-Object { $_.id -eq $CurrentGroupId }

        if (-not $Group -or -not $Group.parent_id) {
            Write-LevelLog "Reached top-level after $LevelsTraversed level(s)" -Level "WARN"
            return $CurrentGroupId
        }

        $CurrentGroupId = $Group.parent_id
        $LevelsTraversed++
    }

    return $CurrentGroupId
}

<#
.SYNOPSIS
    Recursively retrieves all descendant group IDs from a parent group.

.PARAMETER ParentGroupId
    The root group ID to start from.

.PARAMETER AllGroups
    Pre-fetched array of all groups for lookup.

.OUTPUTS
    [array] Collection of group IDs including the parent and all descendants.
#>
function Get-DescendantGroupIds {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ParentGroupId,

        [Parameter(Mandatory = $true)]
        [array]$AllGroups
    )

    $GroupIds = @($ParentGroupId)
    $DirectChildren = $AllGroups | Where-Object { $_.parent_id -eq $ParentGroupId }

    foreach ($Child in $DirectChildren) {
        $GroupIds += Get-DescendantGroupIds -ParentGroupId $Child.id -AllGroups $AllGroups
    }

    return $GroupIds
}

<#
.SYNOPSIS
    Extracts the first valid MAC address from a device's network interfaces.

.PARAMETER Device
    The device object containing network_interfaces.

.OUTPUTS
    [string] The MAC address if found, $null otherwise.
#>
function Get-DeviceMacAddress {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Device
    )

    if (-not $Device.network_interfaces) {
        return $null
    }

    $ValidInterface = $Device.network_interfaces |
        Where-Object { $_.mac_address -and $_.mac_address -ne "00:00:00:00:00:00" } |
        Select-Object -First 1

    return $ValidInterface.mac_address
}

#endregion Helper Functions

#region Main Execution

try {
    $LocalHostname = $env:COMPUTERNAME

    # Step 1: Fetch all groups
    Write-LevelLog "Fetching all groups from Level.io..."
    $AllGroups = Get-LevelGroups -ApiKey $ApiKey

    if (-not $AllGroups) {
        Write-LevelLog "Failed to fetch groups" -Level "ERROR"
        exit 1
    }

    Write-LevelLog "Found $($AllGroups.Count) groups"

    # Step 2: Find current device
    Write-LevelLog "Finding current device: $LocalHostname"
    $CurrentDevice = Find-LevelDevice -ApiKey $ApiKey -Hostname $LocalHostname

    if (-not $CurrentDevice) {
        Write-LevelLog "Device not found in Level.io: $LocalHostname" -Level "ERROR"
        exit 1
    }

    # Step 3: Validate group assignment
    $GroupId = $CurrentDevice.group_id
    if (-not $GroupId) {
        Write-LevelLog "Device is not assigned to any group" -Level "WARN"
        exit 0
    }

    $CurrentGroup = $AllGroups | Where-Object { $_.id -eq $GroupId }
    $CurrentGroupName = if ($CurrentGroup.name) { $CurrentGroup.name } else { $GroupId }
    Write-LevelLog "Current folder: $CurrentGroupName"

    # Step 4: Traverse to target folder
    Write-LevelLog "Traversing up $LevelsUp level(s)..."
    $TargetGroupId = Get-AncestorGroupId -GroupId $GroupId -LevelsUp $LevelsUp -AllGroups $AllGroups
    $TargetGroup = $AllGroups | Where-Object { $_.id -eq $TargetGroupId }
    $TargetGroupName = if ($TargetGroup.name) { $TargetGroup.name } else { $TargetGroupId }
    Write-LevelLog "Target folder: $TargetGroupName" -Level "SUCCESS"

    # Step 5: Get all descendant folders
    Write-LevelLog "Finding all subfolders..."
    $AllGroupIds = Get-DescendantGroupIds -ParentGroupId $TargetGroupId -AllGroups $AllGroups
    Write-LevelLog "Found $($AllGroupIds.Count) folder(s) total"

    # Step 6: Fetch all devices from all groups
    Write-LevelLog "Fetching devices from all folders..."
    $AllDevices = @()

    foreach ($GrpId in $AllGroupIds) {
        $Devices = Get-LevelDevices -ApiKey $ApiKey -GroupId $GrpId -IncludeNetworkInterfaces
        if ($Devices) {
            $AllDevices += $Devices
        }
    }

    Write-LevelLog "Found $($AllDevices.Count) device(s)" -Level "SUCCESS"

    # Step 7: Send WOL to each device
    Write-LevelLog "Sending Wake-on-LAN packets..."
    $WolSent = 0
    $WolSkipped = 0
    $WolFailed = 0

    foreach ($Device in $AllDevices) {
        $DeviceName = if ($Device.nickname) { $Device.nickname } else { $Device.hostname }
        $MacAddress = Get-DeviceMacAddress -Device $Device

        if (-not $MacAddress) {
            Write-LevelLog "[SKIP] $DeviceName - No valid MAC address" -Level "SKIP"
            $WolSkipped++
            continue
        }

        $Success = Send-LevelWakeOnLan -MacAddress $MacAddress -Attempts $WolAttempts -DelayMs $WolDelayMs

        if ($Success) {
            Write-LevelLog "[SENT] $DeviceName ($MacAddress)" -Level "SUCCESS"
            $WolSent++
        }
        else {
            Write-LevelLog "[FAIL] $DeviceName - Failed to send packet" -Level "ERROR"
            $WolFailed++
        }
    }

    # Summary
    Write-LevelLog "========================================"
    Write-LevelLog "Wake-on-LAN Summary"
    Write-LevelLog "========================================"
    Write-LevelLog "Packets Sent:  $WolSent" -Level "SUCCESS"
    Write-LevelLog "Skipped:       $WolSkipped" -Level "SKIP"
    Write-LevelLog "Failed:        $WolFailed" -Level $(if ($WolFailed -gt 0) { "ERROR" } else { "INFO" })
    Write-LevelLog "Total Devices: $($AllDevices.Count)"
    Write-LevelLog "========================================"
}
catch {
    Write-LevelLog "Script failed: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

#endregion Main Execution
