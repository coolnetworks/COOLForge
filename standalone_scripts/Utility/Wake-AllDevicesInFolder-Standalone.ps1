<#
.SYNOPSIS
    Standalone Wake-on-LAN script for Level.io devices.

.DESCRIPTION
    Sends Wake-on-LAN (WOL) packets to all devices within a Level.io folder hierarchy.
    This is a STANDALONE script that does not require the COOLForge library.

    BEFORE USE:
    1. Set a Level.io custom field called "apikey" (cf_apikey) containing your API key
    2. Optionally adjust LevelsUp (0 = current folder, 1 = parent, 2 = grandparent)
    3. Run on any device in the target folder hierarchy

.PARAMETER LevelsUp
    Number of folder levels to traverse upward from the current device's folder.
    - 0 = Current folder only
    - 1 = Parent folder (default)
    - 2 = Grandparent folder

.NOTES
    Prerequisite: Level.io API key with device read permissions
    API Version:  Level.io API v2

.EXAMPLE
    .\Wake-AllDevicesInFolder-Standalone.ps1
#>

#region Configuration
# ============================================================
# CONFIGURATION
# ============================================================
# API Key: Set a Level.io custom field called "apikey" (cf_apikey) on your devices
# The script will automatically use it via Level.io variable substitution
$ApiKey = "{{cf_apikey}}"

$LevelsUp = 1          # 0 = current folder, 1 = parent, 2 = grandparent
$WolAttempts = 10      # Number of WOL packets to send per device
$WolDelayMs = 500      # Delay between WOL packet attempts (milliseconds)
$BaseUrl = "https://api.level.io/v2"
#endregion Configuration

#region Embedded Functions
# ============================================================
# LOGGING FUNCTION
# ============================================================
function Write-LevelLog {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "SKIP", "DEBUG")]
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Prefix = switch ($Level) {
        "INFO"    { "[*]" }
        "WARN"    { "[!]" }
        "ERROR"   { "[X]" }
        "SUCCESS" { "[+]" }
        "SKIP"    { "[-]" }
        "DEBUG"   { "[D]" }
    }
    Write-Host "$Timestamp $Prefix $Message"
}

# ============================================================
# API HELPER FUNCTION
# ============================================================
function Invoke-LevelApiCall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        [Parameter(Mandatory = $false)]
        [ValidateSet("GET", "POST", "PUT", "DELETE", "PATCH")]
        [string]$Method = "GET",
        [Parameter(Mandatory = $false)]
        [hashtable]$Body,
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 30
    )

    $Headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }

    $Params = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        TimeoutSec      = $TimeoutSec
        UseBasicParsing = $true
    }

    if ($Body -and $Method -ne "GET") {
        $Params.Body = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $Response = Invoke-RestMethod @Params
        return @{ Success = $true; Data = $Response }
    }
    catch {
        Write-LevelLog "API call failed: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================
# LEVEL.IO API FUNCTIONS
# ============================================================
function Get-LevelGroups {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $AllGroups = @()
    $StartingAfter = $null

    do {
        $Uri = "$BaseUrl/groups?limit=100"
        if ($StartingAfter) {
            $Uri += "&starting_after=$StartingAfter"
        }

        $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "GET"

        if (-not $Result.Success) {
            Write-LevelLog "Failed to fetch groups: $($Result.Error)" -Level "ERROR"
            return $null
        }

        $AllGroups += $Result.Data.data

        $StartingAfter = if ($Result.Data.has_more -and $Result.Data.data.Count -gt 0) {
            $Result.Data.data[-1].id
        } else {
            $null
        }
    } while ($StartingAfter)

    return $AllGroups
}

function Get-LevelDevices {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        [Parameter(Mandatory = $false)]
        [string]$GroupId,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeNetworkInterfaces,
        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $AllDevices = @()
    $StartingAfter = $null

    do {
        $Uri = "$BaseUrl/devices?limit=100"

        if ($GroupId) {
            $Uri += "&group_id=$GroupId"
        }

        if ($IncludeNetworkInterfaces) {
            $Uri += "&include_network_interfaces=true"
        }

        if ($StartingAfter) {
            $Uri += "&starting_after=$StartingAfter"
        }

        $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "GET"

        if (-not $Result.Success) {
            Write-LevelLog "Failed to fetch devices: $($Result.Error)" -Level "ERROR"
            return $null
        }

        $AllDevices += $Result.Data.data

        $StartingAfter = if ($Result.Data.has_more -and $Result.Data.data.Count -gt 0) {
            $Result.Data.data[-1].id
        } else {
            $null
        }
    } while ($StartingAfter)

    return $AllDevices
}

function Find-LevelDevice {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        [Parameter(Mandatory = $true)]
        [string]$Hostname,
        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api.level.io/v2"
    )

    $StartingAfter = $null

    do {
        $Uri = "$BaseUrl/devices?limit=100"
        if ($StartingAfter) {
            $Uri += "&starting_after=$StartingAfter"
        }

        $Result = Invoke-LevelApiCall -Uri $Uri -ApiKey $ApiKey -Method "GET"

        if (-not $Result.Success) {
            Write-LevelLog "Failed to search for device: $($Result.Error)" -Level "ERROR"
            return $null
        }

        $Device = $Result.Data.data | Where-Object { $_.hostname -eq $Hostname } | Select-Object -First 1

        if ($Device) {
            return $Device
        }

        $StartingAfter = if ($Result.Data.has_more -and $Result.Data.data.Count -gt 0) {
            $Result.Data.data[-1].id
        } else {
            $null
        }
    } while ($StartingAfter)

    return $null
}

# ============================================================
# WAKE-ON-LAN FUNCTION
# ============================================================
function Send-LevelWakeOnLan {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MacAddress,
        [Parameter(Mandatory = $false)]
        [int]$Attempts = 10,
        [Parameter(Mandatory = $false)]
        [int]$DelayMs = 500
    )

    $CleanMac = $MacAddress -replace '[:-]', ''

    if ($CleanMac.Length -ne 12) {
        Write-LevelLog "Invalid MAC address: $MacAddress" -Level "WARN"
        return $false
    }

    try {
        $MacBytes = [byte[]]::new(6)
        for ($i = 0; $i -lt 6; $i++) {
            $MacBytes[$i] = [Convert]::ToByte($CleanMac.Substring($i * 2, 2), 16)
        }

        $MagicPacket = [byte[]]::new(102)

        for ($i = 0; $i -lt 6; $i++) {
            $MagicPacket[$i] = 0xFF
        }

        for ($i = 0; $i -lt 16; $i++) {
            [Array]::Copy($MacBytes, 0, $MagicPacket, 6 + ($i * 6), 6)
        }

        $UdpClient = New-Object System.Net.Sockets.UdpClient
        $UdpClient.Connect([System.Net.IPAddress]::Broadcast, 9)

        for ($i = 1; $i -le $Attempts; $i++) {
            $UdpClient.Send($MagicPacket, $MagicPacket.Length) | Out-Null
            if ($i -lt $Attempts) {
                Start-Sleep -Milliseconds $DelayMs
            }
        }

        $UdpClient.Close()
        return $true
    }
    catch {
        Write-LevelLog "Failed to send WOL packet: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

#endregion Embedded Functions

#region Helper Functions
function Get-AncestorGroupId {
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

function Get-DescendantGroupIds {
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

function Get-DeviceMacAddress {
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
Write-Host ""
Write-Host "============================================================"
Write-Host "  Wake-on-LAN - Level.io Folder Devices (Standalone)"
Write-Host "============================================================"
Write-Host ""

# Validate API key
if ([string]::IsNullOrWhiteSpace($ApiKey) -or $ApiKey -eq "{{cf_apikey}}") {
    Write-LevelLog "ERROR: API key not configured" -Level "ERROR"
    Write-Host ""
    Write-Host "Set a Level.io custom field called 'apikey' (cf_apikey) on your devices."
    Write-Host "The script will automatically use it via Level.io variable substitution."
    Write-Host ""
    exit 1
}

try {
    $LocalHostname = $env:COMPUTERNAME

    # Step 1: Fetch all groups
    Write-LevelLog "Fetching all groups from Level.io..."
    $AllGroups = Get-LevelGroups -ApiKey $ApiKey -BaseUrl $BaseUrl

    if (-not $AllGroups) {
        Write-LevelLog "Failed to fetch groups" -Level "ERROR"
        exit 1
    }

    Write-LevelLog "Found $($AllGroups.Count) groups"

    # Step 2: Find current device
    Write-LevelLog "Finding current device: $LocalHostname"
    $CurrentDevice = Find-LevelDevice -ApiKey $ApiKey -Hostname $LocalHostname -BaseUrl $BaseUrl

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
        $Devices = Get-LevelDevices -ApiKey $ApiKey -GroupId $GrpId -IncludeNetworkInterfaces -BaseUrl $BaseUrl
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
    Write-Host ""
    Write-LevelLog "========================================"
    Write-LevelLog "Wake-on-LAN Summary"
    Write-LevelLog "========================================"
    Write-LevelLog "Packets Sent:  $WolSent" -Level "SUCCESS"
    Write-LevelLog "Skipped:       $WolSkipped" -Level "SKIP"
    Write-LevelLog "Failed:        $WolFailed" -Level $(if ($WolFailed -gt 0) { "ERROR" } else { "INFO" })
    Write-LevelLog "Total Devices: $($AllDevices.Count)"
    Write-LevelLog "========================================"
    Write-Host ""
}
catch {
    Write-LevelLog "Script failed: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
#endregion Main Execution
