<#
.SYNOPSIS
    Gets all custom field values for all devices, showing inheritance level.
.DESCRIPTION
    Uses the Level.io API to:
    1. Get all custom field definitions
    2. Get all devices
    3. For each device, retrieve all custom field values
    4. Prefix each value with inheritance level:
       (0) = Org level
       (1) = Top-level group
       (2) = Subgroup
       (3) = Device level
    5. Export to CSV
.NOTES
    Version: 2026.01.06.01
    Requires: Level.io API key with read access to devices and custom fields
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile
)

$ErrorActionPreference = 'Stop'

# ============================================================
# API FUNCTIONS
# ============================================================

$Script:LevelApiBase = "https://api.level.io/v2"

function Invoke-LevelApi {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Body = $null
    )

    $Headers = @{
        "Authorization" = $Script:ApiKey
        "Content-Type"  = "application/json"
    }

    $Uri = "$Script:LevelApiBase$Endpoint"

    try {
        $Params = @{
            Uri     = $Uri
            Method  = $Method
            Headers = $Headers
        }
        if ($Body) {
            $Params.Body = ($Body | ConvertTo-Json -Depth 10)
        }

        $Response = Invoke-RestMethod @Params
        return @{ Success = $true; Data = $Response }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Get-AllPaginated {
    param(
        [string]$Endpoint,
        [int]$Limit = 100
    )

    $AllItems = @()
    $Cursor = $null

    do {
        $Url = "$Endpoint"
        $Separator = if ($Url -match '\?') { '&' } else { '?' }
        $Url += "${Separator}limit=$Limit"
        if ($Cursor) {
            $Url += "&starting_after=$Cursor"
        }

        $Result = Invoke-LevelApi -Endpoint $Url
        if (-not $Result.Success) {
            Write-Host "[!] API Error: $($Result.Error)" -ForegroundColor Red
            break
        }

        $Items = if ($Result.Data.data) { $Result.Data.data } else { @($Result.Data) }
        if ($Items.Count -eq 0) { break }

        $AllItems += $Items
        $Cursor = $Items[-1].id

        if ($Items.Count -lt $Limit) { break }

    } while ($true)

    return $AllItems
}

# ============================================================
# MAIN
# ============================================================

Write-Host "=== Level.io Full Device Custom Fields Report ===" -ForegroundColor Cyan
Write-Host ""

# Get API key
$CachePath = Join-Path $PSScriptRoot ".levelio-apikey.cache"

if (-not $ApiKey) {
    if (Test-Path $CachePath) {
        try {
            $EncryptedKey = (Get-Content $CachePath -Raw).Trim()
            $SecureKey = $EncryptedKey | ConvertTo-SecureString
            $Script:ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
            )
            Write-Host "[+] Loaded API key from cache" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed to load cached key: $_" -ForegroundColor Yellow
            Remove-Item $CachePath -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $Script:ApiKey) {
        $Script:ApiKey = Read-Host "Enter Level.io API Key"
        try {
            $Script:ApiKey | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Set-Content $CachePath
            Write-Host "[+] API key cached for future use" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Could not cache API key: $_" -ForegroundColor Yellow
        }
    }
}
else {
    $Script:ApiKey = $ApiKey
}

# Get all custom field definitions
Write-Host "[*] Getting custom field definitions..." -ForegroundColor Gray
$Fields = Get-AllPaginated -Endpoint "/custom_fields"
Write-Host "[+] Found $($Fields.Count) custom field(s)" -ForegroundColor Green

# Build field name lookup
$FieldNameById = @{}
foreach ($Field in $Fields) {
    $FieldNameById[$Field.id] = $Field.name
}

# Get all groups and build hierarchy
Write-Host "[*] Getting groups..." -ForegroundColor Gray
$Groups = Get-AllPaginated -Endpoint "/groups"
Write-Host "[+] Found $($Groups.Count) group(s)" -ForegroundColor Green

# Build group lookup and determine depth
$GroupById = @{}
foreach ($Group in $Groups) {
    $GroupById[$Group.id] = $Group
}

# Function to get group depth (0 = org, 1 = top group, 2 = subgroup, etc.)
function Get-GroupDepth {
    param([string]$GroupId)

    if (-not $GroupId) { return 0 }

    $Depth = 1
    $CurrentGroup = $GroupById[$GroupId]

    while ($CurrentGroup -and $CurrentGroup.parent_id) {
        $Depth++
        $CurrentGroup = $GroupById[$CurrentGroup.parent_id]
    }

    return $Depth
}

# Get all devices
Write-Host "[*] Getting devices..." -ForegroundColor Gray
$Devices = Get-AllPaginated -Endpoint "/devices"
Write-Host "[+] Found $($Devices.Count) device(s)" -ForegroundColor Green

# Prepare results - dynamic columns based on custom fields
$AllResults = @()
$DeviceCount = 0
$TotalDevices = $Devices.Count

Write-Host "[*] Processing devices..." -ForegroundColor Gray

$SpinChars = @('|', '/', '-', '\')
$SpinIndex = 0

foreach ($Device in $Devices) {
    $DeviceCount++

    # Update spinner
    $Spinner = $SpinChars[$SpinIndex % 4]
    $SpinIndex++
    Write-Host "`r    [$Spinner] Processing $DeviceCount of $TotalDevices - $($Device.hostname.PadRight(20))" -NoNewline -ForegroundColor DarkGray

    # Get all custom field values for this device
    $DeviceValues = Get-AllPaginated -Endpoint "/custom_field_values?assigned_to_id=$($Device.id)"

    # Build a hashtable of field values with their inheritance level
    $FieldValues = @{}

    foreach ($Value in $DeviceValues) {
        $FieldName = $Value.custom_field_name
        if (-not $FieldName) {
            $FieldName = $FieldNameById[$Value.custom_field_id]
        }
        if (-not $FieldName) { continue }

        # Determine inheritance level
        $Level = 0  # Default to org level

        if ($Value.assigned_to_id) {
            if ($Value.assigned_to_id -eq $Device.id) {
                # Device level
                $Level = 3
            }
            elseif ($Value.assigned_to_id -eq $Device.group_id) {
                # Direct group - check if it's top-level or subgroup
                $GroupDepth = Get-GroupDepth -GroupId $Device.group_id
                if ($GroupDepth -eq 1) {
                    $Level = 1  # Top-level group
                }
                else {
                    $Level = 2  # Subgroup
                }
            }
            else {
                # Parent group - check depth
                $GroupDepth = Get-GroupDepth -GroupId $Value.assigned_to_id
                if ($GroupDepth -eq 1) {
                    $Level = 1
                }
                else {
                    $Level = 2
                }
            }
        }

        $FieldValues[$FieldName] = "($Level) $($Value.value)"
    }

    # Create result object with device info
    $Result = [ordered]@{
        DeviceName = $Device.hostname
        DeviceId   = $Device.id
        GroupName  = $Device.group_name
    }

    # Add all custom fields as columns
    foreach ($Field in $Fields | Sort-Object name) {
        if ($FieldValues.ContainsKey($Field.name)) {
            $Result[$Field.name] = $FieldValues[$Field.name]
        }
        else {
            $Result[$Field.name] = ""  # Empty if not set at any level
        }
    }

    $AllResults += [PSCustomObject]$Result
}

# Clear the spinner line
Write-Host "`r    [+] Processed $TotalDevices devices                              " -ForegroundColor Green

# Sort by device name
$Sorted = $AllResults | Sort-Object DeviceName

# Export to CSV (default to exports folder)
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot

if (-not $OutputFile) {
    $ExportsFolder = Join-Path $ProjectRoot "exports"
    if (-not (Test-Path $ExportsFolder)) {
        New-Item -ItemType Directory -Path $ExportsFolder -Force | Out-Null
    }
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
    $OutputPath = Join-Path $ExportsFolder "DeviceCustomFields_$Timestamp.csv"
}
elseif ([System.IO.Path]::IsPathRooted($OutputFile)) {
    $OutputPath = $OutputFile
}
else {
    $OutputPath = Join-Path $ScriptRoot $OutputFile
}

$Sorted | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "[+] Exported to: $OutputPath" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor White
Write-Host "  Devices: $($Sorted.Count)" -ForegroundColor White
Write-Host "  Custom Fields: $($Fields.Count)" -ForegroundColor White
Write-Host ""
Write-Host "Legend:" -ForegroundColor Yellow
Write-Host "  (0) = Org level" -ForegroundColor Gray
Write-Host "  (1) = Top-level group" -ForegroundColor Gray
Write-Host "  (2) = Subgroup" -ForegroundColor Gray
Write-Host "  (3) = Device level" -ForegroundColor Gray
