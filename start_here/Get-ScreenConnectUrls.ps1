<#
.SYNOPSIS
    Gets all ScreenConnect URL custom field values for devices.
.DESCRIPTION
    Uses the Level.io API to:
    1. Find the screenconnect_url custom field
    2. Get all devices
    3. Retrieve the screenconnect_url value for each device
    4. Output sorted by device name
.NOTES
    Version: 2026.01.06.03
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

        # Check if we got less than limit (last page)
        if ($Items.Count -lt $Limit) { break }

    } while ($true)

    return $AllItems
}

# ============================================================
# MAIN
# ============================================================

Write-Host "=== Level.io ScreenConnect URL Report ===" -ForegroundColor Cyan
Write-Host ""

# Get API key
$CachePath = Join-Path $PSScriptRoot ".levelio-apikey.cache"

if (-not $ApiKey) {
    # Try to load from cache first
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
        # Cache the key (encrypted with DPAPI - only works for current user on this machine)
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

# Find screenconnect_device_url custom field
Write-Host "[*] Finding screenconnect_device_url custom field..." -ForegroundColor Gray
$Fields = Get-AllPaginated -Endpoint "/custom_fields"
$ScField = $Fields | Where-Object { $_.name -eq "screenconnect_device_url" } | Select-Object -First 1

if (-not $ScField) {
    Write-Host "[!] Could not find screenconnect_device_url custom field" -ForegroundColor Red
    Write-Host "    Available fields:" -ForegroundColor Yellow
    $Fields | ForEach-Object { Write-Host "      - $($_.name)" -ForegroundColor Gray }
    exit 1
}

Write-Host "[+] Found field: $($ScField.name) (ID: $($ScField.id))" -ForegroundColor Green

# Get all devices
Write-Host "[*] Getting devices..." -ForegroundColor Gray
$Devices = Get-AllPaginated -Endpoint "/devices"
Write-Host "[+] Found $($Devices.Count) device(s)" -ForegroundColor Green

# Collect all devices and get their screenconnect_url values
Write-Host "[*] Getting screenconnect_url for each device..." -ForegroundColor Gray
$AllDevices = @()
$DeviceCount = 0
$TotalDevices = $Devices.Count

foreach ($Device in $Devices) {
    $DeviceCount++
    if ($DeviceCount % 10 -eq 0 -or $DeviceCount -eq $TotalDevices) {
        Write-Host "    Processing device $DeviceCount / $TotalDevices..." -ForegroundColor DarkGray
    }

    # Get all custom field values for this device
    $DeviceValues = Get-AllPaginated -Endpoint "/custom_field_values?assigned_to_id=$($Device.id)"

    # Find the screenconnect_device_url value
    $ScUrlValue = $DeviceValues | Where-Object { $_.custom_field_name -eq "screenconnect_device_url" } | Select-Object -First 1

    $AllDevices += [PSCustomObject]@{
        DeviceName       = $Device.hostname
        DeviceId         = $Device.id
        ScreenConnectUrl = $ScUrlValue.value
    }
}

# Sort by device name
$Sorted = $AllDevices | Sort-Object DeviceName

# Output
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host " SCREENCONNECT URL REPORT" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

foreach ($Device in $Sorted) {
    $Url = if ($Device.ScreenConnectUrl) { $Device.ScreenConnectUrl } else { "(not set)" }
    $Color = if ($Device.ScreenConnectUrl) { "Green" } else { "DarkGray" }
    Write-Host "$($Device.DeviceName) : " -NoNewline -ForegroundColor White
    Write-Host $Url -ForegroundColor $Color
}

# Export to CSV (default to exports folder)
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot

if (-not $OutputFile) {
    $ExportsFolder = Join-Path $ProjectRoot "exports"
    if (-not (Test-Path $ExportsFolder)) {
        New-Item -ItemType Directory -Path $ExportsFolder -Force | Out-Null
    }
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
    $OutputFile = Join-Path $ExportsFolder "ScreenConnectUrls_$Timestamp.csv"
}

$Sorted | Select-Object DeviceName, ScreenConnectUrl | Export-Csv -Path $OutputFile -NoTypeInformation
Write-Host ""
Write-Host "[+] Exported to: $OutputFile" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
$WithUrl = ($Sorted | Where-Object { $_.ScreenConnectUrl }).Count
$WithoutUrl = ($Sorted | Where-Object { -not $_.ScreenConnectUrl }).Count
Write-Host "Summary: $WithUrl with URL, $WithoutUrl without URL" -ForegroundColor White

