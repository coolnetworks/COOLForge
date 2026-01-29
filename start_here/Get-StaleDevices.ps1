<#
.SYNOPSIS
    Lists devices that have been offline for more than a specified number of days.

.DESCRIPTION
    Queries the Level.io API to find devices that haven't been seen online
    for longer than the specified threshold. Useful for identifying:
    - Decommissioned machines still in Level
    - Devices that need attention
    - Cleanup candidates

.PARAMETER Days
    Number of days offline to consider a device stale. Default: 29

.PARAMETER GroupFilter
    Filter to specific group name pattern (supports wildcards).
    Example: -GroupFilter "*Production*"

.PARAMETER ExportCsv
    Export results to CSV file at the specified path.

.PARAMETER ShowReinstallCommands
    Show PowerShell reinstall commands for each stale device.
    Requires you to provide your Level install key.

.NOTES
    Version:          2026.01.13.01
    Target Platform:  Windows PowerShell 5.1+

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    .\Get-StaleDevices.ps1
    Lists all devices offline for more than 29 days.

.EXAMPLE
    .\Get-StaleDevices.ps1 -Days 14
    Lists all devices offline for more than 14 days.

.EXAMPLE
    .\Get-StaleDevices.ps1 -Days 30 -GroupFilter "*ACME*"
    Lists devices in ACME groups offline for more than 30 days.

.EXAMPLE
    .\Get-StaleDevices.ps1 -ExportCsv ".\stale-devices.csv"
    Exports stale device list to CSV.

.EXAMPLE
    .\Get-StaleDevices.ps1 -ShowReinstallCommands
    Shows reinstall commands with group assignment for each stale device.
#>

param(
    [Parameter(Mandatory = $false)]
    [int]$Days = 29,

    [Parameter(Mandatory = $false)]
    [string]$GroupFilter,

    [Parameter(Mandatory = $false)]
    [string]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [switch]$ShowReinstallCommands
)

$ErrorActionPreference = 'Stop'

# ============================================================
# PATHS AND SETUP
# ============================================================

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SavedConfigPath = Join-Path $ScriptRoot ".COOLForge_Lib-setup.json"
$CutoffDate = (Get-Date).AddDays(-$Days)

# ============================================================
# API FUNCTIONS
# ============================================================

$Script:LevelApiBase = "https://api.level.io/v2"
$Script:ApiKey = $null

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

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " COOLForge Stale Device Finder" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Threshold: $Days days (last seen before $($CutoffDate.ToString('yyyy-MM-dd')))" -ForegroundColor Gray
Write-Host ""

# ============================================================
# LOAD API KEY
# ============================================================

if (Test-Path $SavedConfigPath) {
    try {
        $SavedConfig = Get-Content $SavedConfigPath -Raw | ConvertFrom-Json

        $EncryptedKey = $SavedConfig.CoolForge_ApiKeyEncrypted
        if (-not $EncryptedKey) {
            $EncryptedKey = $SavedConfig.ApiKeyEncrypted
        }

        if ($EncryptedKey) {
            $SecureKey = $EncryptedKey | ConvertTo-SecureString
            $Script:ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
            )
            Write-Host "[+] Using saved API key" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] Could not load saved API key: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $Script:ApiKey) {
    Write-Host "Enter your Level.io API key: " -NoNewline -ForegroundColor Yellow
    $SecureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    $Script:ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

if ([string]::IsNullOrWhiteSpace($Script:ApiKey)) {
    Write-Host "[X] API key is required" -ForegroundColor Red
    exit 1
}

# ============================================================
# FETCH DATA
# ============================================================

Write-Host "[*] Fetching groups..." -ForegroundColor Gray
$AllGroups = Get-AllPaginated -Endpoint "/groups"
Write-Host "[+] Found $($AllGroups.Count) group(s)" -ForegroundColor Green

$GroupLookup = @{}
$GroupIdLookup = @{}
foreach ($Group in $AllGroups) {
    $GroupLookup[$Group.id] = $Group.name
    $GroupIdLookup[$Group.id] = $Group.id
}

Write-Host "[*] Fetching devices..." -ForegroundColor Gray
$AllDevices = Get-AllPaginated -Endpoint "/devices"
Write-Host "[+] Found $($AllDevices.Count) device(s)" -ForegroundColor Green

# ============================================================
# FILTER STALE DEVICES
# ============================================================

$StaleDevices = @()

foreach ($Device in $AllDevices) {
    # Skip online devices
    if ($Device.online -eq $true) { continue }

    # Parse last seen time (API returns UTC)
    # Try last_seen_at first, fall back to last_reboot_time
    $LastSeen = $null
    $LastSeenField = $Device.last_seen_at
    if (-not $LastSeenField) {
        $LastSeenField = $Device.last_reboot_time
    }

    if ($LastSeenField) {
        try {
            $LastSeen = [DateTime]::Parse($LastSeenField).ToLocalTime()
        }
        catch {
            $LastSeen = [DateTime]::MinValue
        }
    }
    else {
        # No timestamp means never seen or very old
        $LastSeen = [DateTime]::MinValue
    }

    # Check if older than cutoff
    if ($LastSeen -lt $CutoffDate) {
        $GroupName = $GroupLookup[$Device.group_id]

        # Apply group filter if specified
        if ($GroupFilter -and $GroupName -notlike $GroupFilter) {
            continue
        }

        $DaysOffline = [math]::Floor(((Get-Date) - $LastSeen).TotalDays)
        if ($LastSeen -eq [DateTime]::MinValue) {
            $DaysOffline = "Never seen"
            $LastSeenStr = "Never"
        }
        else {
            $LastSeenStr = $LastSeen.ToString("yyyy-MM-dd HH:mm")
        }

        $StaleDevices += [PSCustomObject]@{
            Hostname     = $Device.hostname
            GroupName    = $GroupName
            GroupId      = $Device.group_id
            LastSeen     = $LastSeenStr
            DaysOffline  = $DaysOffline
            LastUser     = $Device.last_logged_in_user
            Platform     = $Device.platform
            DeviceId     = $Device.id
        }
    }
}

# Sort by days offline (descending)
$StaleDevices = $StaleDevices | Sort-Object {
    if ($_.DaysOffline -eq "Never seen") { [int]::MaxValue }
    else { [int]$_.DaysOffline }
} -Descending

# ============================================================
# OUTPUT
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Results" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if ($StaleDevices.Count -eq 0) {
    Write-Host "[+] No devices found offline for more than $Days days." -ForegroundColor Green
}
else {
    Write-Host "[!] Found $($StaleDevices.Count) device(s) offline for more than $Days days:" -ForegroundColor Yellow
    Write-Host ""

    $StaleDevices | Format-Table -AutoSize -Property Hostname, GroupName, LastSeen, DaysOffline, LastUser, Platform

    if ($ExportCsv) {
        $StaleDevices | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host "[+] Exported to: $ExportCsv" -ForegroundColor Green
    }

    if ($ShowReinstallCommands) {
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host " Reinstall Commands" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "To reinstall the Level agent on these devices, use the commands below." -ForegroundColor Gray
        Write-Host "Replace YOUR_INSTALL_KEY with your Level install key from the Level UI." -ForegroundColor Gray
        Write-Host "(Devices > Select Group > Install New Agent > Copy API Key)" -ForegroundColor DarkGray
        Write-Host ""

        foreach ($Device in $StaleDevices) {
            Write-Host "# $($Device.Hostname) - $($Device.GroupName)" -ForegroundColor Yellow
            if ($Device.GroupId) {
                Write-Host "Invoke-Expression (Invoke-RestMethod 'https://downloads.level.io/install_windows.ps1') -LEVEL_API_KEY 'YOUR_INSTALL_KEY' -LEVEL_GROUP_ID '$($Device.GroupId)'" -ForegroundColor White
            }
            else {
                Write-Host "Invoke-Expression (Invoke-RestMethod 'https://downloads.level.io/install_windows.ps1') -LEVEL_API_KEY 'YOUR_INSTALL_KEY'" -ForegroundColor White
            }
            Write-Host ""
        }

        Write-Host "--------------------------------------------" -ForegroundColor DarkGray
        Write-Host "Or use the MSI installer with:" -ForegroundColor Gray
        Write-Host 'msiexec /quiet /i level.msi LEVEL_API_KEY="YOUR_INSTALL_KEY" LEVEL_GROUP_ID="GROUP_ID"' -ForegroundColor White
        Write-Host ""
    }
}

Write-Host ""
