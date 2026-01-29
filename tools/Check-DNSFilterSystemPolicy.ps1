<#
.SYNOPSIS
    Checks that all DNSFilter users named "SYSTEM" are assigned to the correct policy.

.DESCRIPTION
    Uses the DNSFilter API to retrieve all users, filters for those named "SYSTEM",
    and verifies they are assigned to the "g-Internet Safety" global policy.

    This is an alert-only script - it reports non-compliance but does not
    automatically remediate policy assignments.

.PARAMETER ApiKey
    DNSFilter API key for authentication. Required.

.PARAMETER PolicyName
    The policy name that SYSTEM users should be assigned to.
    Default: "g-Internet Safety"

.PARAMETER UserName
    The username to check for policy compliance.
    Default: "SYSTEM"

.EXAMPLE
    .\Check-DNSFilterSystemPolicy.ps1 -ApiKey "your-api-key-here"

.EXAMPLE
    .\Check-DNSFilterSystemPolicy.ps1 -ApiKey $env:DNSFILTER_API_KEY -PolicyName "Custom Policy"

.NOTES
    Version:    2026.01.17.01
    Exit Codes: 0 = All users compliant | 1 = Non-compliant users found

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [string]$PolicyName = "g-Internet Safety",

    [Parameter(Mandatory = $false)]
    [string]$UserName = "SYSTEM"
)

$ErrorActionPreference = "Stop"

# Import COOLForge library from relative path
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LibraryPath = Join-Path $ScriptDir "..\modules\COOLForge-Common.psm1"
if (Test-Path $LibraryPath) {
    Import-Module $LibraryPath -Force
    Write-Host "[+] Loaded COOLForge-Common library" -ForegroundColor DarkGray
}

$DnsFilterApiBase = "https://api.dnsfilter.com/v1"

# ============================================================
# API HELPER FUNCTIONS
# ============================================================
function Invoke-DnsFilterApi {
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [string]$Method = "GET",

        [hashtable]$Body = $null
    )

    $Headers = @{
        "Authorization" = "Token $ApiKey"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }

    $Uri = "$DnsFilterApiBase/$Endpoint"

    $Params = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        UseBasicParsing = $true
        TimeoutSec      = 30
    }

    if ($Body -and $Method -ne "GET") {
        $Params.Body = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $Response = Invoke-RestMethod @Params
        return $Response
    }
    catch {
        $StatusCode = $null
        if ($_.Exception.Response) {
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }
        $ErrorMessage = $_.Exception.Message

        Write-Host "[X] API Error ($StatusCode): $ErrorMessage" -ForegroundColor Red
        Write-Host "    Endpoint: $Endpoint" -ForegroundColor DarkGray

        return $null
    }
}

function Get-AllPaginatedResults {
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint
    )

    $AllResults = @()
    $Page = 1
    $PageSize = 100
    $HasMore = $true

    while ($HasMore) {
        $Separator = if ($Endpoint -match '\?') { '&' } else { '?' }
        $PagedEndpoint = "$Endpoint${Separator}page=$Page&per_page=$PageSize"
        $Response = Invoke-DnsFilterApi -Endpoint $PagedEndpoint

        if ($null -eq $Response) {
            Write-Host "[!] Failed to retrieve page $Page" -ForegroundColor Yellow
            break
        }

        # Handle different response structures
        $Data = if ($Response.data) { $Response.data } else { $Response }

        if ($Data -is [array]) {
            $AllResults += $Data
            $HasMore = ($Data.Count -eq $PageSize)
        }
        else {
            $AllResults += $Data
            $HasMore = $false
        }

        $Page++

        # Safety limit
        if ($Page -gt 100) {
            Write-Host "[!] Reached pagination safety limit (100 pages)" -ForegroundColor Yellow
            break
        }
    }

    return $AllResults
}

# ============================================================
# MAIN SCRIPT
# ============================================================
Write-Host ""
Write-Host "DNSFilter SYSTEM Policy Compliance Check" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Target User:     $UserName"
Write-Host "Required Policy: $PolicyName"
Write-Host ""

# Step 1: Get all policies to find the required policy ID
Write-Host "[*] Retrieving policies from DNSFilter..."
$Policies = Get-AllPaginatedResults -Endpoint "policies"

if ($null -eq $Policies -or $Policies.Count -eq 0) {
    Write-Host "[Alert] Could not retrieve policies from DNSFilter API" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Found $($Policies.Count) policies" -ForegroundColor Green

# Find the required policy
$RequiredPolicy = $Policies | Where-Object { $_.name -eq $PolicyName }

if ($null -eq $RequiredPolicy) {
    Write-Host "[Alert] Required policy '$PolicyName' not found in DNSFilter" -ForegroundColor Red
    Write-Host ""
    Write-Host "Available policies:" -ForegroundColor Yellow
    $Policies | ForEach-Object { Write-Host "  - $($_.name)" }
    exit 1
}

$RequiredPolicyId = $RequiredPolicy.id
Write-Host "[+] Required policy found: $PolicyName (ID: $RequiredPolicyId)" -ForegroundColor Green

# Step 2: Get all users
Write-Host ""
Write-Host "[*] Retrieving users from DNSFilter..."
$Users = Get-AllPaginatedResults -Endpoint "users"

if ($null -eq $Users) {
    Write-Host "[Alert] Could not retrieve users from DNSFilter API" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Found $($Users.Count) total users" -ForegroundColor Green

# Step 3: Filter for target users
$TargetUsers = $Users | Where-Object { $_.name -eq $UserName -or $_.username -eq $UserName }

if ($TargetUsers.Count -eq 0) {
    Write-Host ""
    Write-Host "[+] COMPLIANT: No users named '$UserName' found" -ForegroundColor Green
    exit 0
}

Write-Host "[*] Found $($TargetUsers.Count) '$UserName' user(s)"

# Step 4: Check policy compliance for each target user
Write-Host ""
Write-Host "Checking policy assignments..." -ForegroundColor Cyan
Write-Host "============================================================"

$CompliantUsers = @()
$NonCompliantUsers = @()

foreach ($User in $TargetUsers) {
    $DisplayName = if ($User.name) { $User.name } else { $User.username }
    $UserId = $User.id
    $UserPolicyId = $User.policy_id
    $UserPolicyName = $null

    # Get policy name if we have a policy ID
    if ($UserPolicyId) {
        $UserPolicy = $Policies | Where-Object { $_.id -eq $UserPolicyId }
        $UserPolicyName = if ($UserPolicy) { $UserPolicy.name } else { "Unknown (ID: $UserPolicyId)" }
    }
    else {
        $UserPolicyName = "(No policy assigned)"
    }

    $IsCompliant = ($UserPolicyId -eq $RequiredPolicyId)

    if ($IsCompliant) {
        Write-Host "[+] $DisplayName (ID: $UserId): $UserPolicyName" -ForegroundColor Green
        $CompliantUsers += [PSCustomObject]@{
            Name     = $DisplayName
            Id       = $UserId
            Policy   = $UserPolicyName
            PolicyId = $UserPolicyId
        }
    }
    else {
        Write-Host "[!] $DisplayName (ID: $UserId): $UserPolicyName" -ForegroundColor Yellow
        Write-Host "    Expected: $PolicyName" -ForegroundColor DarkGray
        $NonCompliantUsers += [PSCustomObject]@{
            Name             = $DisplayName
            Id               = $UserId
            CurrentPolicy    = $UserPolicyName
            CurrentPolicyId  = $UserPolicyId
            ExpectedPolicy   = $PolicyName
            ExpectedPolicyId = $RequiredPolicyId
        }
    }
}

Write-Host "============================================================"
Write-Host ""

# Step 5: Report results
$TotalTargetUsers = $TargetUsers.Count
$CompliantCount = $CompliantUsers.Count
$NonCompliantCount = $NonCompliantUsers.Count

Write-Host "Results: $CompliantCount/$TotalTargetUsers $UserName users compliant"

if ($NonCompliantCount -gt 0) {
    Write-Host ""
    Write-Host "ALERT: $NonCompliantCount $UserName user(s) have incorrect policy assignment" -ForegroundColor Red
    Write-Host ""
    Write-Host "Non-compliant users:" -ForegroundColor Yellow
    foreach ($User in $NonCompliantUsers) {
        Write-Host "  - $($User.Name) (ID: $($User.Id))"
        Write-Host "    Current:  $($User.CurrentPolicy)" -ForegroundColor DarkGray
        Write-Host "    Expected: $($User.ExpectedPolicy)" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "To remediate, assign these users to '$PolicyName' in the DNSFilter dashboard."
    exit 1
}
else {
    Write-Host ""
    Write-Host "[+] All $UserName users are assigned to '$PolicyName'" -ForegroundColor Green
    exit 0
}
