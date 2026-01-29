<#
.SYNOPSIS
    Deletes all custom fields with empty values from Level.io

.DESCRIPTION
    Lists all custom fields and deletes those with empty/null default values.
    Useful for cleaning up before testing auto-creation functionality.

.PARAMETER ApiKey
    Level.io API key with Custom Fields permission

.PARAMETER WhatIf
    Show what would be deleted without actually deleting

.EXAMPLE
    .\Clear-EmptyCustomFields.ps1 -ApiKey "your-api-key"
    .\Clear-EmptyCustomFields.ps1 -ApiKey "your-api-key" -WhatIf
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$BaseUrl = "https://api.level.io/v2"

function Invoke-LevelApi {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Body = $null
    )

    # Level.io v2 API does NOT use "Bearer" prefix - just the API key directly
    $Headers = @{
        "Authorization" = $ApiKey
        "Content-Type"  = "application/json"
    }

    $Params = @{
        Uri     = $Uri
        Method  = $Method
        Headers = $Headers
    }

    if ($Body) {
        $Params.Body = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $Response = Invoke-RestMethod @Params
        return @{ Success = $true; Data = $Response }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Get all custom fields
Write-Host "`n[*] Fetching custom fields..." -ForegroundColor Cyan
$AllFields = @()
$StartingAfter = $null

do {
    $Uri = "$BaseUrl/custom_fields?limit=100"
    if ($StartingAfter) { $Uri += "&starting_after=$StartingAfter" }

    $Result = Invoke-LevelApi -Uri $Uri
    if (-not $Result.Success) {
        Write-Host "[X] Failed to fetch fields: $($Result.Error)" -ForegroundColor Red
        exit 1
    }

    $Data = $Result.Data
    $Fields = if ($Data.data) { $Data.data } else { @($Data) }
    $AllFields += $Fields

    $HasMore = $Data.has_more -eq $true
    if ($HasMore -and $Fields.Count -gt 0) {
        $StartingAfter = $Fields[-1].id
    }
} while ($HasMore)

Write-Host "[+] Found $($AllFields.Count) custom fields" -ForegroundColor Green

# Get values for each field
Write-Host "[*] Fetching field values..." -ForegroundColor Cyan
$ValuesResult = Invoke-LevelApi -Uri "$BaseUrl/custom_field_values?limit=100"
$AllValues = @()
if ($ValuesResult.Success) {
    $AllValues = if ($ValuesResult.Data.data) { $ValuesResult.Data.data } else { @($ValuesResult.Data) }
}

# Build lookup of field values (org-level only, where assigned_to_id is null)
$FieldValues = @{}
foreach ($Value in $AllValues) {
    if ([string]::IsNullOrEmpty($Value.assigned_to_id)) {
        $FieldValues[$Value.custom_field_id] = $Value.value
    }
}

# Find empty fields
$EmptyFields = @()
foreach ($Field in $AllFields) {
    $Value = $FieldValues[$Field.id]
    if ([string]::IsNullOrWhiteSpace($Value)) {
        $EmptyFields += $Field
    }
}

Write-Host "[*] Found $($EmptyFields.Count) fields with empty values:" -ForegroundColor Yellow
foreach ($Field in $EmptyFields) {
    Write-Host "    - $($Field.name) (id: $($Field.id))" -ForegroundColor Gray
}

if ($EmptyFields.Count -eq 0) {
    Write-Host "`n[+] No empty fields to delete" -ForegroundColor Green
    exit 0
}

# Confirm deletion
if (-not $WhatIf) {
    Write-Host "`n" -NoNewline
    $Confirm = Read-Host "Delete these $($EmptyFields.Count) fields? (y/N)"
    if ($Confirm -ne "y" -and $Confirm -ne "Y") {
        Write-Host "[*] Cancelled" -ForegroundColor Yellow
        exit 0
    }
}

# Delete fields
$Deleted = 0
$Failed = 0
foreach ($Field in $EmptyFields) {
    if ($WhatIf) {
        Write-Host "[WHATIF] Would delete: $($Field.name)" -ForegroundColor Magenta
    }
    else {
        $DeleteResult = Invoke-LevelApi -Uri "$BaseUrl/custom_fields/$($Field.id)" -Method "DELETE"
        if ($DeleteResult.Success) {
            Write-Host "[+] Deleted: $($Field.name)" -ForegroundColor Green
            $Deleted++
        }
        else {
            Write-Host "[X] Failed to delete $($Field.name): $($DeleteResult.Error)" -ForegroundColor Red
            $Failed++
        }
    }
}

if (-not $WhatIf) {
    Write-Host "`n[*] Done: $Deleted deleted, $Failed failed" -ForegroundColor Cyan
}
