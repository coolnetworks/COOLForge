<#
.SYNOPSIS
    Test script to explore Level.io Custom Fields API

.DESCRIPTION
    This script tests the Level.io v2 API endpoints for custom fields and custom field values
    to understand how to retrieve the CoolForge_msp_scratch_folder value.

.NOTES
    API Documentation: https://levelapi.readme.io/
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ApiKey
)

$LevelApiBase = "https://api.level.io/v2"

# ============================================================
# LOAD SAVED API KEY
# ============================================================

$ConfigPath = Join-Path $PSScriptRoot ".COOLForgeLib-setup.json"
if (-not $ApiKey -and (Test-Path $ConfigPath)) {
    try {
        $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        if ($Config.ApiKeyEncrypted) {
            $SecureString = ConvertTo-SecureString $Config.ApiKeyEncrypted -ErrorAction Stop
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
            $ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            Write-Host "[+] Using saved API key" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] Could not load saved API key: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $ApiKey) {
    Write-Host "Enter your Level.io API key: " -NoNewline -ForegroundColor Yellow
    $SecureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    $ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

# ============================================================
# API HELPER
# ============================================================

function Invoke-LevelApi {
    param(
        [string]$Endpoint,
        [string]$Method = "GET"
    )

    $Uri = "$LevelApiBase$Endpoint"
    $Headers = @{
        "Authorization" = $ApiKey
        "Content-Type"  = "application/json"
    }

    try {
        $Response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -ErrorAction Stop
        return @{ Success = $true; Data = $Response }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================
# TEST 1: List Custom Fields
# ============================================================

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host " TEST 1: GET /custom_fields" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

$Result = Invoke-LevelApi -Endpoint "/custom_fields"
if ($Result.Success) {
    $Fields = if ($Result.Data.data) { $Result.Data.data } else { $Result.Data }
    Write-Host "[+] Got $($Fields.Count) custom fields" -ForegroundColor Green

    # Find CoolForge_msp_scratch_folder
    $MspScratchField = $Fields | Where-Object { $_.name -eq "CoolForge_msp_scratch_folder" }
    if ($MspScratchField) {
        Write-Host ""
        Write-Host "[+] Found CoolForge_msp_scratch_folder:" -ForegroundColor Green
        Write-Host ($MspScratchField | ConvertTo-Json -Depth 5) -ForegroundColor White
        $MspScratchFieldId = $MspScratchField.id
    }
    else {
        Write-Host "[!] CoolForge_msp_scratch_folder not found in first page" -ForegroundColor Yellow
    }

    # Check pagination
    Write-Host ""
    Write-Host "has_more: $($Result.Data.has_more)" -ForegroundColor DarkGray
}
else {
    Write-Host "[X] Failed: $($Result.Error)" -ForegroundColor Red
}

# ============================================================
# TEST 2: List ALL Custom Fields (with pagination)
# ============================================================

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host " TEST 2: GET /custom_fields (all pages)" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

$AllFields = @()
$Cursor = $null
$PageNum = 0

do {
    $PageNum++
    $Endpoint = "/custom_fields"
    if ($Cursor) {
        $Endpoint += "?starting_after=$Cursor"
    }

    Write-Host "Fetching page $PageNum..." -ForegroundColor DarkGray
    $Result = Invoke-LevelApi -Endpoint $Endpoint

    if ($Result.Success) {
        $Fields = if ($Result.Data.data) { $Result.Data.data } else { $Result.Data }
        $AllFields += $Fields

        if ($Result.Data.has_more -eq $true -and $Fields.Count -gt 0) {
            $Cursor = $Fields[-1].id
        }
        else {
            break
        }
    }
    else {
        Write-Host "[X] Failed: $($Result.Error)" -ForegroundColor Red
        break
    }
} while ($true)

Write-Host "[+] Total custom fields: $($AllFields.Count)" -ForegroundColor Green

# Find CoolForge_msp_scratch_folder in all fields
$MspScratchField = $AllFields | Where-Object { $_.name -eq "CoolForge_msp_scratch_folder" }
if ($MspScratchField) {
    Write-Host ""
    Write-Host "[+] Found CoolForge_msp_scratch_folder:" -ForegroundColor Green
    Write-Host ($MspScratchField | ConvertTo-Json -Depth 5) -ForegroundColor White
    $MspScratchFieldId = $MspScratchField.id
}

# ============================================================
# TEST 3: Get single Custom Field by ID
# ============================================================

if ($MspScratchFieldId) {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host " TEST 3: GET /custom_fields/$MspScratchFieldId" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan

    $Result = Invoke-LevelApi -Endpoint "/custom_fields/$MspScratchFieldId"
    if ($Result.Success) {
        Write-Host "[+] Single field response:" -ForegroundColor Green
        Write-Host ($Result.Data | ConvertTo-Json -Depth 5) -ForegroundColor White
    }
    else {
        Write-Host "[X] Failed: $($Result.Error)" -ForegroundColor Red
    }
}

# ============================================================
# TEST 4: List Custom Field Values (no filter)
# ============================================================

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host " TEST 4: GET /custom_field_values" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

$Result = Invoke-LevelApi -Endpoint "/custom_field_values"
if ($Result.Success) {
    $Values = if ($Result.Data.data) { $Result.Data.data } else { $Result.Data }
    Write-Host "[+] Got $($Values.Count) custom field values" -ForegroundColor Green

    if ($Values.Count -gt 0) {
        Write-Host ""
        Write-Host "First 3 values:" -ForegroundColor DarkGray
        $Values | Select-Object -First 3 | ForEach-Object {
            Write-Host ($_ | ConvertTo-Json -Compress) -ForegroundColor White
        }
    }

    # Look for CoolForge_msp_scratch_folder value
    Write-Host ""
    Write-Host "Looking for CoolForge_msp_scratch_folder values..." -ForegroundColor DarkGray
    $MspValues = $Values | Where-Object { $_.custom_field_name -eq "CoolForge_msp_scratch_folder" -or $_.custom_field_id -eq $MspScratchFieldId }
    if ($MspValues) {
        Write-Host "[+] Found CoolForge_msp_scratch_folder value(s):" -ForegroundColor Green
        $MspValues | ForEach-Object {
            Write-Host ($_ | ConvertTo-Json -Depth 5) -ForegroundColor White
        }
    }
    else {
        Write-Host "[!] No CoolForge_msp_scratch_folder values found in response" -ForegroundColor Yellow
    }

    # Check pagination
    Write-Host ""
    Write-Host "has_more: $($Result.Data.has_more)" -ForegroundColor DarkGray
}
else {
    Write-Host "[X] Failed: $($Result.Error)" -ForegroundColor Red
}

# ============================================================
# TEST 5: List Custom Field Values (filtered by field ID)
# ============================================================

if ($MspScratchFieldId) {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host " TEST 5: GET /custom_field_values?custom_field_id=$MspScratchFieldId" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan

    $Result = Invoke-LevelApi -Endpoint "/custom_field_values?custom_field_id=$MspScratchFieldId"
    if ($Result.Success) {
        $Values = if ($Result.Data.data) { $Result.Data.data } else { $Result.Data }
        Write-Host "[+] Got $($Values.Count) values for CoolForge_msp_scratch_folder" -ForegroundColor Green

        if ($Values.Count -gt 0) {
            Write-Host ""
            $Values | ForEach-Object {
                Write-Host ($_ | ConvertTo-Json -Depth 5) -ForegroundColor White
            }
        }
        else {
            Write-Host "[!] No values returned" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[X] Failed: $($Result.Error)" -ForegroundColor Red
    }
}

# ============================================================
# TEST 6: List Custom Field Values with limit=100
# ============================================================

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host " TEST 6: GET /custom_field_values?limit=100" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

$Result = Invoke-LevelApi -Endpoint "/custom_field_values?limit=100"
if ($Result.Success) {
    $Values = if ($Result.Data.data) { $Result.Data.data } else { $Result.Data }
    Write-Host "[+] Got $($Values.Count) custom field values with limit=100" -ForegroundColor Green
    Write-Host "has_more: $($Result.Data.has_more)" -ForegroundColor DarkGray

    # Look for CoolForge_msp_scratch_folder
    $MspValues = $Values | Where-Object { $_.custom_field_name -eq "CoolForge_msp_scratch_folder" -or $_.custom_field_id -eq $MspScratchFieldId }
    if ($MspValues) {
        Write-Host ""
        Write-Host "[+] Found CoolForge_msp_scratch_folder value(s):" -ForegroundColor Green
        $MspValues | ForEach-Object {
            Write-Host ($_ | ConvertTo-Json -Depth 5) -ForegroundColor White
        }
    }
    else {
        Write-Host "[!] No CoolForge_msp_scratch_folder values found" -ForegroundColor Yellow

        # Show all field names we got
        Write-Host ""
        Write-Host "Fields we got values for:" -ForegroundColor DarkGray
        $Values | ForEach-Object { $_.custom_field_name } | Sort-Object -Unique | ForEach-Object {
            Write-Host "  - $_" -ForegroundColor DarkGray
        }
    }
}
else {
    Write-Host "[X] Failed: $($Result.Error)" -ForegroundColor Red
}

# ============================================================
# TEST 6b: Try pagination using custom_field_id as cursor
# ============================================================

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host " TEST 6b: Paginate using starting_after=<last_custom_field_id>" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

if ($Result.Success -and $Result.Data.has_more) {
    $LastValue = $Values[-1]
    $Cursor = $LastValue.custom_field_id
    Write-Host "Using cursor: $Cursor" -ForegroundColor DarkGray

    $Result2 = Invoke-LevelApi -Endpoint "/custom_field_values?limit=100&starting_after=$Cursor"
    if ($Result2.Success) {
        $Values2 = if ($Result2.Data.data) { $Result2.Data.data } else { $Result2.Data }
        Write-Host "[+] Got $($Values2.Count) more values" -ForegroundColor Green

        if ($Values2.Count -gt 0) {
            Write-Host "First value on page 2:" -ForegroundColor DarkGray
            Write-Host ($Values2[0] | ConvertTo-Json -Compress) -ForegroundColor White

            # Look for CoolForge_msp_scratch_folder
            $MspValues2 = $Values2 | Where-Object { $_.custom_field_name -eq "CoolForge_msp_scratch_folder" -or $_.custom_field_id -eq $MspScratchFieldId }
            if ($MspValues2) {
                Write-Host ""
                Write-Host "[+] Found CoolForge_msp_scratch_folder on page 2:" -ForegroundColor Green
                $MspValues2 | ForEach-Object {
                    Write-Host ($_ | ConvertTo-Json -Depth 5) -ForegroundColor White
                }
            }
        }
    }
    else {
        Write-Host "[X] Failed: $($Result2.Error)" -ForegroundColor Red
    }
}

# ============================================================
# TEST 7: List Organizations (to check custom_fields there)
# ============================================================

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host " TEST 7: GET /organizations (check for custom_fields property)" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

$Result = Invoke-LevelApi -Endpoint "/organizations"
if ($Result.Success) {
    $Orgs = if ($Result.Data.data) { $Result.Data.data } else { $Result.Data }
    Write-Host "[+] Got $($Orgs.Count) organization(s)" -ForegroundColor Green

    if ($Orgs.Count -gt 0) {
        $FirstOrg = $Orgs[0]
        Write-Host ""
        Write-Host "First org properties: $($FirstOrg.PSObject.Properties.Name -join ', ')" -ForegroundColor DarkGray

        if ($FirstOrg.custom_fields) {
            Write-Host ""
            Write-Host "[+] Organization has custom_fields:" -ForegroundColor Green
            Write-Host ($FirstOrg.custom_fields | ConvertTo-Json -Depth 5) -ForegroundColor White
        }
        else {
            Write-Host "[!] Organization doesn't have custom_fields property" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Full first org:" -ForegroundColor DarkGray
            Write-Host ($FirstOrg | ConvertTo-Json -Depth 5) -ForegroundColor White
        }
    }
}
else {
    Write-Host "[X] Failed: $($Result.Error)" -ForegroundColor Red
}

# ============================================================
# TEST 8: Get single Organization (might have more details)
# ============================================================

if ($Orgs -and $Orgs.Count -gt 0) {
    $OrgId = $Orgs[0].id

    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host " TEST 8: GET /organizations/$OrgId" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan

    $Result = Invoke-LevelApi -Endpoint "/organizations/$OrgId"
    if ($Result.Success) {
        Write-Host "[+] Single organization response:" -ForegroundColor Green
        Write-Host ""
        Write-Host "Properties: $($Result.Data.PSObject.Properties.Name -join ', ')" -ForegroundColor DarkGray

        if ($Result.Data.custom_fields) {
            Write-Host ""
            Write-Host "[+] Organization custom_fields:" -ForegroundColor Green
            Write-Host ($Result.Data.custom_fields | ConvertTo-Json -Depth 5) -ForegroundColor White

            # Look for CoolForge_msp_scratch_folder
            if ($Result.Data.custom_fields.CoolForge_msp_scratch_folder -or $Result.Data.custom_fields.cf_CoolForge_msp_scratch_folder) {
                $Value = $Result.Data.custom_fields.CoolForge_msp_scratch_folder
                if (-not $Value) { $Value = $Result.Data.custom_fields.cf_CoolForge_msp_scratch_folder }
                Write-Host ""
                Write-Host "[+] FOUND CoolForge_msp_scratch_folder value: $Value" -ForegroundColor Green
            }
        }
    }
    else {
        Write-Host "[X] Failed: $($Result.Error)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host " TESTS COMPLETE" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
