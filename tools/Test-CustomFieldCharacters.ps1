<#
.SYNOPSIS
    Tests which characters Level.io accepts in custom field values

.DESCRIPTION
    Creates 4 test custom fields with variations of | and - characters
    to determine what Level.io's API accepts.

.PARAMETER ApiKey
    Level.io API key with Custom Fields permission

.EXAMPLE
    .\Test-CustomFieldCharacters.ps1 -ApiKey "your-api-key"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$ApiKey
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

# Test cases
$TestCases = @(
    @{ Name = "test1_pipe"; Value = "test | test"; Description = "Pipe with spaces" },
    @{ Name = "test2_dash"; Value = "test - test"; Description = "Dash with spaces" },
    @{ Name = "test3_escaped_pipe"; Value = "test \| test"; Description = "Escaped pipe" },
    @{ Name = "test4_raw_pipe"; Value = "test|test"; Description = "Raw pipe no spaces" }
)

Write-Host "`n[*] Testing custom field value characters..." -ForegroundColor Cyan
Write-Host ""

foreach ($Test in $TestCases) {
    Write-Host "Creating: $($Test.Name)" -ForegroundColor Yellow
    Write-Host "  Value: '$($Test.Value)'" -ForegroundColor Gray

    # Create the field
    $Body = @{
        name          = $Test.Name
        description   = $Test.Description
        default_value = $Test.Value
        admin_only    = $false
    }

    $CreateResult = Invoke-LevelApi -Uri "$BaseUrl/custom_fields" -Method "POST" -Body $Body

    if ($CreateResult.Success) {
        $FieldId = $CreateResult.Data.id
        Write-Host "  [+] Created field (id: $FieldId)" -ForegroundColor Green

        # Now try to set the org-level value
        $ValueBody = @{
            custom_field_id = $FieldId
            assigned_to_id  = $null
            value           = $Test.Value
        }

        $ValueResult = Invoke-LevelApi -Uri "$BaseUrl/custom_field_values" -Method "PATCH" -Body $ValueBody

        if ($ValueResult.Success) {
            Write-Host "  [+] Set value successfully" -ForegroundColor Green
        }
        else {
            Write-Host "  [X] Failed to set value: $($ValueResult.Error)" -ForegroundColor Red
        }

        # Read back the actual org-level value from custom_field_values
        $ValuesResult = Invoke-LevelApi -Uri "$BaseUrl/custom_field_values?limit=100" -Method "GET"
        if ($ValuesResult.Success) {
            $Values = if ($ValuesResult.Data.data) { $ValuesResult.Data.data } else { @($ValuesResult.Data) }
            $OrgValue = $Values | Where-Object { $_.custom_field_id -eq $FieldId -and [string]::IsNullOrEmpty($_.assigned_to_id) } | Select-Object -First 1
            if ($OrgValue) {
                Write-Host "  [i] Actual org-level value: '$($OrgValue.value)'" -ForegroundColor Cyan
            } else {
                Write-Host "  [!] No org-level value found!" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "  [X] Failed to create: $($CreateResult.Error)" -ForegroundColor Red
    }

    Write-Host ""
}

Write-Host "[*] Done! Check Level.io to see which fields were created with correct values." -ForegroundColor Cyan
Write-Host "[*] Clean up with: .\Clear-EmptyCustomFields.ps1 or delete test1-4 manually" -ForegroundColor Gray
