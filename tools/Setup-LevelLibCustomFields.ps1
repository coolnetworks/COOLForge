<#
.SYNOPSIS
    Interactive setup script for LevelLib custom fields in Level.io.

.DESCRIPTION
    This script helps you configure the required custom fields for LevelLib in your
    Level.io account. It will:

    1. Authenticate with the Level.io API using your API key
    2. Check which custom fields already exist
    3. Create any missing required fields
    4. Optionally set default values for fields
    5. Suggest pinning to the current version for stability

    REQUIRED CUSTOM FIELDS:
    - msp_scratch_folder      : Persistent storage folder on endpoints (REQUIRED)

    OPTIONAL CUSTOM FIELDS:
    - ps_module_library_source : Custom library URL (defaults to official repo)
    - pin_psmodule_to_version  : Pin to specific version tag
    - screenconnect_instance_id: Your MSP's ScreenConnect instance ID
    - is_screenconnect_server  : Mark ScreenConnect server devices

.NOTES
    Version:          2025.12.29.01
    Target Platform:  Windows PowerShell 5.1+

    API Documentation: https://levelapi.readme.io/

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/LevelLib

.LINK
    https://github.com/coolnetworks/LevelLib

.EXAMPLE
    .\Setup-LevelLibCustomFields.ps1

    Runs the interactive setup wizard.

.EXAMPLE
    .\Setup-LevelLibCustomFields.ps1 -ApiKey "your-api-key"

    Runs setup with API key provided (skips the prompt).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApiKey
)

# ============================================================
# CONFIGURATION
# ============================================================

$Script:LevelApiBase = "https://api.level.io/v2"
$Script:CurrentVersion = "v2025.12.29"  # Current LevelLib release tag

# Define the custom fields we need
$Script:RequiredFields = @(
    @{
        Name        = "msp_scratch_folder"
        Description = "Persistent storage folder for MSP scripts and libraries"
        Required    = $true
        Default     = "C:\ProgramData\MSP"
        AdminOnly   = $false
    }
)

$Script:OptionalFields = @(
    @{
        Name        = "ps_module_library_source"
        Description = "URL to download LevelIO-Common.psm1 library (leave empty for official repo)"
        Required    = $false
        Default     = ""
        AdminOnly   = $false
    },
    @{
        Name        = "pin_psmodule_to_version"
        Description = "Pin scripts to a specific version tag (e.g., v2025.12.29)"
        Required    = $false
        Default     = ""
        AdminOnly   = $false
    },
    @{
        Name        = "screenconnect_instance_id"
        Description = "Your MSP's ScreenConnect instance ID for whitelisting"
        Required    = $false
        Default     = ""
        AdminOnly   = $true
    },
    @{
        Name        = "is_screenconnect_server"
        Description = "Set to 'true' on devices hosting ScreenConnect server"
        Required    = $false
        Default     = ""
        AdminOnly   = $false
    }
)

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success {
    param([string]$Text)
    Write-Host "[+] $Text" -ForegroundColor Green
}

function Write-Info {
    param([string]$Text)
    Write-Host "[*] $Text" -ForegroundColor White
}

function Write-Warning {
    param([string]$Text)
    Write-Host "[!] $Text" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Text)
    Write-Host "[X] $Text" -ForegroundColor Red
}

function Invoke-LevelApi {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Body = $null
    )

    $Uri = "$Script:LevelApiBase$Endpoint"
    $Headers = @{
        "Authorization" = $Script:ApiKey
        "Content-Type"  = "application/json"
    }

    $Params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $Headers
        ErrorAction = "Stop"
    }

    if ($Body -and $Method -ne "GET") {
        $Params.Body = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $Response = Invoke-RestMethod @Params
        return @{ Success = $true; Data = $Response }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            try {
                $Reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $ErrorBody = $Reader.ReadToEnd()
                $Reader.Close()
                if ($ErrorBody) {
                    $ErrorMessage = $ErrorBody
                }
            }
            catch { }
        }
        return @{ Success = $false; Error = $ErrorMessage }
    }
}

function Get-ExistingCustomFields {
    Write-Info "Fetching existing custom fields..."
    $Result = Invoke-LevelApi -Endpoint "/custom_fields"

    if (-not $Result.Success) {
        Write-Error "Failed to fetch custom fields: $($Result.Error)"
        return $null
    }

    return $Result.Data
}

function Find-CustomField {
    param(
        [string]$Name,
        [array]$ExistingFields
    )

    foreach ($Field in $ExistingFields) {
        # Check both 'name' and 'key' properties as API may use either
        if ($Field.name -eq $Name -or $Field.key -eq $Name) {
            return $Field
        }
    }
    return $null
}

function New-CustomField {
    param(
        [string]$Name,
        [string]$DefaultValue = "",
        [bool]$AdminOnly = $false
    )

    $Body = @{
        name       = $Name
        admin_only = $AdminOnly
    }

    if (-not [string]::IsNullOrWhiteSpace($DefaultValue)) {
        $Body.default_value = $DefaultValue
    }

    Write-Info "Creating custom field: $Name"
    $Result = Invoke-LevelApi -Endpoint "/custom_fields" -Method "POST" -Body $Body

    if ($Result.Success) {
        Write-Success "Created custom field: $Name"
        return $Result.Data
    }
    else {
        Write-Error "Failed to create custom field '$Name': $($Result.Error)"
        return $null
    }
}

function Update-CustomFieldValue {
    param(
        [string]$FieldId,
        [string]$Value
    )

    $Body = @{
        default_value = $Value
    }

    $Result = Invoke-LevelApi -Endpoint "/custom_fields/$FieldId" -Method "PATCH" -Body $Body
    return $Result.Success
}

function Read-UserInput {
    param(
        [string]$Prompt,
        [string]$Default = ""
    )

    if ([string]::IsNullOrWhiteSpace($Default)) {
        $FullPrompt = "$Prompt`: "
    }
    else {
        $FullPrompt = "$Prompt [$Default]: "
    }

    Write-Host $FullPrompt -NoNewline -ForegroundColor Yellow
    $Input = Read-Host

    if ([string]::IsNullOrWhiteSpace($Input)) {
        return $Default
    }
    return $Input
}

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default = $true
    )

    $DefaultText = if ($Default) { "Y/n" } else { "y/N" }
    Write-Host "$Prompt [$DefaultText]: " -NoNewline -ForegroundColor Yellow
    $Input = Read-Host

    if ([string]::IsNullOrWhiteSpace($Input)) {
        return $Default
    }

    return $Input.ToLower() -eq "y" -or $Input.ToLower() -eq "yes"
}

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-Header "LevelLib Custom Fields Setup"

Write-Host "This wizard will help you configure the custom fields required for LevelLib."
Write-Host "You'll need a Level.io API key with permission to manage custom fields."
Write-Host ""
Write-Host "Get your API key at: https://app.level.io/security" -ForegroundColor Cyan
Write-Host ""

# Get API Key
if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Host "Enter your Level.io API key: " -NoNewline -ForegroundColor Yellow
    $SecureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    $Script:ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
}
else {
    $Script:ApiKey = $ApiKey
}

if ([string]::IsNullOrWhiteSpace($Script:ApiKey)) {
    Write-Error "API key is required. Exiting."
    exit 1
}

# Test API connection
Write-Header "Testing API Connection"

$ExistingFields = Get-ExistingCustomFields
if ($null -eq $ExistingFields) {
    Write-Error "Could not connect to Level.io API. Please check your API key."
    exit 1
}

# Handle both array and object with data property
if ($ExistingFields.data) {
    $ExistingFields = $ExistingFields.data
}

$FieldCount = if ($ExistingFields -is [array]) { $ExistingFields.Count } else { 1 }
Write-Success "Connected! Found $FieldCount existing custom field(s)."

# Process Required Fields
Write-Header "Required Custom Fields"

foreach ($Field in $Script:RequiredFields) {
    Write-Host ""
    Write-Host "Field: $($Field.Name)" -ForegroundColor Cyan
    Write-Host "  Description: $($Field.Description)"
    Write-Host "  Required: Yes"
    Write-Host ""

    $Existing = Find-CustomField -Name $Field.Name -ExistingFields $ExistingFields

    if ($Existing) {
        $CurrentValue = $Existing.default_value
        if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
            $CurrentValue = "(not set)"
        }
        Write-Success "Field already exists!"
        Write-Host "  Current default value: $CurrentValue"

        $NewValue = Read-UserInput -Prompt "  New value (press Enter to keep current)" -Default ""
        if (-not [string]::IsNullOrWhiteSpace($NewValue)) {
            if (Update-CustomFieldValue -FieldId $Existing.id -Value $NewValue) {
                Write-Success "Updated default value to: $NewValue"
            }
        }
    }
    else {
        Write-Warning "Field does not exist - will create it."
        $DefaultValue = Read-UserInput -Prompt "  Default value" -Default $Field.Default

        $Created = New-CustomField -Name $Field.Name -DefaultValue $DefaultValue -AdminOnly $Field.AdminOnly
        if ($Created) {
            $ExistingFields += $Created
        }
    }
}

# Process Optional Fields
Write-Header "Optional Custom Fields"

Write-Host "These fields are optional but enable additional features."
Write-Host ""

foreach ($Field in $Script:OptionalFields) {
    Write-Host ""
    Write-Host "Field: $($Field.Name)" -ForegroundColor Cyan
    Write-Host "  Description: $($Field.Description)"
    if ($Field.AdminOnly) {
        Write-Host "  Admin Only: Yes (values hidden from non-admins)" -ForegroundColor Yellow
    }
    Write-Host ""

    $Existing = Find-CustomField -Name $Field.Name -ExistingFields $ExistingFields

    if ($Existing) {
        $CurrentValue = $Existing.default_value
        if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
            $CurrentValue = "(not set)"
        }
        Write-Success "Field already exists!"
        Write-Host "  Current default value: $CurrentValue"

        # Special handling for version pinning
        if ($Field.Name -eq "pin_psmodule_to_version") {
            if ([string]::IsNullOrWhiteSpace($Existing.default_value)) {
                Write-Host ""
                Write-Host "  TIP: Pin to current version for stability: $Script:CurrentVersion" -ForegroundColor Cyan
                if (Read-YesNo -Prompt "  Would you like to pin to $Script:CurrentVersion" -Default $false) {
                    if (Update-CustomFieldValue -FieldId $Existing.id -Value $Script:CurrentVersion) {
                        Write-Success "Pinned to version: $Script:CurrentVersion"
                    }
                }
            }
            else {
                $NewValue = Read-UserInput -Prompt "  New value (press Enter to keep current, 'clear' to remove)" -Default ""
                if ($NewValue -eq "clear") {
                    if (Update-CustomFieldValue -FieldId $Existing.id -Value "") {
                        Write-Success "Cleared version pin - will use latest from main"
                    }
                }
                elseif (-not [string]::IsNullOrWhiteSpace($NewValue)) {
                    if (Update-CustomFieldValue -FieldId $Existing.id -Value $NewValue) {
                        Write-Success "Updated version pin to: $NewValue"
                    }
                }
            }
        }
        else {
            $NewValue = Read-UserInput -Prompt "  New value (press Enter to keep current)" -Default ""
            if (-not [string]::IsNullOrWhiteSpace($NewValue)) {
                if (Update-CustomFieldValue -FieldId $Existing.id -Value $NewValue) {
                    Write-Success "Updated default value to: $NewValue"
                }
            }
        }
    }
    else {
        if (Read-YesNo -Prompt "  Create this field" -Default $false) {
            $DefaultValue = ""

            # Special handling for version pinning
            if ($Field.Name -eq "pin_psmodule_to_version") {
                Write-Host ""
                Write-Host "  TIP: Pin to current version for stability: $Script:CurrentVersion" -ForegroundColor Cyan
                if (Read-YesNo -Prompt "  Would you like to pin to $Script:CurrentVersion" -Default $false) {
                    $DefaultValue = $Script:CurrentVersion
                }
            }
            else {
                $DefaultValue = Read-UserInput -Prompt "  Default value" -Default $Field.Default
            }

            $Created = New-CustomField -Name $Field.Name -DefaultValue $DefaultValue -AdminOnly $Field.AdminOnly
            if ($Created) {
                $ExistingFields += $Created
            }
        }
        else {
            Write-Info "Skipped: $($Field.Name)"
        }
    }
}

# Summary
Write-Header "Setup Complete"

Write-Host "Your LevelLib custom fields are configured!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Deploy a launcher script from the 'launchers/' folder"
Write-Host "  2. Or copy 'templates/Launcher_Template.ps1' and customize it"
Write-Host "  3. Test on a single device first"
Write-Host ""
Write-Host "Documentation: https://github.com/coolnetworks/LevelLib"
Write-Host ""

# Show final field status
Write-Host "Custom Fields Status:" -ForegroundColor Cyan
$AllFields = $Script:RequiredFields + $Script:OptionalFields
foreach ($Field in $AllFields) {
    $Existing = Find-CustomField -Name $Field.Name -ExistingFields $ExistingFields
    $Status = if ($Existing) { "[OK]" } else { "[--]" }
    $Color = if ($Existing) { "Green" } else { "DarkGray" }
    Write-Host "  $Status $($Field.Name)" -ForegroundColor $Color
}

Write-Host ""
