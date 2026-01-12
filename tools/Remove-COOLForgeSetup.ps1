<#
.SYNOPSIS
    Removes COOLForge custom fields and tags from Level.io.

.DESCRIPTION
    This script provides options to remove:
    - All COOLForge custom fields (those starting with "coolforge_" or known field names)
    - All policy tags (emoji-prefixed tags for software policies)
    - Special tags (technician, standalone emoji markers)

    Use this to clean up a Level.io account after testing or to start fresh.

.NOTES
    Version:          2026.01.12
    Target Platform:  Level.io RMM
    Requirements:     Level.io API key with Custom Fields and Tags permissions

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

#Requires -Version 5.1

# Set UTF-8 encoding for proper emoji handling
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# ============================================================
# LOAD MODULE
# ============================================================

$ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-CustomFields.psm1"
if (-not (Test-Path $ModulePath)) {
    Write-Host "ERROR: Cannot find COOLForge-CustomFields.psm1 at: $ModulePath" -ForegroundColor Red
    exit 1
}

# Force reimport to get latest changes
Remove-Module COOLForge-CustomFields -ErrorAction SilentlyContinue
Import-Module $ModulePath -Force

# ============================================================
# CONFIGURATION
# ============================================================

# Known COOLForge custom field names (including legacy names)
$KnownCOOLForgeFields = @(
    # Core fields
    "coolforge_msp_scratch_folder",
    "coolforge_ps_module_library_source",
    "coolforge_pin_psmodule_to_version",
    "coolforge_pat",
    "coolforge_nosleep_duration_min",
    "coolforge_technician_alerts",
    # Legacy names
    "msp_scratch_folder",
    "ps_module_library_source",
    "pin_psmodule_to_version",
    # Level API
    "apikey",
    # ScreenConnect
    "screenconnect_instance_id",
    "screenconnect_instance",
    "screenconnect_baseurl",
    "screenconnect_api_user",
    "screenconnect_api_password",
    "is_screenconnect_server",
    "screenconnect_device_url",
    "screenconnect_url",
    # Huntress
    "huntress_account_key",
    "huntress_organization_key",
    "huntress_tags"
)

# Policy tag emoji prefixes (5-tag model per POLICY-TAGS.md)
$PolicyEmojiPrefixes = @(
    [char]::ConvertFromUtf32(0x1F64F)  # U+1F64F Pray (Install override)
    [char]::ConvertFromUtf32(0x1F6AB)  # U+1F6AB Prohibited (Remove override)
    [char]::ConvertFromUtf32(0x1F4CC)  # U+1F4CC Pushpin (Pin override)
    [char]::ConvertFromUtf32(0x1F504)  # U+1F504 Arrows (Reinstall override)
    [char]0x2705                        # U+2705 Checkmark (Status: Installed)
)

# Special standalone tags
$SpecialTags = @(
    "technician"
    "$([char]0x274C)"  # Standalone cross mark
    "$([char]0x2705)"  # Standalone check mark
    "__coolforge_permission_test__"  # Test tag from setup wizard
)

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor DarkGray
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkGray
    Write-Host ""
}

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default = $false
    )
    $DefaultText = if ($Default) { "Y/n" } else { "y/N" }
    $Response = Read-Host "$Prompt [$DefaultText]"
    if ([string]::IsNullOrWhiteSpace($Response)) {
        return $Default
    }
    return $Response.Trim().ToLower() -in @("y", "yes")
}

function Test-IsCOOLForgeField {
    param([string]$FieldName)

    # Check if it's a known COOLForge field
    if ($FieldName -in $KnownCOOLForgeFields) {
        return $true
    }

    # Check if it starts with coolforge_
    if ($FieldName -like "coolforge_*") {
        return $true
    }

    return $false
}

function Test-IsPolicyTag {
    param([string]$TagName)

    # Check if it's a special tag
    if ($TagName -in $SpecialTags) {
        return $true
    }

    # Check if it starts with a policy emoji
    foreach ($Emoji in $PolicyEmojiPrefixes) {
        if ($TagName.StartsWith($Emoji)) {
            return $true
        }
    }

    return $false
}

# ============================================================
# MAIN SCRIPT
# ============================================================

Write-Host ""
Write-Host "  COOLForge Cleanup Tool" -ForegroundColor Yellow
Write-Host "  Remove custom fields and tags from Level.io" -ForegroundColor DarkGray
Write-Host ""

# ============================================================
# API KEY
# ============================================================

Write-Header "API Authentication"

# Try to load saved config
$ConfigPath = Join-Path $PSScriptRoot "coolforge-setup.json"
$SavedApiKey = $null

if (Test-Path $ConfigPath) {
    try {
        $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        if ($Config.api_key_encrypted) {
            $SavedApiKey = Unprotect-ApiKey -EncryptedKey $Config.api_key_encrypted
            if ($SavedApiKey) {
                Write-Host "Found saved API key from previous setup." -ForegroundColor Green
                $UseSaved = Read-YesNo -Prompt "Use saved API key" -Default $true
                if (-not $UseSaved) {
                    $SavedApiKey = $null
                }
            }
        }
    }
    catch {
        # Ignore config load errors
    }
}

if ($SavedApiKey) {
    $ApiKey = $SavedApiKey
}
else {
    Write-Host "Enter your Level.io API key."
    Write-Host "The key needs 'Custom Fields' and 'Tags' permissions." -ForegroundColor DarkGray
    Write-Host ""
    $ApiKey = Read-Host "API Key"

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-Host "No API key provided. Exiting." -ForegroundColor Red
        exit 1
    }
}

# Initialize the API
Initialize-COOLForgeCustomFields -ApiKey $ApiKey

# Test connection
Write-Host ""
Write-Host "Testing API connection..." -ForegroundColor DarkGray
$TestFields = Get-ExistingCustomFields
if ($null -eq $TestFields) {
    Write-Host "Failed to connect to Level.io API. Please check your API key." -ForegroundColor Red
    exit 1
}
Write-Host "Connected successfully." -ForegroundColor Green

# ============================================================
# CUSTOM FIELDS CLEANUP
# ============================================================

Write-Header "Custom Fields Cleanup"

$AllFields = Get-ExistingCustomFields
$COOLForgeFields = @($AllFields | Where-Object { Test-IsCOOLForgeField $_.name })

if ($COOLForgeFields.Count -eq 0) {
    Write-Host "No COOLForge custom fields found." -ForegroundColor DarkGray
}
else {
    Write-Host "Found $($COOLForgeFields.Count) COOLForge custom field(s):" -ForegroundColor Yellow
    Write-Host ""
    foreach ($Field in $COOLForgeFields) {
        $AdminTag = if ($Field.admin_only) { " (admin-only)" } else { "" }
        Write-Host "  - $($Field.name)$AdminTag" -ForegroundColor White
    }
    Write-Host ""

    $DeleteFields = Read-YesNo -Prompt "Delete all COOLForge custom fields" -Default $false

    if ($DeleteFields) {
        Write-Host ""
        Write-Host "Deleting custom fields..." -ForegroundColor Yellow

        $DeletedCount = 0
        $FailedCount = 0

        foreach ($Field in $COOLForgeFields) {
            Write-Host "  Deleting: $($Field.name)..." -NoNewline
            $Result = Remove-CustomField -FieldId $Field.id -FieldName $Field.name
            if ($Result) {
                Write-Host " Done" -ForegroundColor Green
                $DeletedCount++
            }
            else {
                Write-Host " Failed" -ForegroundColor Red
                $FailedCount++
            }
        }

        Write-Host ""
        if ($DeletedCount -gt 0) {
            Write-Host "Deleted $DeletedCount custom field(s)." -ForegroundColor Green
        }
        if ($FailedCount -gt 0) {
            Write-Host "Failed to delete $FailedCount custom field(s)." -ForegroundColor Red
        }
    }
    else {
        Write-Host "Skipped custom field deletion." -ForegroundColor DarkGray
    }
}

# ============================================================
# TAGS CLEANUP
# ============================================================

Write-Header "Tags Cleanup"

$AllTags = Get-LevelTags -ApiKey $ApiKey

if ($null -eq $AllTags -or $AllTags.Count -eq 0) {
    Write-Host "No tags found (or no tag permission)." -ForegroundColor DarkGray
}
else {
    $PolicyTags = @($AllTags | Where-Object { Test-IsPolicyTag $_.name })

    if ($PolicyTags.Count -eq 0) {
        Write-Host "No COOLForge policy tags found." -ForegroundColor DarkGray
    }
    else {
        Write-Host "Found $($PolicyTags.Count) COOLForge policy tag(s):" -ForegroundColor Yellow
        Write-Host ""
        foreach ($Tag in $PolicyTags) {
            Write-Host "  - $($Tag.name)" -ForegroundColor White
        }
        Write-Host ""

        $DeleteTags = Read-YesNo -Prompt "Delete all COOLForge policy tags" -Default $false

        if ($DeleteTags) {
            Write-Host ""
            Write-Host "Deleting tags..." -ForegroundColor Yellow

            $DeletedCount = 0
            $FailedCount = 0

            foreach ($Tag in $PolicyTags) {
                Write-Host "  Deleting: $($Tag.name)..." -NoNewline
                $Result = Remove-LevelTag -ApiKey $ApiKey -TagId $Tag.id -TagName $Tag.name
                if ($Result) {
                    Write-Host " Done" -ForegroundColor Green
                    $DeletedCount++
                }
                else {
                    Write-Host " Failed" -ForegroundColor Red
                    $FailedCount++
                }
            }

            Write-Host ""
            if ($DeletedCount -gt 0) {
                Write-Host "Deleted $DeletedCount tag(s)." -ForegroundColor Green
            }
            if ($FailedCount -gt 0) {
                Write-Host "Failed to delete $FailedCount tag(s)." -ForegroundColor Red
            }
        }
        else {
            Write-Host "Skipped tag deletion." -ForegroundColor DarkGray
        }
    }
}

# ============================================================
# DELETE ALL TAGS OPTION
# ============================================================

if ($AllTags -and $AllTags.Count -gt 0) {
    $NonPolicyTags = @($AllTags | Where-Object { -not (Test-IsPolicyTag $_.name) })

    if ($NonPolicyTags.Count -gt 0) {
        Write-Host ""
        Write-Host "There are $($NonPolicyTags.Count) other (non-COOLForge) tags in your account." -ForegroundColor DarkGray

        $ShowOther = Read-YesNo -Prompt "Show other tags" -Default $false
        if ($ShowOther) {
            Write-Host ""
            foreach ($Tag in $NonPolicyTags) {
                Write-Host "  - $($Tag.name)" -ForegroundColor White
            }
        }

        Write-Host ""
        Write-Host "WARNING: The following option will delete ALL tags, not just COOLForge ones!" -ForegroundColor Red
        $DeleteAllTags = Read-YesNo -Prompt "Delete ALL tags (including non-COOLForge)" -Default $false

        if ($DeleteAllTags) {
            Write-Host ""
            Write-Host "Are you absolutely sure? This cannot be undone!" -ForegroundColor Red
            $Confirm = Read-YesNo -Prompt "Type 'y' to confirm deletion of ALL tags" -Default $false

            if ($Confirm) {
                Write-Host ""
                Write-Host "Deleting ALL tags..." -ForegroundColor Yellow

                $DeletedCount = 0
                $FailedCount = 0

                foreach ($Tag in $AllTags) {
                    Write-Host "  Deleting: $($Tag.name)..." -NoNewline
                    $Result = Remove-LevelTag -ApiKey $ApiKey -TagId $Tag.id -TagName $Tag.name
                    if ($Result) {
                        Write-Host " Done" -ForegroundColor Green
                        $DeletedCount++
                    }
                    else {
                        Write-Host " Failed" -ForegroundColor Red
                        $FailedCount++
                    }
                }

                Write-Host ""
                if ($DeletedCount -gt 0) {
                    Write-Host "Deleted $DeletedCount tag(s)." -ForegroundColor Green
                }
                if ($FailedCount -gt 0) {
                    Write-Host "Failed to delete $FailedCount tag(s)." -ForegroundColor Red
                }
            }
            else {
                Write-Host "Cancelled." -ForegroundColor DarkGray
            }
        }
    }
}

# ============================================================
# CLEANUP COMPLETE
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor DarkGray
Write-Host " Cleanup Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor DarkGray
Write-Host ""
