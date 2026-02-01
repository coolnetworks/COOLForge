<#
.SYNOPSIS
    Software policy enforcement for CIPP Browser Extension.

.DESCRIPTION
    Implements the COOLForge 5-tag policy model for CIPP browser extension management.
    See docs/POLICY-TAGS.md for the complete policy specification.

    This script manages the CIPP (CyberDrain Improved Partner Portal) browser extension
    for both Google Chrome and Microsoft Edge via registry-based extension policies.

    POLICY FLOW (per POLICY-TAGS.md):
    1. Check global control tags (device must have checkmark to be managed)
    2. Check software-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_cipp)
    4. Execute resolved action (install/remove/reinstall)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    SOFTWARE-SPECIFIC OVERRIDE TAGS (with "cipp" suffix):
    - U+1F64F cipp = Install if missing (transient)
    - U+1F6AB cipp = Remove if present (transient)
    - U+1F4CC cipp = Pin - no changes allowed (persistent)
    - U+1F504 cipp = Reinstall - remove + install (transient)
    - U+2705 cipp  = Status: software is installed (set by script)

    CUSTOM FIELD POLICY (inherited Group->Folder->Device):
    - policy_cipp = "install" | "remove" | "pin" | ""

.NOTES
    Version:          2026.02.01.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags
    - $policy_cipp        : Custom field policy value (inherited)
    - $policy_cipp_tenantid : CIPP tenant ID for extension configuration

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# Software Policy - CIPP Browser Extension
# Version: 2026.02.01.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# DEBUG OUTPUT HELPER (Software-specific)
# ============================================================
# Generic debug functions (Write-DebugSection, Write-DebugTags, Write-DebugPolicy,
# Write-DebugTagManagement) are in COOLForge-Common.psm1. This function is
# CIPP-specific with hardcoded registry paths.

function Write-DebugInstallCheck {
    param([bool]$IsInstalled)
    if (-not $DebugScripts) { return }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " DEBUG: Installation Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $RegPaths = @(
        "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionSettings\benimdeioplgkhanklclahllklceahbe",
        "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionSettings\knepjpocdagponkonnbggpcnhnaikajg"
    )

    Write-Host "  --- Registry Keys ---"
    $RegFound = $false
    foreach ($Path in $RegPaths) {
        $Exists = Test-Path $Path
        if ($Exists) { $RegFound = $true }
        Write-Host "  $(if ($Exists) { '[FOUND]' } else { '[    ]' }) $Path" -ForegroundColor $(if ($Exists) { 'Green' } else { 'DarkGray' })
    }

    Write-Host ""
    Write-Host "  SOFTWARE INSTALLED: $(if ($IsInstalled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($IsInstalled) { 'Green' } else { 'Yellow' })
}

# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "cipp"

# Chrome extension ID and URLs
$ChromeExtensionId = "benimdeioplgkhanklclahllklceahbe"
$ChromeUpdateUrl = "https://clients2.google.com/service/update2/crx"

# Edge extension ID and URLs
$EdgeExtensionId = "knepjpocdagponkonnbggpcnhnaikajg"
$EdgeUpdateUrl = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"

# Get tenant ID from custom field
$CippTenantId = Get-Variable -Name "policy_cipp_tenantid" -ValueOnly -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($CippTenantId) -or $CippTenantId -like "{{*}}") { $CippTenantId = $null }

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "Policy-$SoftwareName" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

# Sync script-level debug variables if a debug tag overrode the custom field
if ($Init.DebugTagDetected) {
    $DebugLevel = $Init.DebugLevel
    $DebugScripts = $Init.DebugMode
}

# ============================================================
# SOFTWARE DETECTION
# ============================================================

function Test-CippInstalled {
    $ChromeKey = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionSettings\$ChromeExtensionId"
    $EdgeKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionSettings\$EdgeExtensionId"
    return (Test-Path $ChromeKey) -or (Test-Path $EdgeKey)
}

# ============================================================
# INSTALL FUNCTION
# ============================================================

function Install-Cipp {
    Write-LevelLog "Configuring CIPP browser extension policies..."

    # Warn if tenant ID is not configured
    if ([string]::IsNullOrWhiteSpace($CippTenantId)) {
        Write-LevelLog "WARNING: policy_cipp_tenantid not configured - extension will install but tenant binding will be empty" -Level "WARN"
        Write-Host "  To configure tenant ID:"
        Write-Host "  1. Set the 'policy_cipp_tenantid' custom field in Level.io"
        Write-Host "  2. Value should be your Microsoft 365 tenant ID"
    }

    $Success = $true
    $ConfiguredBrowsers = @()

    # ---- Chrome Extension Policy ----
    try {
        Write-LevelLog "Configuring Chrome extension policy..."

        # ExtensionSettings key
        $ChromeExtSettingsPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionSettings\$ChromeExtensionId"
        if (-not (Test-Path $ChromeExtSettingsPath)) {
            New-Item -Path $ChromeExtSettingsPath -Force | Out-Null
        }
        Set-ItemProperty -Path $ChromeExtSettingsPath -Name "installation_mode" -Value "normal_installed" -Type String -Force
        Set-ItemProperty -Path $ChromeExtSettingsPath -Name "update_url" -Value $ChromeUpdateUrl -Type String -Force
        Set-ItemProperty -Path $ChromeExtSettingsPath -Name "toolbar_pin" -Value "force_pinned" -Type String -Force

        # 3rdparty managed storage - policy key
        $ChromeManagedPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$ChromeExtensionId\policy"
        if (-not (Test-Path $ChromeManagedPath)) {
            New-Item -Path $ChromeManagedPath -Force | Out-Null
        }
        Set-ItemProperty -Path $ChromeManagedPath -Name "showNotifications" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $ChromeManagedPath -Name "enableValidPageBadge" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $ChromeManagedPath -Name "enablePageBlocking" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $ChromeManagedPath -Name "enableCippReporting" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $ChromeManagedPath -Name "cippServerUrl" -Value "https://365.cool.net.au" -Type String -Force
        Set-ItemProperty -Path $ChromeManagedPath -Name "cippTenantId" -Value $(if ($CippTenantId) { $CippTenantId } else { "" }) -Type String -Force
        Set-ItemProperty -Path $ChromeManagedPath -Name "customRulesUrl" -Value "" -Type String -Force
        Set-ItemProperty -Path $ChromeManagedPath -Name "updateInterval" -Value 24 -Type DWord -Force
        Set-ItemProperty -Path $ChromeManagedPath -Name "urlAllowlist" -Value ([string[]]@()) -Type MultiString -Force
        Set-ItemProperty -Path $ChromeManagedPath -Name "enableDebugLogging" -Value 0 -Type DWord -Force

        # customBranding subkey
        $ChromeBrandingPath = Join-Path $ChromeManagedPath "customBranding"
        if (-not (Test-Path $ChromeBrandingPath)) {
            New-Item -Path $ChromeBrandingPath -Force | Out-Null
        }
        Set-ItemProperty -Path $ChromeBrandingPath -Name "companyName" -Value "COOLNETWORKS" -Type String -Force
        Set-ItemProperty -Path $ChromeBrandingPath -Name "companyURL" -Value "https://cool.net.au" -Type String -Force
        Set-ItemProperty -Path $ChromeBrandingPath -Name "productName" -Value "Check - Phishing Protection" -Type String -Force
        Set-ItemProperty -Path $ChromeBrandingPath -Name "supportEmail" -Value "" -Type String -Force
        Set-ItemProperty -Path $ChromeBrandingPath -Name "primaryColor" -Value "#F77F00" -Type String -Force
        Set-ItemProperty -Path $ChromeBrandingPath -Name "logoUrl" -Value "https://cool.net.au/wp-content/uploads/2018/02/COOL-NETWORKS_Logo_3_Final_300-384x160-7666.png" -Type String -Force

        $ConfiguredBrowsers += "Chrome"
        Write-LevelLog "Chrome extension policy configured" -Level "SUCCESS"
    }
    catch {
        Write-LevelLog "Failed to configure Chrome extension policy: $($_.Exception.Message)" -Level "ERROR"
        $Success = $false
    }

    # ---- Edge Extension Policy ----
    try {
        Write-LevelLog "Configuring Edge extension policy..."

        # ExtensionSettings key
        $EdgeExtSettingsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionSettings\$EdgeExtensionId"
        if (-not (Test-Path $EdgeExtSettingsPath)) {
            New-Item -Path $EdgeExtSettingsPath -Force | Out-Null
        }
        Set-ItemProperty -Path $EdgeExtSettingsPath -Name "installation_mode" -Value "normal_installed" -Type String -Force
        Set-ItemProperty -Path $EdgeExtSettingsPath -Name "update_url" -Value $EdgeUpdateUrl -Type String -Force
        Set-ItemProperty -Path $EdgeExtSettingsPath -Name "toolbar_state" -Value "force_shown" -Type String -Force

        # 3rdparty managed storage - policy key
        $EdgeManagedPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$EdgeExtensionId\policy"
        if (-not (Test-Path $EdgeManagedPath)) {
            New-Item -Path $EdgeManagedPath -Force | Out-Null
        }
        Set-ItemProperty -Path $EdgeManagedPath -Name "showNotifications" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $EdgeManagedPath -Name "enableValidPageBadge" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $EdgeManagedPath -Name "enablePageBlocking" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $EdgeManagedPath -Name "enableCippReporting" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $EdgeManagedPath -Name "cippServerUrl" -Value "https://365.cool.net.au" -Type String -Force
        Set-ItemProperty -Path $EdgeManagedPath -Name "cippTenantId" -Value $(if ($CippTenantId) { $CippTenantId } else { "" }) -Type String -Force
        Set-ItemProperty -Path $EdgeManagedPath -Name "customRulesUrl" -Value "" -Type String -Force
        Set-ItemProperty -Path $EdgeManagedPath -Name "updateInterval" -Value 24 -Type DWord -Force
        Set-ItemProperty -Path $EdgeManagedPath -Name "urlAllowlist" -Value ([string[]]@()) -Type MultiString -Force
        Set-ItemProperty -Path $EdgeManagedPath -Name "enableDebugLogging" -Value 0 -Type DWord -Force

        # customBranding subkey
        $EdgeBrandingPath = Join-Path $EdgeManagedPath "customBranding"
        if (-not (Test-Path $EdgeBrandingPath)) {
            New-Item -Path $EdgeBrandingPath -Force | Out-Null
        }
        Set-ItemProperty -Path $EdgeBrandingPath -Name "companyName" -Value "COOLNETWORKS" -Type String -Force
        Set-ItemProperty -Path $EdgeBrandingPath -Name "companyURL" -Value "https://cool.net.au" -Type String -Force
        Set-ItemProperty -Path $EdgeBrandingPath -Name "productName" -Value "Check - Phishing Protection" -Type String -Force
        Set-ItemProperty -Path $EdgeBrandingPath -Name "supportEmail" -Value "" -Type String -Force
        Set-ItemProperty -Path $EdgeBrandingPath -Name "primaryColor" -Value "#F77F00" -Type String -Force
        Set-ItemProperty -Path $EdgeBrandingPath -Name "logoUrl" -Value "https://cool.net.au/wp-content/uploads/2018/02/COOL-NETWORKS_Logo_3_Final_300-384x160-7666.png" -Type String -Force

        $ConfiguredBrowsers += "Edge"
        Write-LevelLog "Edge extension policy configured" -Level "SUCCESS"
    }
    catch {
        Write-LevelLog "Failed to configure Edge extension policy: $($_.Exception.Message)" -Level "ERROR"
        $Success = $false
    }

    if ($Success) {
        Write-LevelLog "CIPP extension configured for: $($ConfiguredBrowsers -join ', ')" -Level "SUCCESS"
    }

    return $Success
}

# ============================================================
# REMOVE FUNCTION
# ============================================================

function Confirm-ExtensionSubkeyPath {
    param(
        [string]$Path,
        [string]$ExtensionId
    )
    $normalized = $Path -replace '/', '\'
    $regexSafeId = [Regex]::Escape($ExtensionId)
    $allowed = @(
        "\\ExtensionSettings\\$regexSafeId$",
        "\\3rdparty\\extensions\\$regexSafeId$",
        "\\3rdparty\\extensions\\$regexSafeId\\policy$",
        "\\3rdparty\\extensions\\$regexSafeId\\policy\\customBranding$"
    )
    foreach ($pattern in $allowed) {
        if ($normalized -match $pattern) { return $true }
    }
    return $false
}

function Remove-Cipp {
    Write-LevelLog "Removing CIPP browser extension policies..."

    $removed = 0
    $notFound = 0
    $failed = 0

    # All registry paths to remove (order: deepest first for clean removal)
    $pathsToRemove = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$ChromeExtensionId\policy\customBranding"; ExtId = $ChromeExtensionId },
        @{ Path = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$ChromeExtensionId\policy"; ExtId = $ChromeExtensionId },
        @{ Path = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$ChromeExtensionId"; ExtId = $ChromeExtensionId },
        @{ Path = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionSettings\$ChromeExtensionId"; ExtId = $ChromeExtensionId },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$EdgeExtensionId\policy\customBranding"; ExtId = $EdgeExtensionId },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$EdgeExtensionId\policy"; ExtId = $EdgeExtensionId },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$EdgeExtensionId"; ExtId = $EdgeExtensionId },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionSettings\$EdgeExtensionId"; ExtId = $EdgeExtensionId }
    )

    foreach ($entry in $pathsToRemove) {
        $regPath = $entry.Path
        $extId = $entry.ExtId

        # Safety validation - ensure path contains expected extension ID
        if (-not (Confirm-ExtensionSubkeyPath -Path $regPath -ExtensionId $extId)) {
            Write-LevelLog "SAFETY: Refusing to delete unvalidated path: $regPath" -Level "ERROR"
            $failed++
            continue
        }

        if (Test-Path $regPath) {
            try {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                Write-LevelLog "Removed: $regPath" -Level "DEBUG"
                $removed++
            }
            catch {
                Write-LevelLog "Failed to remove: $regPath - $($_.Exception.Message)" -Level "ERROR"
                $failed++
            }
        }
        else {
            $notFound++
        }
    }

    Write-LevelLog "Removal summary: $removed removed, $notFound not found, $failed failed" -Level $(if ($failed -gt 0) { "WARN" } else { "SUCCESS" })

    if ($failed -gt 0) {
        Write-Host "Alert: Some CIPP extension registry keys could not be removed"
        Write-Host "  Removed: $removed"
        Write-Host "  Not found: $notFound"
        Write-Host "  Failed: $failed"
        return $false
    }

    # Verify removal
    if (-not (Test-CippInstalled)) {
        Write-LevelLog "CIPP extension policies fully removed" -Level "SUCCESS"
        return $true
    }
    else {
        Write-LevelLog "Some CIPP extension policies may still be present" -Level "WARN"
        return $false
    }
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.02.01.01"
$ExitCode = 0

$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Policy Enforcement: $SoftwareName (v$ScriptVersion)"

    # Debug header
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Magenta
        Write-Host " DEBUG MODE ENABLED (debug_coolforge = verbose)" -ForegroundColor Magenta
        Write-Host " Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
        Write-Host " Computer:  $env:COMPUTERNAME" -ForegroundColor Magenta
        Write-Host "============================================================" -ForegroundColor Magenta
    }

    # Debug: Show all launcher variables
    Write-DebugSection -Title "Launcher Variables" -Data @{
        'MspScratchFolder' = $MspScratchFolder
        'DeviceHostname' = $DeviceHostname
        'DeviceTags' = $DeviceTags
        'LevelApiKey' = $LevelApiKey
    } -MaskApiKey

    Write-Host ""

    # Get custom field policy if available (passed from launcher)
    $CustomFieldPolicyVar = "policy_$SoftwareName"
    $CustomFieldPolicy = Get-Variable -Name $CustomFieldPolicyVar -ValueOnly -ErrorAction SilentlyContinue
    if ($CustomFieldPolicy) {
        Write-LevelLog "Custom field policy: $CustomFieldPolicy"
    }

    # Debug: Show custom field policy
    Write-DebugSection -Title "Custom Field Policy" -Data @{
        "policy_$SoftwareName" = $CustomFieldPolicy
        "policy_cipp_tenantid" = $CippTenantId
    }

    # Debug: Analyze device tags
    Write-DebugTags -TagString $DeviceTags -SoftwareName $SoftwareName

    # ============================================================
    # AUTO-BOOTSTRAP: Ensure policy infrastructure exists
    # ============================================================
    # Always check and create missing tags/custom fields
    # Initialize-SoftwarePolicyInfrastructure is idempotent
    if ($LevelApiKey) {
        # Debug: Show API key info (obfuscated - first 4 chars only)
        $KeyLength = $LevelApiKey.Length
        $KeyPreview = if ($KeyLength -gt 4) { $LevelApiKey.Substring(0, 4) + "****" } else { "(invalid)" }
        Write-LevelLog "API key: $KeyPreview (length: $KeyLength)" -Level "DEBUG"

        # Pass launcher variable values to skip API calls for field existence check
        $PolicyFieldValue = Get-Variable -Name "policy_$SoftwareName" -ValueOnly -ErrorAction SilentlyContinue

        $InfraResult = Initialize-SoftwarePolicyInfrastructure -ApiKey $LevelApiKey `
            -SoftwareName $SoftwareName `
            -RequireUrl $false `
            -PolicyFieldValue $PolicyFieldValue

        # Bootstrap CIPP-specific extra field: policy_cipp_tenantid
        $ExtraFieldsCreated = 0
        $TenantIdFieldName = "policy_cipp_tenantid"
        $TenantIdRaw = Get-Variable -Name $TenantIdFieldName -ValueOnly -ErrorAction SilentlyContinue
        $TenantIdFieldExists = -not [string]::IsNullOrWhiteSpace($TenantIdRaw) -and $TenantIdRaw -notlike "{{*}}"
        if (-not $TenantIdFieldExists) {
            $NewField = New-LevelCustomField -ApiKey $LevelApiKey -Name $TenantIdFieldName -DefaultValue ""
            if ($NewField) {
                Write-LevelLog "Created custom field: $TenantIdFieldName" -Level "SUCCESS"
                $ExtraFieldsCreated++
            }
        }

        $TotalFieldsCreated = $InfraResult.FieldsCreated + $ExtraFieldsCreated

        if ($InfraResult.Success) {
            if ($InfraResult.TagsCreated -gt 0 -or $TotalFieldsCreated -gt 0) {
                Write-LevelLog "Created $($InfraResult.TagsCreated) tags, $TotalFieldsCreated fields" -Level "SUCCESS"
                # Alert user to configure the new custom fields on first run
                Write-Host ""
                Write-Host "Alert: Policy infrastructure created - please configure custom fields"
                Write-Host "  Set the following custom fields in Level.io:"
                Write-Host "  - policy_cipp: Set to 'install', 'remove', or 'pin' at Group/Folder/Device level"
                Write-Host "  - policy_cipp_tenantid: Set to your Microsoft 365 tenant ID"
                Write-Host ""
                Write-LevelLog "Infrastructure created - exiting for configuration" -Level "INFO"
                $script:ExitCode = 1
                return 1
            }
        }
        else {
            Write-LevelLog "Infrastructure setup warning: $($InfraResult.Error)" -Level "WARN"
        }
    }

    # Check current installation state
    $IsInstalled = Test-CippInstalled
    Write-LevelLog "Current state: $(if ($IsInstalled) { 'Installed' } else { 'Not installed' })"

    # Debug: Show installation check details
    Write-DebugInstallCheck -IsInstalled $IsInstalled

    Write-Host ""

    # Run the policy check with the 5-tag model
    # For deep debugging, call Get-SoftwarePolicy directly with -ShowDebug
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host " DEBUG: Get-SoftwarePolicy Internal Trace" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        $null = Get-SoftwarePolicy -SoftwareName $SoftwareName -DeviceTags $DeviceTags -CustomFieldPolicy $CustomFieldPolicy -ShowDebug
    }
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $SoftwareName `
                                         -DeviceTags $DeviceTags `
                                         -CustomFieldPolicy $CustomFieldPolicy

    # Debug: Show policy resolution details
    Write-DebugPolicy -Policy $Policy

    # Debug: Show tag management readiness
    Write-DebugTagManagement -HasApiKey ([bool]$LevelApiKey) -DeviceHostname $DeviceHostname -ApiKeyValue $LevelApiKey

    Write-Host ""

    # Take action based on resolved policy
    $ActionSuccess = $false
    if ($Policy.ShouldProcess) {
        switch ($Policy.ResolvedAction) {
            "Install" {
                # If triggered by tag, set device custom field to "install" so intent persists
                if ($Policy.ActionSource -eq "Tag" -and $LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $FieldRef = "policy_$SoftwareName"
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $FieldRef -Value "install"
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$FieldRef' = 'install'" -Level "SUCCESS"
                        }
                    }
                }
                if ($IsInstalled) {
                    Write-LevelLog "Already installed - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                else {
                    Write-LevelLog "ACTION: Installing $SoftwareName" -Level "INFO"
                    $ActionSuccess = Install-Cipp
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Installation unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Remove" {
                # If triggered by tag, set device custom field to "remove" so intent persists
                if ($Policy.ActionSource -eq "Tag" -and $LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $FieldRef = "policy_$SoftwareName"
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $FieldRef -Value "remove"
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$FieldRef' = 'remove'" -Level "SUCCESS"
                        }
                    }
                }

                if (-not $IsInstalled) {
                    Write-LevelLog "Not installed - no action needed" -Level "SUCCESS"
                    $ActionSuccess = $true
                }
                else {
                    Write-LevelLog "ACTION: Removing $SoftwareName" -Level "INFO"
                    $ActionSuccess = Remove-Cipp
                    if (-not $ActionSuccess) {
                        Write-LevelLog "FAILED: Removal unsuccessful" -Level "ERROR"
                        $script:ExitCode = 1
                    }
                }
            }
            "Reinstall" {
                Write-LevelLog "ACTION: Reinstalling $SoftwareName" -Level "INFO"
                if ($IsInstalled) {
                    $RemoveSuccess = Remove-Cipp
                    if (-not $RemoveSuccess) {
                        Write-LevelLog "FAILED: Could not remove for reinstall" -Level "ERROR"
                        $script:ExitCode = 1
                        break
                    }
                }
                $ActionSuccess = Install-Cipp
                if (-not $ActionSuccess) {
                    Write-LevelLog "FAILED: Reinstallation unsuccessful" -Level "ERROR"
                    $script:ExitCode = 1
                }
            }
            "Pin" {
                Write-LevelLog "Pinned - no changes allowed" -Level "INFO"
                # Set device-level custom field based on intent:
                # - If Remove tag also present, set to "remove" (block installs)
                # - Otherwise set to "pin" (preserve current state)
                if ($LevelApiKey) {
                    $Device = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
                    if ($Device) {
                        $FieldRef = "policy_$SoftwareName"
                        $FieldValue = if ("Remove" -in $Policy.PolicyActions) { "remove" } else { "pin" }
                        $SetResult = Set-LevelCustomFieldValue -ApiKey $LevelApiKey -EntityType "device" -EntityId $Device.id -FieldReference $FieldRef -Value $FieldValue
                        if ($SetResult) {
                            Write-LevelLog "Set device custom field '$FieldRef' = '$FieldValue'" -Level "SUCCESS"
                        }
                    }
                }
                $ActionSuccess = $true
            }
            "None" {
                # Verify current state matches expected
                if ($Policy.HasInstalled -and -not $IsInstalled) {
                    Write-LevelLog "WARNING: Status tag says installed but extension policies not found" -Level "WARN"
                }
                elseif (-not $Policy.HasInstalled -and $IsInstalled) {
                    Write-LevelLog "INFO: Extension policies are configured (no policy action)" -Level "INFO"
                }
                else {
                    Write-LevelLog "No action required" -Level "INFO"
                }
                $ActionSuccess = $true
            }
        }
    }

    # ============================================================
    # TAG MANAGEMENT (per POLICY-TAGS.md Tag Cleanup Rules)
    # ============================================================
    # Only update tags if we have an API key
    if ($LevelApiKey) {
        Write-Host ""
        Write-LevelLog "Updating tags..." -Level "INFO"

        # Debug: Get device ID and tags BEFORE changes
        $DeviceForTags = $null
        $TagsBefore = @()
        if ($DebugScripts) {
            $DeviceForTags = Find-LevelDevice -ApiKey $LevelApiKey -Hostname $DeviceHostname
            if ($DeviceForTags) {
                Write-LevelLog "Device ID: $($DeviceForTags.id)" -Level "DEBUG"
                $TagsBefore = Get-LevelDeviceTagNames -ApiKey $LevelApiKey -DeviceId $DeviceForTags.id
                Write-LevelLog "Tags BEFORE: $($TagsBefore -join ', ')" -Level "DEBUG"
            } else {
                Write-LevelLog "Could not find device for tag verification" -Level "WARN"
            }
        }

        # Check final install state
        $FinalInstallState = Test-CippInstalled

        # Tag cleanup based on action and success
        if ($ActionSuccess -and $Policy.ShouldProcess) {
            $SoftwareNameUpper = $SoftwareName.ToUpper()

            switch ($Policy.ResolvedAction) {
                "Install" {
                    # Remove Install tag, set Has tag
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Install" -DeviceHostname $DeviceHostname
                    if ($FinalInstallState) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "Remove" {
                    # Remove Remove tag, remove Has tag
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Remove" -DeviceHostname $DeviceHostname
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                }
                "Reinstall" {
                    # Remove Reinstall tag, set Has tag
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Reinstall" -DeviceHostname $DeviceHostname
                    if ($FinalInstallState) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "Pin" {
                    # Remove Pin tag (intent now captured in custom field)
                    Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Pin" -DeviceHostname $DeviceHostname
                    # Also remove Remove tag if present (intent captured in custom field as "remove")
                    if ("Remove" -in $Policy.PolicyActions) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Remove" -DeviceHostname $DeviceHostname
                    }
                    # Ensure Has tag reflects actual state
                    if ($FinalInstallState -and -not $Policy.HasInstalled) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                    elseif (-not $FinalInstallState -and $Policy.HasInstalled) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
                "None" {
                    # Reconcile Has tag with actual install state
                    if ($FinalInstallState -and -not $Policy.HasInstalled) {
                        Add-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                    elseif (-not $FinalInstallState -and $Policy.HasInstalled) {
                        Remove-LevelPolicyTag -ApiKey $LevelApiKey -TagName $SoftwareNameUpper -EmojiPrefix "Has" -DeviceHostname $DeviceHostname
                    }
                }
            }
        }
        elseif (-not $Policy.ShouldProcess) {
            Write-LevelLog "Skipped - no tag updates needed" -Level "INFO"
        }
        else {
            Write-LevelLog "Action failed - tags not updated" -Level "WARN"
        }

        # Debug: Get tags AFTER changes
        if ($DebugScripts -and $DeviceForTags) {
            $TagsAfter = Get-LevelDeviceTagNames -ApiKey $LevelApiKey -DeviceId $DeviceForTags.id
            Write-LevelLog "Tags AFTER: $($TagsAfter -join ', ')" -Level "DEBUG"

            # Show what changed
            $Added = $TagsAfter | Where-Object { $_ -notin $TagsBefore }
            $Removed = $TagsBefore | Where-Object { $_ -notin $TagsAfter }
            if ($Added.Count -gt 0) {
                Write-LevelLog "Tags ADDED: $($Added -join ', ')" -Level "DEBUG"
            }
            if ($Removed.Count -gt 0) {
                Write-LevelLog "Tags REMOVED: $($Removed -join ', ')" -Level "DEBUG"
            }
            if ($Added.Count -eq 0 -and $Removed.Count -eq 0) {
                Write-LevelLog "No tag changes detected" -Level "DEBUG"
            }
        }
    }
    else {
        Write-LevelLog "No API key - tag updates skipped" -Level "DEBUG"
    }

    Write-Host ""

    if ($ActionSuccess) {
        Write-LevelLog "Policy enforcement completed successfully" -Level "SUCCESS"
    }
    else {
        Write-Host ""
        Write-Host "Alert: Policy enforcement failed for $SoftwareName"
        Write-Host "  Device: $DeviceHostname"
        Write-Host "  Action: $($Policy.ResolvedAction)"
        Write-Host "  See details above for specific error"
        Write-LevelLog "Policy enforcement completed with errors" -Level "ERROR"
    }

    # Debug footer
    if ($DebugScripts) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Magenta
        Write-Host " END OF DEBUG OUTPUT" -ForegroundColor Magenta
        Write-Host "============================================================" -ForegroundColor Magenta
    }

    # Return exit code based on action success
    return $(if ($ActionSuccess) { 0 } else { 1 })
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams

exit $ExitCode
