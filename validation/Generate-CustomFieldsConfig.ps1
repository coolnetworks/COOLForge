<#
.SYNOPSIS
    Scans the COOLForge repository for custom field references and generates a configuration file.

.DESCRIPTION
    This script searches through all PowerShell files in the repository to find Level.io
    custom field references ({{cf_*}}) and generates a JSON configuration file that can be
    used by the Setup-COOLForge.ps1 script to automatically create these fields.

    Field definitions are prioritized to match the Setup wizard's question order.

.PARAMETER OutputPath
    Path where the generated JSON configuration file will be saved.
    Default: .\config\custom-fields-config.json

.PARAMETER IncludeCommented
    Include custom fields that are commented out in the code.
    Default: $false

.EXAMPLE
    .\Generate-CustomFieldsConfig.ps1

.EXAMPLE
    .\Generate-CustomFieldsConfig.ps1 -OutputPath ".\my-config.json" -IncludeCommented

.NOTES
    Version: 1.0.0
    Author: COOLNETWORKS
    https://github.com/coolnetworks/COOLForge
#>

param(
    [string]$OutputPath = ".\config\custom-fields-config.json",
    [switch]$IncludeCommented = $false
)

# Get repository root (parent of tools folder)
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "[*] Scanning COOLForge repository for custom field references..."
Write-Host "[*] Repository root: $RepoRoot"

# Find all PowerShell files
$Files = Get-ChildItem -Path $RepoRoot -Include "*.ps1","*.psm1" -Recurse -ErrorAction SilentlyContinue

# Regex pattern to match {{cf_fieldname}}
$Pattern = '\{\{cf_([A-Za-z0-9_]+)\}\}'

# Hash table to store field information
$FieldsFound = @{}

# Scan all files
$FileCount = 0
foreach ($File in $Files) {
    $FileCount++
    Write-Host "[*] Scanning: $($File.FullName.Replace($RepoRoot, ''))" -ForegroundColor DarkGray

    $LineNumber = 0
    foreach ($Line in Get-Content $File.FullName) {
        $LineNumber++

        # Skip commented lines unless IncludeCommented is set
        if (-not $IncludeCommented -and $Line.Trim().StartsWith('#')) {
            continue
        }

        # Find all matches in this line
        $Matches = [regex]::Matches($Line, $Pattern)

        foreach ($Match in $Matches) {
            $FieldName = $Match.Groups[1].Value

            # Initialize field info if first time seeing this field
            if (-not $FieldsFound.ContainsKey($FieldName)) {
                $FieldsFound[$FieldName] = @{
                    FieldName = $FieldName
                    Occurrences = @()
                    IsCommented = $false
                }
            }

            # Track if this occurrence is commented
            $IsCommented = $Line.Trim().StartsWith('#')
            if ($IsCommented) {
                $FieldsFound[$FieldName].IsCommented = $true
            }

            # Add occurrence
            $FieldsFound[$FieldName].Occurrences += @{
                File = $File.FullName.Replace($RepoRoot + '\', '')
                Line = $LineNumber
                Context = $Line.Trim()
                IsCommented = $IsCommented
            }
        }
    }
}

Write-Host "[+] Scanned $FileCount files"
Write-Host "[+] Found $($FieldsFound.Count) unique custom fields"

# Define field configurations
# IMPORTANT: Priority determines the order fields are presented in Setup wizard
# Priority 1 = asked first (required fields)
# Priority 2 = asked second (common optional fields)
# Priority 3 = asked if specific features are enabled
# Priority 99 = legacy/example fields (not shown in wizard)
$FieldDefinitions = @{
    # ========================================
    # PRIORITY 1: CORE REQUIRED FIELDS
    # ========================================
    'CoolForge_msp_scratch_folder' = @{
        Name = 'CoolForge_msp_scratch_folder'
        LegacyName = 'msp_scratch_folder'
        Description = 'Persistent storage folder on endpoints for COOLForge scripts, libraries, and lockfiles'
        Required = $true
        Scope = 'Global'
        DefaultValue = 'C:\ProgramData\MSP'
        Category = 'Core'
        AdminOnly = $false
        Priority = 1
        Group = $null
    }

    # ========================================
    # PRIORITY 2: OPTIONAL CONFIGURATION FIELDS
    # ========================================
    'CoolForge_ps_module_library_source' = @{
        Name = 'CoolForge_ps_module_library_source'
        LegacyName = 'ps_module_library_source'
        Description = 'URL to download COOLForge-Common.psm1 library (leave empty for official repo)'
        Required = $false
        Scope = 'Global'
        DefaultValue = ''
        Category = 'Configuration'
        AdminOnly = $false
        Priority = 2
        Group = $null
        Note = 'Used for private forks or custom library sources'
    }

    'CoolForge_pin_psmodule_to_version' = @{
        Name = 'CoolForge_pin_psmodule_to_version'
        LegacyName = 'pin_psmodule_to_version'
        Description = 'Pin scripts to specific version tag, branch, or commit (e.g., v2025.12.29, dev)'
        Required = $false
        Scope = 'Global'
        DefaultValue = ''
        Category = 'Configuration'
        AdminOnly = $false
        Priority = 2
        Group = $null
        Note = 'Used for staged rollouts and testing. Setup wizard suggests pinning to current release.'
    }

    'CoolForge_pat' = @{
        Name = 'CoolForge_pat'
        LegacyName = $null
        Description = 'GitHub Personal Access Token for private repository access'
        Required = $false
        Scope = 'Global'
        DefaultValue = ''
        Category = 'Security'
        AdminOnly = $true
        Priority = 2
        Group = $null
        Note = 'Admin-only field. Token is never logged or visible in script output. Required for private forks.'
    }

    'CoolForge_nosleep_duration_min' = @{
        Name = 'CoolForge_nosleep_duration_min'
        LegacyName = $null
        Description = 'Duration in minutes to prevent device sleep (used by Prevent Sleep script)'
        Required = $false
        Scope = 'Global'
        DefaultValue = '60'
        Category = 'Configuration'
        AdminOnly = $false
        Priority = 2
        Group = $null
    }

    # ========================================
    # PRIORITY 3: FEATURE-SPECIFIC FIELDS (asked conditionally)
    # ========================================
    'CoolForge_screenconnect_instance_id' = @{
        Name = 'CoolForge_screenconnect_instance_id'
        LegacyName = 'screenconnect_instance_id'
        Description = 'Your MSP''s ScreenConnect instance ID for whitelisting authorized remote access'
        Required = $false
        Scope = 'Global'
        DefaultValue = ''
        Category = 'Feature-Specific'
        AdminOnly = $true
        Priority = 3
        Group = 'ScreenConnect'
        Note = 'Used by Check for Unauthorized Remote Access Tools script. Setup wizard asks if you use ScreenConnect.'
    }

    'CoolForge_is_screenconnect_server' = @{
        Name = 'CoolForge_is_screenconnect_server'
        LegacyName = 'is_screenconnect_server'
        Description = 'Set to "true" on devices hosting ScreenConnect server (skip RAT checks)'
        Required = $false
        Scope = 'Device'
        DefaultValue = ''
        Category = 'Feature-Specific'
        AdminOnly = $false
        Priority = 3
        Group = 'ScreenConnect'
        Note = 'Device-level field. Set on ScreenConnect server devices to skip remote access tool detection.'
    }

    # ========================================
    # INTEGRATION FIELDS
    # ========================================
    'apikey' = @{
        Name = 'apikey'
        LegacyName = $null
        Description = 'Level.io API key for scripts that interact with the Level.io API'
        Required = $false
        Scope = 'Global'
        DefaultValue = ''
        Category = 'Integration'
        AdminOnly = $true
        Priority = 2
        Group = $null
        Note = 'Required for API-based scripts like Wake-on-LAN. Get API key from https://app.level.io/api-keys'
    }

    # ========================================
    # PRIORITY 99: LEGACY FIELDS (backward compatibility only)
    # ========================================
    'msp_scratch_folder' = @{
        Name = 'msp_scratch_folder'
        LegacyName = $null
        Description = 'LEGACY: Use CoolForge_msp_scratch_folder instead'
        Required = $false
        Scope = 'Global'
        DefaultValue = ''
        Category = 'Legacy'
        AdminOnly = $false
        Priority = 99
        Group = $null
        Deprecated = $true
        Note = 'Pre-2025 field name. Automatically migrated by scripts to CoolForge_msp_scratch_folder.'
    }

    'ps_module_library_source' = @{
        Name = 'ps_module_library_source'
        LegacyName = $null
        Description = 'LEGACY: Use CoolForge_ps_module_library_source instead'
        Required = $false
        Scope = 'Global'
        DefaultValue = ''
        Category = 'Legacy'
        AdminOnly = $false
        Priority = 99
        Group = $null
        Deprecated = $true
        Note = 'Pre-2025 field name. Automatically migrated by scripts to CoolForge_ps_module_library_source.'
    }

    'pin_psmodule_to_version' = @{
        Name = 'pin_psmodule_to_version'
        LegacyName = $null
        Description = 'LEGACY: Use CoolForge_pin_psmodule_to_version instead'
        Required = $false
        Scope = 'Global'
        DefaultValue = ''
        Category = 'Legacy'
        AdminOnly = $false
        Priority = 99
        Group = $null
        Deprecated = $true
        Note = 'Pre-2025 field name. Automatically migrated by scripts to CoolForge_pin_psmodule_to_version.'
    }

    'screenconnect_instance_id' = @{
        Name = 'screenconnect_instance_id'
        LegacyName = $null
        Description = 'LEGACY: Use CoolForge_screenconnect_instance_id instead'
        Required = $false
        Scope = 'Global'
        DefaultValue = ''
        Category = 'Legacy'
        AdminOnly = $true
        Priority = 99
        Group = $null
        Deprecated = $true
        Note = 'Pre-2025 field name. Automatically migrated by scripts to CoolForge_screenconnect_instance_id.'
    }

    'is_screenconnect_server' = @{
        Name = 'is_screenconnect_server'
        LegacyName = $null
        Description = 'LEGACY: Use CoolForge_is_screenconnect_server instead'
        Required = $false
        Scope = 'Device'
        DefaultValue = ''
        Category = 'Legacy'
        AdminOnly = $false
        Priority = 99
        Group = $null
        Deprecated = $true
        Note = 'Pre-2025 field name. Automatically migrated by scripts to CoolForge_is_screenconnect_server.'
    }

    # ========================================
    # EXAMPLE/TEMPLATE FIELDS (not for production)
    # ========================================
    'script_to_run' = @{
        Name = 'script_to_run'
        LegacyName = $null
        Description = 'EXAMPLE: Dynamic script selection (see launcher template for usage)'
        Required = $false
        Scope = 'Device'
        DefaultValue = ''
        Category = 'Example'
        AdminOnly = $false
        Priority = 99
        Group = $null
        Note = 'Example field shown in documentation. Not typically deployed to production.'
    }

    'custom_field_1' = @{
        Name = 'custom_field_1'
        LegacyName = $null
        Description = 'EXAMPLE: Template for adding custom fields'
        Required = $false
        Scope = 'Device'
        DefaultValue = ''
        Category = 'Example'
        AdminOnly = $false
        Priority = 99
        Group = $null
        Note = 'Example field shown in template. Not typically deployed to production.'
    }

    'test_variables' = @{
        Name = 'test_variables'
        LegacyName = $null
        Description = 'EXAMPLE: Used by Test Variable Output script for demonstration'
        Required = $false
        Scope = 'Device'
        DefaultValue = ''
        Category = 'Example'
        AdminOnly = $false
        Priority = 99
        Group = $null
        Note = 'Example field for testing automation variable output. Not typically deployed to production.'
    }
}

# Build the output structure
$Config = @{
    GeneratedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Version = '1.0.0'
    RepositoryRoot = $RepoRoot
    FilesScanned = $FileCount
    FieldsFound = $FieldsFound.Count
    Fields = @()
}

# Process each field found and merge with definitions
# Sort by Priority first, then by Name
$SortedFields = $FieldDefinitions.GetEnumerator() | Sort-Object { $_.Value.Priority }, { $_.Value.Name }

foreach ($FieldEntry in $SortedFields) {
    $FieldName = $FieldEntry.Key
    $Definition = $FieldEntry.Value

    # Add usage statistics if field was found in code
    if ($FieldsFound.ContainsKey($FieldName)) {
        $FieldInfo = $FieldsFound[$FieldName]
        $Definition.UsageCount = $FieldInfo.Occurrences.Count
        $Definition.UsedInFiles = ($FieldInfo.Occurrences | Select-Object -ExpandProperty File -Unique | Sort-Object)
        $Definition.AllCommented = $FieldInfo.Occurrences | Where-Object { -not $_.IsCommented } | Measure-Object | Select-Object -ExpandProperty Count | ForEach-Object { $_ -eq 0 }
    }
    else {
        # Field is defined but not found in code (possible future field)
        $Definition.UsageCount = 0
        $Definition.UsedInFiles = @()
        $Definition.AllCommented = $true
    }

    $Config.Fields += $Definition
}

# Check for fields found in code but not defined
foreach ($FieldName in $FieldsFound.Keys) {
    if (-not $FieldDefinitions.ContainsKey($FieldName)) {
        Write-Warning "No definition found for field: $FieldName (found in $($FieldsFound[$FieldName].Occurrences.Count) locations)"

        # Create a basic definition for unknown fields
        $Definition = @{
            Name = $FieldName
            LegacyName = $null
            Description = "UNDEFINED: Found in code but not documented"
            Required = $false
            Scope = 'Unknown'
            DefaultValue = ''
            Category = 'Undefined'
            AdminOnly = $false
            Priority = 999
            Group = $null
            UsageCount = $FieldsFound[$FieldName].Occurrences.Count
            UsedInFiles = ($FieldsFound[$FieldName].Occurrences | Select-Object -ExpandProperty File -Unique | Sort-Object)
            AllCommented = $FieldsFound[$FieldName].Occurrences | Where-Object { -not $_.IsCommented } | Measure-Object | Select-Object -ExpandProperty Count | ForEach-Object { $_ -eq 0 }
        }

        $Config.Fields += $Definition
    }
}

# Ensure output directory exists
$OutputDir = Split-Path -Parent $OutputPath
if ($OutputDir -and -not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

# Write configuration to JSON
$Config | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

Write-Host ""
Write-Host "[+] Configuration file generated: $OutputPath" -ForegroundColor Green
Write-Host ""

# Display summary by priority and category
Write-Host "=== Custom Fields Summary (by Priority) ===" -ForegroundColor Cyan
Write-Host ""

$PriorityGroups = $Config.Fields | Group-Object -Property Priority | Sort-Object Name

foreach ($PriorityGroup in $PriorityGroups) {
    $PriorityLabel = switch ($PriorityGroup.Name) {
        "1" { "Priority 1: Required Fields (asked first)" }
        "2" { "Priority 2: Optional Configuration (asked second)" }
        "3" { "Priority 3: Feature-Specific (asked conditionally)" }
        "99" { "Priority 99: Legacy/Example (not shown in wizard)" }
        "999" { "Priority 999: Undefined (found in code, needs documentation)" }
        default { "Priority $($PriorityGroup.Name)" }
    }

    Write-Host "[$PriorityLabel]" -ForegroundColor Yellow
    Write-Host ""

    foreach ($Field in ($PriorityGroup.Group | Sort-Object Category, Name)) {
        $RequiredText = if ($Field.Required) { " [REQUIRED]" } else { "" }
        $AdminText = if ($Field.AdminOnly) { " [ADMIN-ONLY]" } else { "" }
        $DeprecatedText = if ($Field.Deprecated) { " [DEPRECATED]" } else { "" }
        $CommentedText = if ($Field.AllCommented) { " [COMMENTED-ONLY]" } else { "" }
        $GroupText = if ($Field.Group) { " (Group: $($Field.Group))" } else { "" }

        Write-Host "  [$($Field.Category)] $($Field.Name)$RequiredText$AdminText$DeprecatedText$CommentedText$GroupText" -ForegroundColor White
        Write-Host "    $($Field.Description)" -ForegroundColor DarkGray

        if ($Field.LegacyName) {
            Write-Host "    Legacy Name: $($Field.LegacyName)" -ForegroundColor DarkYellow
        }

        Write-Host "    Scope: $($Field.Scope) | Default: '$($Field.DefaultValue)' | Used in $($Field.UsageCount) locations" -ForegroundColor DarkGray

        if ($Field.Note) {
            Write-Host "    Note: $($Field.Note)" -ForegroundColor DarkCyan
        }

        Write-Host ""
    }
}

Write-Host "Configuration file ready for use with Setup-COOLForge.ps1" -ForegroundColor Green
Write-Host ""
Write-Host "Field Order in Setup Wizard:" -ForegroundColor Cyan
Write-Host "  1. Required fields (Priority 1)" -ForegroundColor White
Write-Host "  2. Optional configuration (Priority 2)" -ForegroundColor White
Write-Host "  3. Feature-specific fields (Priority 3, asked only if features enabled)" -ForegroundColor White
Write-Host "  4. Legacy/Example fields (Priority 99) are not shown in wizard" -ForegroundColor DarkGray
