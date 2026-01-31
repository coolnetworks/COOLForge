<#
.SYNOPSIS
    Creates a new script and launcher from templates with automatic setup.

.DESCRIPTION
    Streamlines the process of adding a new script to the COOLForge repository:
    - Creates script file in the correct category folder
    - Automatically creates matching launcher
    - Updates script inventory cache
    - Prompts to run pre-release tools

.PARAMETER ScriptName
    Name of the script (without emoji prefix or .ps1 extension)
    Example: "Disable Windows Update"

.PARAMETER Category
    Category folder: Check, Fix, Remove, or Utility

.PARAMETER EmojiPrefix
    Optional emoji prefix. If not provided, will use category default.

.PARAMETER Description
    Short description of what the script does

.PARAMETER SkipLauncher
    Don't create a matching launcher file

.NOTES
    Version: 2025.12.31.01
    Copyright (c) COOLNETWORKS

.EXAMPLE
    .\tools\Create-New-Script.ps1 -ScriptName "Disable Windows Update" -Category Fix -Description "Disables Windows Update service"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ScriptName,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Check", "Fix", "Remove", "Utility")]
    [string]$Category,

    [Parameter(Mandatory=$false)]
    [string]$EmojiPrefix,

    [Parameter(Mandatory=$true)]
    [string]$Description,

    [Parameter(Mandatory=$false)]
    [switch]$SkipLauncher
)

$ErrorActionPreference = "Stop"

# Get repository root
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "COOLForge New Script Creator" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Category emoji mapping - using codepoints to avoid encoding issues
$CategoryEmojiMap = @{
    "Check" = [char]::ConvertFromUtf32(0x1F440)    # Eyes emoji
    "Fix" = [char]::ConvertFromUtf32(0x1F527)      # Wrench emoji
    "Remove" = [char]::ConvertFromUtf32(0x26D4)    # No entry emoji
    "Utility" = [char]::ConvertFromUtf32(0x1F64F)  # Pray hands emoji
}

# Use category default if no emoji provided
if ([string]::IsNullOrWhiteSpace($EmojiPrefix)) {
    $EmojiPrefix = $CategoryEmojiMap[$Category]
}

# Build file names
$ScriptFileName = "$EmojiPrefix$ScriptName.ps1"
$ScriptPath = Join-Path $RepoRoot "scripts\$Category\$ScriptFileName"
$LauncherPath = Join-Path $RepoRoot "launchers\$ScriptFileName"
$LauncherTemplatePath = Join-Path $RepoRoot "templates\Launcher_Template.ps1"

# Check if script already exists
if (Test-Path $ScriptPath) {
    Write-Host "[X] Script already exists: $ScriptPath" -ForegroundColor Red
    exit 1
}

# Create basic script content
Write-Host "[*] Creating script..." -ForegroundColor Yellow
$ScriptContent = @"
<#
.SYNOPSIS
    $Description

.DESCRIPTION
    TODO: Add detailed description

.NOTES
    Version: 1.0.0
    Created: $(Get-Date -Format "yyyy-MM-dd")
    Copyright (c) COOLNETWORKS

.EXAMPLE
    .\$ScriptFileName
#>

`$ErrorActionPreference = "Stop"

# TODO: Implement script logic here

Write-Host "[$ScriptName] Script executed successfully" -ForegroundColor Green
"@

# Write script file
[System.IO.File]::WriteAllText($ScriptPath, $ScriptContent, [System.Text.UTF8Encoding]::new($true))
Write-Host "[+] Created: $ScriptPath" -ForegroundColor Green

# Create launcher unless skipped
if (!$SkipLauncher) {
    if (!(Test-Path $LauncherTemplatePath)) {
        Write-Host "[!] Launcher template not found: $LauncherTemplatePath" -ForegroundColor Yellow
        Write-Host "[!] Skipping launcher creation" -ForegroundColor Yellow
    }
    else {
        Write-Host "[*] Creating launcher..." -ForegroundColor Yellow
        $LauncherContent = Get-Content -Path $LauncherTemplatePath -Raw

        # Set the $ScriptToRun value
        $LauncherContent = $LauncherContent -replace '\$ScriptToRun\s*=\s*"[^"]+"', "`$ScriptToRun = `"$ScriptFileName`""

        # Change "CHANGE THIS VALUE" to "PRE-CONFIGURED"
        $LauncherContent = $LauncherContent -replace '# SCRIPT TO RUN - CHANGE THIS VALUE', '# SCRIPT TO RUN - PRE-CONFIGURED'

        # Write launcher file
        [System.IO.File]::WriteAllText($LauncherPath, $LauncherContent, [System.Text.UTF8Encoding]::new($true))
        Write-Host "[+] Created: $LauncherPath" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Next Steps" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Edit your new script:" -ForegroundColor Yellow
Write-Host "   $ScriptPath" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Implement your script logic" -ForegroundColor Yellow
Write-Host ""
Write-Host "3. Test your script locally" -ForegroundColor Yellow
Write-Host ""
Write-Host "4. Run pre-release tools:" -ForegroundColor Yellow
Write-Host "   .\pre-release\Test-Syntax.ps1" -ForegroundColor Gray
Write-Host "   .\pre-release\Update-ScriptInventory.ps1" -ForegroundColor Gray
Write-Host "   .\pre-release\Update-MD5SUMS.ps1 -UseCache" -ForegroundColor Gray
Write-Host "   .\pre-release\Validate-Release.ps1" -ForegroundColor Gray
Write-Host ""
Write-Host "5. Commit your changes" -ForegroundColor Yellow
Write-Host ""

# Offer to update inventory now
$UpdateInventory = Read-Host "Update script inventory now? (Y/n)"
if ($UpdateInventory -ne 'n' -and $UpdateInventory -ne 'N') {
    Write-Host ""
    & "$RepoRoot\pre-release\Update-ScriptInventory.ps1"
}
else {
    Write-Host "[*] Remember to run Update-ScriptInventory.ps1 before updating MD5SUMS" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[+] Script creation complete!" -ForegroundColor Green
