# Update-Launchers.ps1
# Synchronizes all launcher files with the template while preserving $ScriptToRun values

$ErrorActionPreference = "Stop"

$TemplateFile = "e:\COOLForge\templates\Launcher_Template.ps1"
$LaunchersDir = "e:\COOLForge\launchers"

if (!(Test-Path $TemplateFile)) {
    Write-Error "Template file not found: $TemplateFile"
    exit 1
}

if (!(Test-Path $LaunchersDir)) {
    Write-Error "Launchers directory not found: $LaunchersDir"
    exit 1
}

# Read template
$TemplateContent = Get-Content -Path $TemplateFile -Raw

# Get all launcher files
$LauncherFiles = Get-ChildItem -Path $LaunchersDir -Filter "*.ps1" -File

Write-Host "Found $($LauncherFiles.Count) launcher files to update"
Write-Host ""

foreach ($LauncherFile in $LauncherFiles) {
    Write-Host "Processing: $($LauncherFile.Name)"

    # Read current launcher to extract $ScriptToRun value
    $CurrentContent = Get-Content -Path $LauncherFile.FullName -Raw

    # Extract the script name from the current file
    if ($CurrentContent -match '\$ScriptToRun\s*=\s*"([^"]+)"') {
        $ScriptName = $Matches[1]
        Write-Host "  Script: $ScriptName"

        # Replace the template's $ScriptToRun value with this script's name
        $NewContent = $TemplateContent -replace '\$ScriptToRun\s*=\s*"[^"]+"', "`$ScriptToRun = `"$ScriptName`""

        # Change "CHANGE THIS VALUE" to "PRE-CONFIGURED" in the comment
        $NewContent = $NewContent -replace '# SCRIPT TO RUN - CHANGE THIS VALUE', '# SCRIPT TO RUN - PRE-CONFIGURED'

        # Write updated launcher
        Set-Content -Path $LauncherFile.FullName -Value $NewContent -Force
        Write-Host "  Updated successfully" -ForegroundColor Green
    }
    else {
        Write-Warning "  Could not extract ScriptToRun value - skipping"
    }
    Write-Host ""
}

Write-Host "All launchers updated!" -ForegroundColor Green
