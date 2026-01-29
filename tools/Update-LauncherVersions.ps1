# Update-LauncherVersions.ps1
# Updates launcher versions to specified version

param(
    [string]$LaunchersPath = "E:\COOLForge\launchers",
    [string]$TemplatePath = "E:\COOLForge\templates\Slim-Launcher.ps1",
    [string]$NewVersion = "2026.01.22.01",
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

Write-Host "Updating launcher versions to: $NewVersion"

# Update template first
if (Test-Path $TemplatePath) {
    Write-Host "`nUpdating template..." -NoNewline
    $content = Get-Content -Path $TemplatePath -Raw -Encoding UTF8

    # Update .NOTES version
    $content = $content -replace 'Launcher Version:\s*[\d\.]+', "Launcher Version: $NewVersion"
    # Update $LauncherVersion variable
    $content = $content -replace '\$LauncherVersion\s*=\s*"[\d\.]+"', "`$LauncherVersion = `"$NewVersion`""

    if (-not $WhatIf) {
        [System.IO.File]::WriteAllText($TemplatePath, $content, [System.Text.UTF8Encoding]::new($true))
    }
    Write-Host " Done" -ForegroundColor Green
}

# Find all launcher files
$Launchers = Get-ChildItem -Path $LaunchersPath -Recurse -Filter "*.ps1"
Write-Host "`nFound $($Launchers.Count) launcher files"

$Updated = 0
$Failed = 0

foreach ($Launcher in $Launchers) {
    Write-Host "Processing: $($Launcher.Name)" -NoNewline

    try {
        $content = Get-Content -Path $Launcher.FullName -Raw -Encoding UTF8
        $originalContent = $content

        # Update .NOTES version
        $content = $content -replace 'Launcher Version:\s*[\d\.]+', "Launcher Version: $NewVersion"
        # Update $LauncherVersion variable
        $content = $content -replace '\$LauncherVersion\s*=\s*"[\d\.]+"', "`$LauncherVersion = `"$NewVersion`""

        if ($content -eq $originalContent) {
            Write-Host " - No changes needed" -ForegroundColor Yellow
            continue
        }

        if ($WhatIf) {
            Write-Host " - Would update" -ForegroundColor Cyan
            $Updated++
            continue
        }

        # Write with proper UTF-8 BOM
        [System.IO.File]::WriteAllText($Launcher.FullName, $content, [System.Text.UTF8Encoding]::new($true))
        Write-Host " - Updated" -ForegroundColor Green
        $Updated++
    }
    catch {
        Write-Host " - FAILED: $_" -ForegroundColor Red
        $Failed++
    }
}

Write-Host "`n=========================================="
Write-Host "Summary:"
Write-Host "  Updated: $Updated"
Write-Host "  Failed: $Failed"

if ($WhatIf) {
    Write-Host "`nRun without -WhatIf to apply changes."
}
