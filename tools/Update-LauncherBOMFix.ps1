# Update-LauncherBOMFix.ps1
# Applies BOM handling fix to all launchers in the repo
#
# The fix:
# 1. Strips mangled BOM from downloaded content
# 2. Strips BOM from local content for consistent hash comparison
# 3. Saves with proper UTF-8 BOM using WriteAllText

param(
    [string]$LaunchersPath = "E:\COOLForge\launchers",
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

# Find all launcher files
$Launchers = Get-ChildItem -Path $LaunchersPath -Recurse -Filter "*.ps1"
Write-Host "Found $($Launchers.Count) launcher files"

$Updated = 0
$Skipped = 0
$Failed = 0

foreach ($Launcher in $Launchers) {
    Write-Host "`nProcessing: $($Launcher.Name)" -NoNewline

    try {
        $Content = Get-Content -Path $Launcher.FullName -Raw -Encoding UTF8
        $OriginalContent = $Content
        $Changes = @()

        # Fix 1: Add BOM stripping after downloading RemoteContent
        $OldPattern1 = @'
        $RemoteContent = (Invoke-WebRequest -Uri $LibFetchUrl -UseBasicParsing -TimeoutSec 10).Content
        $RemoteVersion = Get-ModuleVersion -Content $RemoteContent
'@
        $NewPattern1 = @'
        $RemoteContent = (Invoke-WebRequest -Uri $LibFetchUrl -UseBasicParsing -TimeoutSec 10).Content
        # Strip UTF-8 BOM if present (shows as ? when downloaded via Invoke-WebRequest)
        if ($RemoteContent.StartsWith([char]0xFEFF) -or $RemoteContent.StartsWith('?')) {
            $RemoteContent = $RemoteContent.Substring(1)
        }
        $RemoteVersion = Get-ModuleVersion -Content $RemoteContent
'@

        if ($Content -match [regex]::Escape('$RemoteContent = (Invoke-WebRequest -Uri $LibFetchUrl') -and
            $Content -notmatch 'Strip UTF-8 BOM if present') {
            $Content = $Content -replace [regex]::Escape($OldPattern1), $NewPattern1
            $Changes += "Added BOM stripping after RemoteContent download"
        }

        # Fix 2: Add BOM stripping for LocalContent (for consistent hash comparison)
        $OldPattern2 = @'
        $LocalContent = Get-Content -Path $LibraryPath -Raw -ErrorAction Stop
        $LocalVersion = Get-ModuleVersion -Content $LocalContent
'@
        $NewPattern2 = @'
        $LocalContent = Get-Content -Path $LibraryPath -Raw -ErrorAction Stop
        # Strip BOM for consistent hash comparison
        if ($LocalContent.StartsWith([char]0xFEFF)) {
            $LocalContent = $LocalContent.Substring(1)
        }
        $LocalVersion = Get-ModuleVersion -Content $LocalContent
'@

        if ($Content -match [regex]::Escape('$LocalContent = Get-Content -Path $LibraryPath -Raw') -and
            $Content -notmatch 'Strip BOM for consistent hash comparison') {
            $Content = $Content -replace [regex]::Escape($OldPattern2), $NewPattern2
            $Changes += "Added BOM stripping for LocalContent"
        }

        # Fix 3: Replace Set-Content with WriteAllText for proper UTF-8 BOM
        $OldPattern3 = 'Set-Content -Path $LibraryPath -Value $RemoteContent -Force -ErrorAction Stop'
        $NewPattern3 = '# Save with proper UTF-8 BOM for emoji handling
        [System.IO.File]::WriteAllText($LibraryPath, $RemoteContent, [System.Text.UTF8Encoding]::new($true))'

        if ($Content -match [regex]::Escape($OldPattern3)) {
            $Content = $Content -replace [regex]::Escape($OldPattern3), $NewPattern3
            $Changes += "Changed Set-Content to WriteAllText with UTF-8 BOM"
        }

        if ($Changes.Count -eq 0) {
            Write-Host " - Already up to date" -ForegroundColor Green
            $Skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host " - Would apply $($Changes.Count) changes:" -ForegroundColor Yellow
            foreach ($Change in $Changes) {
                Write-Host "   - $Change"
            }
            $Updated++
            continue
        }

        # Write with proper UTF-8 BOM
        [System.IO.File]::WriteAllText($Launcher.FullName, $Content, [System.Text.UTF8Encoding]::new($true))

        Write-Host " - Applied $($Changes.Count) changes" -ForegroundColor Green
        foreach ($Change in $Changes) {
            Write-Host "   - $Change"
        }
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
Write-Host "  Skipped (already fixed): $Skipped"
Write-Host "  Failed: $Failed"

if ($WhatIf) {
    Write-Host "`nRun without -WhatIf to apply changes."
}
