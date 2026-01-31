# Check all PS1 files for corrupted emoji characters
# Detects common corruption patterns like ?? or garbled bytes

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Determine project root from script location
$ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not (Test-Path "$ProjectRoot\modules")) {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
}

# If a specific file is passed, check just that file
if ($args.Count -gt 0) {
    $filePath = $args[0]
    if (Test-Path $filePath) {
        $content = Get-Content $filePath -Raw -ErrorAction SilentlyContinue
        $issues = @()

        # Check for ?? in variable assignments (corrupted 4-byte emojis)
        if ($content -match '\$\w+\s*=\s*[''"]?\?\?') {
            $issues += "Corrupted emoji in variable assignment (?? pattern)"
        }

        # Check for ScriptToRun with corrupted emoji
        if ($content -match 'ScriptToRun.*\?\?') {
            $issues += "Corrupted emoji in ScriptToRun"
        }

        # Check for LauncherName with corrupted emoji
        if ($content -match 'LauncherName.*\?\?') {
            $issues += "Corrupted emoji in LauncherName"
        }

        # Check for single ? followed by uppercase (corrupted 3-byte emoji)
        if ($content -match '\$\w+\s*=\s*[''"]?\?[A-Z]') {
            $issues += "Corrupted emoji in variable (?X pattern)"
        }

        if ($issues.Count -gt 0) {
            Write-Host "Emoji corruption in: $(Split-Path $filePath -Leaf)" -ForegroundColor Red
            $issues | ForEach-Object { Write-Host "  - $_" }
            exit 1
        } else {
            Write-Host "No emoji corruption: $(Split-Path $filePath -Leaf)" -ForegroundColor Green
            exit 0
        }
    } else {
        Write-Host "File not found: $filePath" -ForegroundColor Red
        exit 1
    }
}

$foldersToCheck = @(
    "$ProjectRoot\modules",
    "$ProjectRoot\scripts",
    "$ProjectRoot\launchers",
    "$ProjectRoot\templates",
    "$ProjectRoot\tools",
    "$ProjectRoot\automations",
    "$ProjectRoot\start_here"
)

$allFiles = @()
foreach ($folder in $foldersToCheck) {
    if (Test-Path $folder) {
        $allFiles += Get-ChildItem -Path $folder -Recurse -Filter "*.ps1"
        $allFiles += Get-ChildItem -Path $folder -Recurse -Filter "*.psm1"
    }
}

Write-Host "Checking $($allFiles.Count) PowerShell files for emoji corruption..."

$corrupted = @()
foreach ($file in $allFiles) {
    try {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        $issues = @()

        # Check for ?? in variable assignments (corrupted 4-byte emojis like eyes, wrench, bell)
        if ($content -match '\$\w+\s*=\s*[''"]?\?\?') {
            $issues += "?? in variable"
        }

        # Check for ScriptToRun with corrupted emoji
        if ($content -match 'ScriptToRun.*\?\?') {
            $issues += "?? in ScriptToRun"
        }

        # Check for LauncherName with corrupted emoji
        if ($content -match 'LauncherName.*\?\?') {
            $issues += "?? in LauncherName"
        }

        # Check for single ? followed by uppercase (corrupted 3-byte emoji like no-entry)
        if ($content -match '\$ScriptToRun\s*=\s*[''"]?\?[A-Z]') {
            $issues += "?X in ScriptToRun"
        }

        # Check for common garbled UTF-8 patterns (Level.io corruption style)
        # These appear when UTF-8 is misinterpreted as Windows-1252
        if ($content -match 'Ã°Å¸|â‰¡Æ''|Î"Â£') {
            $issues += "Garbled UTF-8 bytes"
        }

        if ($issues.Count -gt 0) {
            $corrupted += [PSCustomObject]@{
                File = $file.FullName.Replace($ProjectRoot, ".")
                Issues = $issues -join ", "
            }
        }
    } catch {
        # Skip files that can't be read
    }
}

if ($corrupted.Count -gt 0) {
    Write-Host "`nEmoji corruption detected:" -ForegroundColor Red
    $corrupted | Format-Table File, Issues -AutoSize -Wrap
    Write-Host "`nTo fix, restore UTF-8 BOM: tools\Restore-BOM.ps1" -ForegroundColor Yellow
    Write-Host "Or manually re-save files with proper encoding" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "No emoji corruption found in $($allFiles.Count) files" -ForegroundColor Green
    exit 0
}
