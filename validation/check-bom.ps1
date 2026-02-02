# Check all PS1 files for UTF-8 BOM
# UTF-8 BOM (EF BB BF) is required for proper emoji handling in PowerShell files

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Determine project root from script location
$ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not (Test-Path "$ProjectRoot\modules")) {
    # Fallback: we're directly in the testing folder
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
}

# If a specific file is passed, check just that file
if ($args.Count -gt 0) {
    $filePath = $args[0]
    if (Test-Path $filePath) {
        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        $hasBOM = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
        if ($hasBOM) {
            Write-Host "BOM present: $(Split-Path $filePath -Leaf)" -ForegroundColor Green
            exit 0
        } else {
            Write-Host "Missing BOM: $filePath" -ForegroundColor Red
            Write-Host "  First bytes: $(($bytes[0..2] | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' ')"
            exit 1
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
    "$ProjectRoot\start_here",
    "$ProjectRoot\bootstrap"
)

$allFiles = @()
foreach ($folder in $foldersToCheck) {
    if (Test-Path $folder) {
        $allFiles += Get-ChildItem -Path $folder -Recurse -Filter "*.ps1"
        $allFiles += Get-ChildItem -Path $folder -Recurse -Filter "*.psm1"
    }
}

Write-Host "Checking $($allFiles.Count) PowerShell files for UTF-8 BOM..."

$missingBOM = @()
foreach ($file in $allFiles) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $hasBOM = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
        if (-not $hasBOM) {
            $missingBOM += [PSCustomObject]@{
                File = $file.FullName.Replace($ProjectRoot, ".")
                FirstBytes = if ($bytes.Length -ge 3) {
                    ($bytes[0..2] | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' '
                } else { "(empty or too short)" }
            }
        }
    } catch {
        $missingBOM += [PSCustomObject]@{
            File = $file.FullName.Replace($ProjectRoot, ".")
            FirstBytes = "Error: $($_.Exception.Message)"
        }
    }
}

if ($missingBOM.Count -gt 0) {
    Write-Host "`nFiles missing UTF-8 BOM:" -ForegroundColor Red
    $missingBOM | Format-Table File, FirstBytes -AutoSize -Wrap
    Write-Host "`nTo fix, run: tools\Restore-BOM.ps1" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "All $($allFiles.Count) files have UTF-8 BOM" -ForegroundColor Green
    exit 0
}
