# Check for orphan scripts (no launcher) and orphan launchers (no script)
# Also validates launcher $ScriptToRun references

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Determine project root from script location
$ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not (Test-Path "$ProjectRoot\modules")) {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
}

$scriptsPath = "$ProjectRoot\scripts"
$launchersPath = "$ProjectRoot\launchers"

if (-not (Test-Path $scriptsPath)) {
    Write-Host "Scripts folder not found: $scriptsPath" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $launchersPath)) {
    Write-Host "Launchers folder not found: $launchersPath" -ForegroundColor Red
    exit 1
}

# Get all scripts (recursively, as they're organized in subfolders)
$scripts = Get-ChildItem $scriptsPath -Recurse -Filter "*.ps1" | ForEach-Object { $_.Name }

# Get all launchers (in root and subfolders)
$launchers = Get-ChildItem $launchersPath -Recurse -Filter "*.ps1"
$launcherNames = $launchers | ForEach-Object { $_.Name }

Write-Host "Found $($scripts.Count) scripts and $($launcherNames.Count) launchers"

$hasErrors = $false

# Check for scripts without launchers
$scriptsWithoutLaunchers = $scripts | Where-Object { $_ -notin $launcherNames }
if ($scriptsWithoutLaunchers) {
    $hasErrors = $true
    Write-Host "`nScripts without launchers:" -ForegroundColor Red
    $scriptsWithoutLaunchers | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}

# Check for launchers without scripts
$launchersWithoutScripts = $launcherNames | Where-Object { $_ -notin $scripts }
if ($launchersWithoutScripts) {
    # This might be intentional for utility launchers, so just warn
    Write-Host "`nLaunchers without matching scripts (may be intentional):" -ForegroundColor Yellow
    $launchersWithoutScripts | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
}

# Validate launcher $ScriptToRun references
Write-Host "`nValidating launcher ScriptToRun references..."
$brokenReferences = @()

foreach ($launcher in $launchers) {
    $content = Get-Content $launcher.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }

    # Extract $ScriptToRun value
    if ($content -match '\$ScriptToRun\s*=\s*[''"]([^''"]+)[''"]') {
        $scriptToRun = $Matches[1]

        # Check if the referenced script exists
        $foundScript = Get-ChildItem $scriptsPath -Recurse -Filter $scriptToRun -ErrorAction SilentlyContinue
        if (-not $foundScript) {
            $brokenReferences += [PSCustomObject]@{
                Launcher = $launcher.Name
                References = $scriptToRun
                Status = "Script not found"
            }
        }
    }
}

if ($brokenReferences.Count -gt 0) {
    $hasErrors = $true
    Write-Host "`nBroken ScriptToRun references:" -ForegroundColor Red
    $brokenReferences | Format-Table Launcher, References, Status -AutoSize
}

# Summary
if ($hasErrors) {
    Write-Host "`nOrphan check: Issues found" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nOrphan check: All scripts have launchers, all references valid" -ForegroundColor Green
    exit 0
}
