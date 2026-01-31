# Validate that each launcher declares all policy_ custom fields its script needs
# Compares {{cf_policy_*}} declarations in launchers against $policy_* usage in scripts

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = Split-Path $PSScriptRoot -Parent

$LauncherDir = "$ProjectRoot/launchers"
$ScriptDir = "$ProjectRoot/scripts"

if (-not (Test-Path $LauncherDir)) {
    Write-Host "Launchers directory not found: $LauncherDir" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $ScriptDir)) {
    Write-Host "Scripts directory not found: $ScriptDir" -ForegroundColor Red
    exit 1
}

# Collect all launchers (recursively, since some are in subdirectories like Policy/Chrome/)
$launchers = Get-ChildItem -Path $LauncherDir -Recurse -Filter "*.ps1"
Write-Host "Scanning $($launchers.Count) launchers..."

$errors = @()

foreach ($launcher in $launchers) {
    $launcherContent = Get-Content $launcher.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $launcherContent) { continue }

    # Extract $ScriptToRun value from the launcher
    $scriptToRun = $null
    if ($launcherContent -match '\$ScriptToRun\s*=\s*"([^"]+)"') {
        $scriptToRun = $Matches[1]
    }
    if (-not $scriptToRun) { continue }

    # Find the matching script file
    $scriptPath = "$ScriptDir/$scriptToRun"
    if (-not (Test-Path $scriptPath)) {
        # Try without subdirectory prefix (some scripts are in subdirectories)
        $scriptPath = Get-ChildItem -Path $ScriptDir -Recurse -Filter (Split-Path $scriptToRun -Leaf) |
            Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $scriptPath -or -not (Test-Path $scriptPath)) { continue }

    # Skip non-PowerShell scripts
    if ($scriptPath -notlike "*.ps1") { continue }

    $scriptContent = Get-Content $scriptPath -Raw -ErrorAction SilentlyContinue
    if (-not $scriptContent) { continue }

    # Extract policy_ fields declared in the launcher ({{cf_policy_*}} patterns)
    $declaredFields = @()
    $fieldMatches = [regex]::Matches($launcherContent, '\$([a-z_]*policy_[a-z0-9_]+)\s*=\s*"\{\{cf_')
    foreach ($m in $fieldMatches) {
        $declaredFields += $m.Groups[1].Value
    }

    # Extract policy_ variables the script actually reads as PowerShell variables.
    # We need to distinguish between:
    #   $policy_foo              — variable access, needs launcher declaration
    #   Get-Variable "policy_foo" — variable access, needs launcher declaration
    #   "policy_foo" as arg to Find-LevelCustomField etc — field name string, NOT a variable
    $usedFields = @()

    # Strip block comments (<# ... #>) to avoid matching doc strings
    $codeOnly = $scriptContent -replace '(?s)<#.*?#>', ''

    # Strip single-line comments
    $codeLines = ($codeOnly -split "`n") | Where-Object { $_.TrimStart() -notmatch '^#' }
    $codeOnly = $codeLines -join "`n"

    # Pattern 1: Direct $policy_* variable references (the $ prefix makes it unambiguous)
    $directRefs = [regex]::Matches($codeOnly, '(?<!\w)\$policy_([a-z0-9_]+)')
    foreach ($m in $directRefs) {
        $varName = "policy_$($m.Groups[1].Value)"
        if ($varName -notin $usedFields) {
            $usedFields += $varName
        }
    }

    # Pattern 2: Get-Variable -Name "policy_varname" (explicit variable lookup)
    $getVarRefs = [regex]::Matches($codeOnly, 'Get-Variable\s+(-Name\s+)?[''"]?(policy_[a-z0-9_]+)[''"]?')
    foreach ($m in $getVarRefs) {
        $varName = $m.Groups[2].Value
        if ($varName -notin $usedFields) {
            $usedFields += $varName
        }
    }

    # We intentionally do NOT match bare quoted strings like "policy_foo" used as
    # arguments to API functions (Find-LevelCustomField, New-LevelCustomField, etc.)
    # Those are field *name* strings, not PowerShell variable references.

    $codeUsedFields = $usedFields

    # Find fields used in script but not declared in launcher
    # Skip dynamic references (policy_$SoftwareName) — those are resolved at runtime
    # from the software name which maps to the main policy_SOFTWARENAME field
    $missing = @()
    foreach ($field in $codeUsedFields) {
        # Skip internal/computed variables that aren't Level.io custom fields
        if ($field -eq "policy_from_tags") { continue }
        if ($field -eq "policy_tag") { continue }
        if ($field -eq "policy_sync_hostnames") { continue }

        if ($field -notin $declaredFields) {
            $missing += $field
        }
    }

    if ($missing.Count -gt 0) {
        $launcherRelPath = $launcher.FullName.Replace($ProjectRoot, ".").Replace("\", "/")
        $scriptRelPath = $scriptPath.Replace($ProjectRoot, ".").Replace("\", "/")
        foreach ($field in $missing) {
            $errors += [PSCustomObject]@{
                Launcher = $launcherRelPath
                Script   = $scriptRelPath
                Field    = $field
            }
        }
    }
}

if ($errors.Count -gt 0) {
    Write-Host "`nMissing launcher field declarations:" -ForegroundColor Red
    Write-Host ""

    # Group by launcher for cleaner output
    $grouped = $errors | Group-Object Launcher
    foreach ($group in $grouped) {
        Write-Host "  $($group.Name)" -ForegroundColor Yellow
        Write-Host "    Script: $($group.Group[0].Script)" -ForegroundColor Gray
        Write-Host "    Missing:" -ForegroundColor Gray
        foreach ($item in $group.Group) {
            Write-Host "      `$($($item.Field)) = `"{{cf_$($item.Field)}}`"" -ForegroundColor Cyan
        }
        Write-Host ""
    }

    Write-Host "Add the missing declarations to the launcher's header section" -ForegroundColor Yellow
    Write-Host "(between `$ScriptToRun and the <# comment block)" -ForegroundColor Gray
    exit 1
} else {
    Write-Host "All $($launchers.Count) launchers declare their scripts' required fields" -ForegroundColor Green
    exit 0
}
