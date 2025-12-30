<#
.SYNOPSIS
    Validates COOLForge repository for release readiness.

.DESCRIPTION
    Performs comprehensive validation before creating a release:
    - Git status checks (clean working tree, branch state)
    - PowerShell syntax validation
    - MD5SUMS verification and regeneration if needed
    - Launcher version consistency
    - Launcher completeness (orphaned launchers detection)
    - Script emoji prefix validation
    - TODO comment detection
    - Required files check
    - Provides release tag suggestions (dev-prefixed for dev branch)

.PARAMETER AutoFix
    Automatically fix issues where possible (regenerate MD5SUMS, etc.)

.PARAMETER CreateTag
    Create a git tag after validation passes. Tag will be dev-prefixed if on dev branch.

.NOTES
    Version: 2025.12.31.01
    Copyright (c) COOLNETWORKS

.EXAMPLE
    .\pre-release\Validate-Release.ps1
    # Validates repository, reports issues

.EXAMPLE
    .\pre-release\Validate-Release.ps1 -AutoFix
    # Validates and automatically fixes issues like outdated MD5SUMS

.EXAMPLE
    .\pre-release\Validate-Release.ps1 -AutoFix -CreateTag
    # Validates, fixes, and creates a release tag
#>

param(
    [switch]$AutoFix,
    [switch]$CreateTag
)

$ErrorActionPreference = "Stop"

# Get repository root
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "COOLForge Release Validation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$ValidationErrors = @()
$ValidationWarnings = @()
$ValidationPassed = 0

# ============================================================
# 1. GIT STATUS CHECK
# ============================================================
Write-Host "[1/6] Checking Git status..." -ForegroundColor Yellow

try {
    Push-Location $RepoRoot

    # Get current branch
    $CurrentBranch = git rev-parse --abbrev-ref HEAD 2>&1
    if ($LASTEXITCODE -ne 0) {
        $ValidationErrors += "Not a git repository"
    }
    else {
        Write-Host "    Current branch: $CurrentBranch" -ForegroundColor Gray

        # Check for uncommitted changes
        $GitStatus = git status --porcelain 2>&1
        if ($GitStatus) {
            $ValidationErrors += "Uncommitted changes detected. Commit or stash changes before release."
            Write-Host "    Uncommitted changes:" -ForegroundColor Red
            $GitStatus | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
        }
        else {
            Write-Host "    Working tree clean" -ForegroundColor Green
            $ValidationPassed++
        }

        # Check if branch is up to date with remote
        git fetch origin 2>&1 | Out-Null
        $LocalCommit = git rev-parse $CurrentBranch 2>&1
        $RemoteCommit = git rev-parse "origin/$CurrentBranch" 2>$null

        if ($RemoteCommit -and $LocalCommit -ne $RemoteCommit) {
            $BehindCount = (git rev-list --count "$CurrentBranch..origin/$CurrentBranch" 2>&1)
            $AheadCount = (git rev-list --count "origin/$CurrentBranch..$CurrentBranch" 2>&1)

            if ($AheadCount -gt 0) {
                $ValidationWarnings += "Branch is $AheadCount commit(s) ahead of origin. Consider pushing before release."
            }
            if ($BehindCount -gt 0) {
                $ValidationWarnings += "Branch is $BehindCount commit(s) behind origin. Pull latest changes."
            }
        }
    }
}
finally {
    Pop-Location
}

# ============================================================
# 2. POWERSHELL SYNTAX VALIDATION
# ============================================================
Write-Host "[2/6] Validating PowerShell syntax..." -ForegroundColor Yellow

$PSFiles = Get-ChildItem -Path $RepoRoot -Include "*.ps1", "*.psm1" -Recurse -File |
    Where-Object { $_.FullName -notmatch '\\\.git\\' }

$SyntaxErrors = 0
foreach ($File in $PSFiles) {
    $RelPath = $File.FullName.Substring($RepoRoot.Length + 1)

    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $File.FullName -Raw), [ref]$null)
        # Also try parsing as script
        $null = [System.Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$null, [ref]$null)
    }
    catch {
        $ValidationErrors += "Syntax error in $RelPath`: $($_.Exception.Message)"
        Write-Host "    [X] $RelPath" -ForegroundColor Red
        $SyntaxErrors++
    }
}

if ($SyntaxErrors -eq 0) {
    Write-Host "    All PowerShell files have valid syntax ($($PSFiles.Count) files)" -ForegroundColor Green
    $ValidationPassed++
}
else {
    Write-Host "    $SyntaxErrors file(s) with syntax errors" -ForegroundColor Red
}

# ============================================================
# 3. MD5SUMS VERIFICATION
# ============================================================
Write-Host "[3/6] Verifying MD5SUMS..." -ForegroundColor Yellow

$MD5SumsPath = Join-Path $RepoRoot "MD5SUMS"
if (!(Test-Path $MD5SumsPath)) {
    $ValidationErrors += "MD5SUMS file not found"
    Write-Host "    [X] MD5SUMS file missing" -ForegroundColor Red
}
else {
    $MD5Content = Get-Content -Path $MD5SumsPath
    $MD5Entries = $MD5Content | Where-Object { $_ -notmatch '^#' -and ![string]::IsNullOrWhiteSpace($_) }

    $MismatchCount = 0
    $MissingCount = 0

    foreach ($Entry in $MD5Entries) {
        if ($Entry -match '^([a-f0-9]{32})\s+(.+)$') {
            $ExpectedHash = $Matches[1]
            $FilePath = $Matches[2]
            $FullPath = Join-Path $RepoRoot $FilePath

            if (!(Test-Path $FullPath)) {
                $MissingCount++
                Write-Host "    [!] Missing: $FilePath" -ForegroundColor Yellow
                continue
            }

            $ActualHash = (Get-FileHash -Path $FullPath -Algorithm MD5).Hash.ToLower()
            if ($ActualHash -ne $ExpectedHash) {
                $MismatchCount++
                Write-Host "    [X] Hash mismatch: $FilePath" -ForegroundColor Red
            }
        }
    }

    if ($MismatchCount -eq 0 -and $MissingCount -eq 0) {
        Write-Host "    All MD5 checksums valid ($($MD5Entries.Count) files)" -ForegroundColor Green
        $ValidationPassed++
    }
    else {
        if ($MismatchCount -gt 0) {
            $ValidationErrors += "$MismatchCount file(s) have incorrect MD5 checksums"
        }
        if ($MissingCount -gt 0) {
            $ValidationWarnings += "$MissingCount file(s) in MD5SUMS are missing from repository"
        }

        if ($AutoFix) {
            Write-Host "    [*] Regenerating MD5SUMS..." -ForegroundColor Cyan
            & "$RepoRoot\pre-release\Update-MD5SUMS.ps1"
            Write-Host "    [+] MD5SUMS regenerated" -ForegroundColor Green
            $ValidationPassed++
        }
        else {
            Write-Host "    [!] Run with -AutoFix to regenerate MD5SUMS" -ForegroundColor Yellow
        }
    }
}

# ============================================================
# 4. LAUNCHER VERSION CONSISTENCY
# ============================================================
Write-Host "[4/6] Checking launcher versions..." -ForegroundColor Yellow

$LauncherTemplate = Join-Path $RepoRoot "templates\Launcher_Template.ps1"
$TemplateVersion = $null

if (Test-Path $LauncherTemplate) {
    $TemplateContent = Get-Content -Path $LauncherTemplate -Raw
    if ($TemplateContent -match 'Launcher Version:\s*([\d\.]+)') {
        $TemplateVersion = $Matches[1]
        Write-Host "    Template version: $TemplateVersion" -ForegroundColor Gray
    }
}

if ($TemplateVersion) {
    $LauncherFiles = Get-ChildItem -Path (Join-Path $RepoRoot "launchers") -Filter "*.ps1" -File
    $VersionMismatches = 0

    foreach ($Launcher in $LauncherFiles) {
        $Content = Get-Content -Path $Launcher.FullName -Raw
        if ($Content -match 'Launcher Version:\s*([\d\.]+)') {
            $LauncherVersion = $Matches[1]
            if ($LauncherVersion -ne $TemplateVersion) {
                $VersionMismatches++
                Write-Host "    [X] Version mismatch: $($Launcher.Name) ($LauncherVersion)" -ForegroundColor Red
            }
        }
    }

    if ($VersionMismatches -eq 0) {
        Write-Host "    All launchers match template version ($($LauncherFiles.Count) files)" -ForegroundColor Green
        $ValidationPassed++
    }
    else {
        $ValidationErrors += "$VersionMismatches launcher(s) have mismatched versions. Run Update-Launchers.ps1"
    }
}

# ============================================================
# 5. LAUNCHER COMPLETENESS CHECK
# ============================================================
Write-Host "[5/9] Checking launcher completeness..." -ForegroundColor Yellow

$InventoryPath = Join-Path $RepoRoot ".cache\script-inventory.json"

# Generate inventory if missing
if (!(Test-Path $InventoryPath)) {
    Write-Host "    [*] Generating inventory cache..." -ForegroundColor Gray
    & "$RepoRoot\pre-release\Update-ScriptInventory.ps1" | Out-Null
}

if (Test-Path $InventoryPath) {
    $Inventory = Get-Content -Path $InventoryPath -Raw | ConvertFrom-Json

    # Get all script names
    $AllScripts = @()
    foreach ($Script in $Inventory.Categories.Scripts) {
        $AllScripts += $Script.Name
    }

    # Get all launcher names
    $AllLaunchers = @()
    foreach ($Launcher in $Inventory.Categories.Launchers) {
        $AllLaunchers += $Launcher.Name
    }

    # Find orphaned launchers (launcher without matching script)
    $OrphanedLaunchers = @()
    foreach ($LauncherName in $AllLaunchers) {
        if ($LauncherName -notin $AllScripts) {
            $OrphanedLaunchers += $LauncherName
        }
    }

    # Find missing launchers (script without launcher)
    $MissingLaunchers = @()
    foreach ($ScriptName in $AllScripts) {
        if ($ScriptName -notin $AllLaunchers) {
            $MissingLaunchers += $ScriptName
        }
    }

    if ($OrphanedLaunchers.Count -eq 0 -and $MissingLaunchers.Count -eq 0) {
        Write-Host "    All scripts have matching launchers" -ForegroundColor Green
        $ValidationPassed++
    }
    else {
        if ($OrphanedLaunchers.Count -gt 0) {
            $ValidationErrors += "$($OrphanedLaunchers.Count) orphaned launcher(s) (no matching script)"
            foreach ($Orphan in $OrphanedLaunchers) {
                Write-Host "    [X] Orphaned launcher: $Orphan" -ForegroundColor Red
            }
        }
        if ($MissingLaunchers.Count -gt 0) {
            $ValidationErrors += "$($MissingLaunchers.Count) script(s) without launchers"
            foreach ($Missing in $MissingLaunchers) {
                Write-Host "    [X] Missing launcher for: $Missing" -ForegroundColor Red
            }
        }
    }
}
else {
    $ValidationWarnings += "Could not check launcher completeness (inventory cache missing)"
}

# ============================================================
# 6. EMOJI PREFIX VALIDATION
# ============================================================
Write-Host "[6/9] Validating emoji prefixes..." -ForegroundColor Yellow

$CategoryEmojis = @{
    "Check" = [char]::ConvertFromUtf32(0x1F440)    # 👀
    "Fix" = [char]::ConvertFromUtf32(0x1F527)      # 🔧
    "Remove" = [char]::ConvertFromUtf32(0x26D4)    # ⛔
    "Utility" = [char]::ConvertFromUtf32(0x1F64F)  # 🙏
}

$EmojiErrors = 0
foreach ($Category in $CategoryEmojis.Keys) {
    $CategoryPath = Join-Path $RepoRoot "scripts\$Category"
    if (Test-Path $CategoryPath) {
        $Scripts = Get-ChildItem -Path $CategoryPath -Filter "*.ps1" -File
        foreach ($Script in $Scripts) {
            # Check if file starts with alphanumeric (should start with emoji, not letter/number)
            if ($Script.Name -match '^[a-zA-Z0-9]') {
                Write-Host "    [X] Missing emoji prefix: scripts/$Category/$($Script.Name)" -ForegroundColor Red
                $EmojiErrors++
            }
        }
    }
}

if ($EmojiErrors -eq 0) {
    Write-Host "    All scripts have emoji prefixes" -ForegroundColor Green
    $ValidationPassed++
}
else {
    $ValidationErrors += "$EmojiErrors script(s) missing emoji prefix"
}

# ============================================================
# 7. TODO COMMENT CHECK
# ============================================================
Write-Host "[7/9] Checking for TODO comments..." -ForegroundColor Yellow

$TodoFiles = @()
$ScriptsFolder = Join-Path $RepoRoot "scripts"
if (Test-Path $ScriptsFolder) {
    $AllScriptFiles = Get-ChildItem -Path $ScriptsFolder -Filter "*.ps1" -Recurse -File
    foreach ($File in $AllScriptFiles) {
        $Content = Get-Content -Path $File.FullName -Raw -ErrorAction SilentlyContinue
        if ($Content -match 'TODO:') {
            $RelPath = $File.FullName.Substring($RepoRoot.Length + 1)
            $TodoFiles += $RelPath
        }
    }
}

if ($TodoFiles.Count -eq 0) {
    Write-Host "    No TODO comments found in scripts" -ForegroundColor Green
    $ValidationPassed++
}
else {
    $ValidationWarnings += "$($TodoFiles.Count) script(s) contain TODO comments"
    foreach ($TodoFile in $TodoFiles) {
        Write-Host "    [!] TODO found in: $TodoFile" -ForegroundColor Yellow
    }
}

# ============================================================
# 8. REQUIRED FILES CHECK
# ============================================================
Write-Host "[8/9] Checking required files..." -ForegroundColor Yellow

$RequiredFiles = @(
    "README.md",
    "LICENSE",
    "MD5SUMS",
    "modules/COOLForge-Common.psm1",
    "templates/Launcher_Template.ps1",
    "templates/What is this folder.md",
    "pre-release/Update-MD5SUMS.ps1",
    "pre-release/Update-Launchers.ps1",
    "pre-release/Update-ScriptInventory.ps1",
    "pre-release/Validate-Release.ps1",
    "pre-release/Test-Syntax.ps1"
)

$MissingFiles = @()
foreach ($File in $RequiredFiles) {
    if (!(Test-Path (Join-Path $RepoRoot $File))) {
        $MissingFiles += $File
    }
}

if ($MissingFiles.Count -eq 0) {
    Write-Host "    All required files present" -ForegroundColor Green
    $ValidationPassed++
}
else {
    $ValidationErrors += "Missing required files: $($MissingFiles -join ', ')"
    $MissingFiles | ForEach-Object { Write-Host "    [X] Missing: $_" -ForegroundColor Red }
}

# ============================================================
# 9. SUGGEST RELEASE TAG
# ============================================================
Write-Host "[9/9] Suggesting release tag..." -ForegroundColor Yellow

$Today = Get-Date -Format "yyyy.MM.dd"
$IsDevBranch = $CurrentBranch -eq "dev"

# Find existing tags for today
Push-Location $RepoRoot
$ExistingTags = git tag -l "*$Today*" 2>&1
Pop-Location

if ($IsDevBranch) {
    $SuggestedTag = "dev-$Today"
    if ($ExistingTags -match "dev-$Today") {
        # Find next increment
        $Increment = 1
        while ($ExistingTags -match "dev-$Today.$Increment") {
            $Increment++
        }
        $SuggestedTag = "dev-$Today.$Increment"
    }
}
else {
    $SuggestedTag = "v$Today"
    if ($ExistingTags -match "v$Today") {
        $Increment = 1
        while ($ExistingTags -match "v$Today.$Increment") {
            $Increment++
        }
        $SuggestedTag = "v$Today.$Increment"
    }
}

Write-Host "    Suggested tag: $SuggestedTag" -ForegroundColor Cyan
if ($IsDevBranch) {
    Write-Host "    (dev-prefixed because on dev branch)" -ForegroundColor Gray
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Validation Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if ($ValidationErrors.Count -eq 0) {
    Write-Host "[+] VALIDATION PASSED ($ValidationPassed/9 checks)" -ForegroundColor Green
    Write-Host ""

    if ($ValidationWarnings.Count -gt 0) {
        Write-Host "Warnings:" -ForegroundColor Yellow
        $ValidationWarnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        Write-Host ""
    }

    Write-Host "Ready for release:" -ForegroundColor Green
    Write-Host "  Branch: $CurrentBranch" -ForegroundColor Gray
    Write-Host "  Tag: $SuggestedTag" -ForegroundColor Gray
    Write-Host ""

    if ($CreateTag) {
        Push-Location $RepoRoot
        Write-Host "Creating tag: $SuggestedTag" -ForegroundColor Cyan
        git tag -a $SuggestedTag -m "Release $SuggestedTag"
        Write-Host "[+] Tag created: $SuggestedTag" -ForegroundColor Green
        Write-Host "[*] Push tag with: git push origin $SuggestedTag" -ForegroundColor Yellow
        Pop-Location
    }
    else {
        Write-Host "To create tag: git tag -a $SuggestedTag -m `"Release $SuggestedTag`"" -ForegroundColor Gray
        Write-Host "Or run: .\pre-release\Validate-Release.ps1 -CreateTag" -ForegroundColor Gray
    }

    exit 0
}
else {
    Write-Host "[X] VALIDATION FAILED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Errors:" -ForegroundColor Red
    $ValidationErrors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host ""

    if ($ValidationWarnings.Count -gt 0) {
        Write-Host "Warnings:" -ForegroundColor Yellow
        $ValidationWarnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        Write-Host ""
    }

    Write-Host "Fix the above issues before creating a release." -ForegroundColor Yellow
    if (!$AutoFix) {
        Write-Host "Try running with -AutoFix to automatically fix some issues." -ForegroundColor Yellow
    }

    exit 1
}
