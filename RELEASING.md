# Release Process

This document outlines the steps for creating a new LevelLib release.

## Version Format

LevelLib uses [Calendar Versioning](https://calver.org/): `YYYY.MM.DD.NN`
- `YYYY.MM.DD` = Release date
- `NN` = Release number for that day (01, 02, etc.)

Example: `v2025.12.29.02` = Second release on December 29, 2025

## Pre-Release Checklist

### 1. Syntax Test All Scripts

Verify all PowerShell files parse without errors:

```powershell
$errors = @()
Get-ChildItem -Path "E:\LevelLib" -Recurse -Filter "*.ps1" | ForEach-Object {
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) {
        $errors += [PSCustomObject]@{ File = $_.Name; Errors = $parseErrors }
    }
}
if ($errors) { $errors | Format-Table -AutoSize } else { Write-Host "All scripts pass syntax check" -ForegroundColor Green }
```

### 2. Ensure All Scripts Have Launchers

Every script in `scripts/` should have a corresponding launcher in `launchers/`:

```powershell
$scripts = Get-ChildItem "scripts/*.ps1" | ForEach-Object { $_.Name }
$launchers = Get-ChildItem "launchers/*.ps1" | ForEach-Object { $_.Name }
$missing = $scripts | Where-Object { $_ -notin $launchers }
if ($missing) { Write-Host "Missing launchers: $($missing -join ', ')" -ForegroundColor Red }
```

To create a missing launcher:
1. Copy `templates/Launcher_Template.ps1` to `launchers/<script-name>.ps1`
2. Update `$ScriptToRun` on line 4 to match the script filename

### 3. Update Module Version (if module changed)

Edit `LevelIO-Common.psm1` in two places:
- Header comment `Version:` (around line 15)
- `$script:ModuleVersion` variable (near end of file)

### 4. Update CHANGELOG.md

Move items from `[Unreleased]` to a new version section:

```markdown
## [vYYYY.MM.DD.NN] - YYYY-MM-DD

### Added
- New features...

### Changed
- Modified features...

### Fixed
- Bug fixes...
```

### 5. Generate MD5SUMS

Run the update script or generate manually:

```powershell
# Using the tool
.\tools\Update-MD5SUMS.ps1

# Or manually
$files = @("LevelIO-Common.psm1") + (Get-ChildItem "scripts/*.ps1" | ForEach-Object { "scripts/$($_.Name)" })
$output = @(
    "# MD5SUMS - Checksums for LevelLib files"
    "# Format: MD5_HASH  FILENAME"
    "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "#"
    "# Verify with PowerShell:"
    '#   $expected = (Invoke-WebRequest -Uri "$BaseUrl/MD5SUMS").Content'
    '#   $hash = (Get-FileHash -Path $file -Algorithm MD5).Hash.ToLower()'
    "#"
)
foreach ($file in $files) {
    $hash = (Get-FileHash -Path $file -Algorithm MD5).Hash.ToLower()
    $output += "$hash  $file"
}
$output | Set-Content "MD5SUMS" -Encoding UTF8
```

## Release Steps

### 6. Commit Changes

```bash
git add -A
git commit -m "vYYYY.MM.DD.NN - Brief description of changes"
```

### 7. Create Tag

```bash
git tag vYYYY.MM.DD.NN -m "vYYYY.MM.DD.NN - Brief description"
```

### 8. Push to Origin

```bash
git push origin main
git push origin vYYYY.MM.DD.NN
```

## Fixing a Release

If you need to update a release after pushing:

```bash
# Delete local and remote tag
git tag -d vYYYY.MM.DD.NN
git push origin :refs/tags/vYYYY.MM.DD.NN

# Make fixes, commit, then recreate tag
git add -A
git commit -m "Fix: description"
git tag vYYYY.MM.DD.NN -m "vYYYY.MM.DD.NN - Description"

# Push everything
git push origin main
git push origin vYYYY.MM.DD.NN
```

## Quick Reference

```bash
# Full release workflow
git add -A && git commit -m "vYYYY.MM.DD.NN - Description"
git tag vYYYY.MM.DD.NN -m "vYYYY.MM.DD.NN - Description"
git push origin main && git push origin vYYYY.MM.DD.NN
```
