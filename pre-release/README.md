# Pre-Release Scripts

This folder contains scripts that should be run before creating a release or committing code changes. These tools ensure code quality, consistency, and release readiness.

## Script Inventory Cache

The pre-release tools use a cached inventory (`.cache/script-inventory.json`) to track all PowerShell files in the repository. This ensures nothing gets missed when updating MD5 checksums or checking launcher completeness.

The cache is automatically generated when needed and excluded from git (via `.gitignore`).

---

## Scripts

### Update-ScriptInventory.ps1

Generates a comprehensive inventory of all PowerShell files in the repository.

**Usage:**
```powershell
.\pre-release\Update-ScriptInventory.ps1
```

**What it does:**
- Scans all categories: scripts/, launchers/, modules/, templates/, pre-release/, tools/
- Generates JSON inventory with file paths, sizes, and modification dates
- Saves to `.cache/script-inventory.json`
- Provides breakdown by category and subcategory

**When to run:**
- Usually not needed manually (other scripts auto-generate when needed)
- Can run manually to see full repository inventory
- Useful for auditing what files exist in each category

**Output includes:**
- Total file count across all categories
- Scripts grouped by subcategory (Check, Fix, Remove, Utility)
- File metadata (path, name, size, last modified)

---

### Test-Syntax.ps1

Validates PowerShell syntax for all `.ps1` and `.psm1` files in the repository.

**Usage:**
```powershell
.\pre-release\Test-Syntax.ps1
```

**What it does:**
- Scans all PowerShell files (excluding `.git` folder)
- Parses each file to check for syntax errors
- Reports errors with file name and line number
- Exit code 0 = success, 1 = syntax errors found

**When to run:**
- Before committing changes
- After editing PowerShell files
- As part of CI/CD pipeline

---

### Update-MD5SUMS.ps1

Regenerates the `MD5SUMS` file with checksums for all tracked files.

**Usage:**
```powershell
# Direct file scanning (original method)
.\pre-release\Update-MD5SUMS.ps1

# Use inventory cache (faster, ensures completeness)
.\pre-release\Update-MD5SUMS.ps1 -UseCache
```

**What it does:**
- Scans `modules/COOLForge-Common.psm1` (only the library downloaded by launchers)
- Scans all scripts in `scripts/` folder (recursive, includes category subfolders)
- Scans `templates/What is this folder.md`
- Generates MD5 checksum for each file
- Updates `MD5SUMS` file at repository root

**With -UseCache:**
- Uses script inventory cache for file list
- Auto-generates inventory if cache missing
- Ensures no scripts are accidentally missed
- Slightly faster for large repositories

**When to run:**
- After modifying any library, script, or template files
- Before creating a release
- When Validate-Release.ps1 reports checksum mismatches

**Note:** The launcher uses MD5SUMS to locate scripts in subfolders and verify file integrity during downloads.

---

### Update-Launchers.ps1

Synchronizes all launcher files with the launcher template.

**Usage:**
```powershell
# Update all launchers from template
.\pre-release\Update-Launchers.ps1

# Update and check for missing/orphaned launchers
.\pre-release\Update-Launchers.ps1 -CheckCompleteness
```

**What it does:**
- Reads `templates/Launcher_Template.ps1`
- Updates all launcher files in `launchers/` folder
- Preserves individual `$ScriptToRun` values
- Updates version numbers and code logic
- Changes comments from "CHANGE THIS VALUE" to "PRE-CONFIGURED"

**With -CheckCompleteness:**
- Uses script inventory cache to verify every script has a launcher
- Reports scripts without launchers (missing launchers)
- Reports launchers without matching scripts (orphaned launchers)
- Helps ensure no script gets left behind

**When to run:**
- After modifying `templates/Launcher_Template.ps1`
- Before committing template changes
- To ensure all launchers have consistent code
- When adding new scripts (use -CheckCompleteness to verify launcher exists)

**Critical:** Always run this after changing the launcher template. Never commit a template change without updating all launchers.

---

### Validate-Release.ps1

Comprehensive pre-release validation with 6 checks.

**Usage:**
```powershell
# Check only (reports issues)
.\pre-release\Validate-Release.ps1

# Check and auto-fix issues
.\pre-release\Validate-Release.ps1 -AutoFix

# Check, fix, and create release tag
.\pre-release\Validate-Release.ps1 -AutoFix -CreateTag
```

**What it validates:**

1. **Git Status**
   - Working tree is clean (no uncommitted changes)
   - Branch state vs. remote (ahead/behind warnings)

2. **PowerShell Syntax**
   - All `.ps1` and `.psm1` files parse correctly
   - Reports syntax errors with file names

3. **MD5SUMS Verification**
   - All files in MD5SUMS have correct checksums
   - AutoFix: Regenerates MD5SUMS if mismatches found

4. **Launcher Version Consistency**
   - All launchers match template version
   - Reports mismatched launcher files

5. **Required Files Check**
   - README.md, LICENSE, MD5SUMS
   - modules/COOLForge-Common.psm1
   - templates/Launcher_Template.ps1
   - templates/What is this folder.md
   - tools/Update-MD5SUMS.ps1, Update-Launchers.ps1

6. **Release Tag Suggestion**
   - Suggests next available tag for current branch
   - Dev branch: `dev-YYYY.MM.DD` (or `.01`, `.02`, etc.)
   - Main branch: `vYYYY.MM.DD` (or `.01`, `.02`, etc.)
   - CreateTag: Creates the suggested tag

**Exit codes:**
- 0 = Validation passed (ready for release)
- 1 = Validation failed (fix issues before release)

**When to run:**
- Before creating any release
- Before pushing to origin
- Before merging dev to main
- As final check before tagging

---

## Recommended Workflow

### Before Committing Code

1. Run syntax check:
   ```powershell
   .\pre-release\Test-Syntax.ps1
   ```

2. If you changed library, scripts, or templates:
   ```powershell
   .\pre-release\Update-MD5SUMS.ps1
   ```

3. If you changed launcher template:
   ```powershell
   .\pre-release\Update-Launchers.ps1
   ```

### Before Creating a Release

Run full validation with auto-fix:
```powershell
.\pre-release\Validate-Release.ps1 -AutoFix
```

If validation passes and you're ready to tag:
```powershell
.\pre-release\Validate-Release.ps1 -AutoFix -CreateTag
```

Then push the tag:
```powershell
git push origin dev-2025.12.31
```

---

## Notes

- These scripts are for **maintainers only** (not end users)
- They run locally on your development machine
- They do not modify endpoint systems
- Exit codes: 0 = success, 1 = failure (standard for automation)
- All scripts use relative paths from repository root
