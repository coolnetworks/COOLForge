# Run PSScriptAnalyzer on all PowerShell files
# Requires: Install-Module PSScriptAnalyzer

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Determine project root from script location
$ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not (Test-Path "$ProjectRoot\modules")) {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
}

# Check if PSScriptAnalyzer is available
$module = Get-Module -ListAvailable -Name PSScriptAnalyzer
if (-not $module) {
    Write-Host "PSScriptAnalyzer not installed" -ForegroundColor Yellow
    Write-Host "Install with: Install-Module PSScriptAnalyzer -Scope CurrentUser" -ForegroundColor Yellow
    Write-Host "Skipping PSScriptAnalyzer checks..." -ForegroundColor Yellow
    exit 0
}

Import-Module PSScriptAnalyzer -ErrorAction SilentlyContinue

# If a specific file is passed, check just that file
if ($args.Count -gt 0) {
    $filePath = $args[0]
    if (Test-Path $filePath) {
        $results = Invoke-ScriptAnalyzer -Path $filePath -Severity Error, Warning
        if ($results) {
            Write-Host "Issues in: $(Split-Path $filePath -Leaf)" -ForegroundColor Red
            $results | Format-Table -Property Line, Severity, RuleName, Message -AutoSize -Wrap
            exit 1
        } else {
            Write-Host "No issues: $(Split-Path $filePath -Leaf)" -ForegroundColor Green
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
    "$ProjectRoot\tools",
    "$ProjectRoot\automations",
    "$ProjectRoot\start_here"
)

# Rules to exclude (too noisy for this codebase)
$ExcludeRules = @(
    'PSAvoidUsingWriteHost',           # We use Write-Host intentionally for console output
    'PSUseShouldProcessForStateChangingFunctions',  # Not using -WhatIf pattern
    'PSAvoidUsingInvokeExpression',    # Used intentionally in some scripts
    'PSUseDeclaredVarsMoreThanAssignments',  # Too many false positives with Level.io vars
    'PSAvoidGlobalVars'                # Used for module state
)

Write-Host "Running PSScriptAnalyzer (Errors and Warnings only)..."

$allResults = @()
foreach ($folder in $foldersToCheck) {
    if (Test-Path $folder) {
        Write-Host "  Scanning: $folder" -ForegroundColor Gray
        $results = Invoke-ScriptAnalyzer -Path $folder -Recurse -Severity Error, Warning -ExcludeRule $ExcludeRules -ErrorAction SilentlyContinue
        if ($results) {
            foreach ($r in $results) {
                $allResults += [PSCustomObject]@{
                    File = $r.ScriptPath.Replace($ProjectRoot, ".")
                    Line = $r.Line
                    Severity = $r.Severity
                    Rule = $r.RuleName
                    Message = $r.Message
                }
            }
        }
    }
}

if ($allResults.Count -gt 0) {
    # Group by severity
    $errors = $allResults | Where-Object { $_.Severity -eq 'Error' }
    $warnings = $allResults | Where-Object { $_.Severity -eq 'Warning' }

    if ($errors.Count -gt 0) {
        Write-Host "`nErrors ($($errors.Count)):" -ForegroundColor Red
        $errors | Format-Table File, Line, Rule, Message -AutoSize -Wrap
    }

    if ($warnings.Count -gt 0) {
        Write-Host "`nWarnings ($($warnings.Count)):" -ForegroundColor Yellow
        $warnings | Format-Table File, Line, Rule, Message -AutoSize -Wrap
    }

    # Only fail on errors, not warnings
    if ($errors.Count -gt 0) {
        exit 1
    } else {
        Write-Host "`nPSScriptAnalyzer: $($warnings.Count) warnings (no errors)" -ForegroundColor Yellow
        exit 0
    }
} else {
    Write-Host "PSScriptAnalyzer: No issues found" -ForegroundColor Green
    exit 0
}
