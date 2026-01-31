# Run all validation checks
# Exit code: 0 if all pass, 1 if any fail

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$TestingDir = $PSScriptRoot
$ProjectRoot = Split-Path $TestingDir -Parent

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "COOLForge Validation Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$checks = @(
    @{ Name = "Syntax"; Script = "check-syntax.ps1"; Critical = $true },
    @{ Name = "UTF-8 BOM"; Script = "check-bom.ps1"; Critical = $true },
    @{ Name = "Emoji Corruption"; Script = "check-emoji-corruption.ps1"; Critical = $true },
    @{ Name = "Launcher Fields"; Script = "check-launcher-fields.ps1"; Critical = $true },
    @{ Name = "Orphan Scripts"; Script = "check-orphans.ps1"; Critical = $false },
    @{ Name = "Definition Cross-Ref"; Script = "check-definitions.ps1"; Critical = $false },
    @{ Name = "PSScriptAnalyzer"; Script = "check-psscriptanalyzer.ps1"; Critical = $false }
)

$results = @()
$criticalFailures = 0
$warnings = 0

foreach ($check in $checks) {
    $scriptPath = Join-Path $TestingDir $check.Script

    if (-not (Test-Path $scriptPath)) {
        Write-Host "[$($check.Name)] " -NoNewline
        Write-Host "SKIP" -ForegroundColor Yellow -NoNewline
        Write-Host " - Script not found: $($check.Script)"
        $results += [PSCustomObject]@{
            Check = $check.Name
            Status = "SKIP"
            Critical = $check.Critical
        }
        continue
    }

    Write-Host "[$($check.Name)] " -NoNewline
    Write-Host "Running..." -ForegroundColor Gray

    try {
        # Capture output and exit code
        $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $scriptPath 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            Write-Host "[$($check.Name)] " -NoNewline
            Write-Host "PASS" -ForegroundColor Green
            $results += [PSCustomObject]@{
                Check = $check.Name
                Status = "PASS"
                Critical = $check.Critical
            }
        } else {
            if ($check.Critical) {
                Write-Host "[$($check.Name)] " -NoNewline
                Write-Host "FAIL" -ForegroundColor Red
                $criticalFailures++
            } else {
                Write-Host "[$($check.Name)] " -NoNewline
                Write-Host "WARN" -ForegroundColor Yellow
                $warnings++
            }
            $results += [PSCustomObject]@{
                Check = $check.Name
                Status = if ($check.Critical) { "FAIL" } else { "WARN" }
                Critical = $check.Critical
            }

            # Show output for failures
            Write-Host $output -ForegroundColor Gray
        }
    } catch {
        Write-Host "[$($check.Name)] " -NoNewline
        Write-Host "ERROR" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Gray
        if ($check.Critical) { $criticalFailures++ } else { $warnings++ }
        $results += [PSCustomObject]@{
            Check = $check.Name
            Status = "ERROR"
            Critical = $check.Critical
        }
    }

    Write-Host ""
}

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$passed = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$failed = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
$warned = ($results | Where-Object { $_.Status -eq "WARN" }).Count
$skipped = ($results | Where-Object { $_.Status -eq "SKIP" }).Count
$errored = ($results | Where-Object { $_.Status -eq "ERROR" }).Count

Write-Host "Passed:  $passed" -ForegroundColor Green
if ($warned -gt 0) { Write-Host "Warned:  $warned" -ForegroundColor Yellow }
if ($failed -gt 0) { Write-Host "Failed:  $failed" -ForegroundColor Red }
if ($errored -gt 0) { Write-Host "Errored: $errored" -ForegroundColor Red }
if ($skipped -gt 0) { Write-Host "Skipped: $skipped" -ForegroundColor Gray }

Write-Host ""

if ($criticalFailures -gt 0) {
    Write-Host "VALIDATION FAILED - $criticalFailures critical issue(s)" -ForegroundColor Red
    exit 1
} elseif ($warnings -gt 0) {
    Write-Host "VALIDATION PASSED with $warnings warning(s)" -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "VALIDATION PASSED" -ForegroundColor Green
    exit 0
}
