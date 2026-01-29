<#
.SYNOPSIS
    Tests the COOLForge_Lib auto-update mechanism using the dev branch.

.DESCRIPTION
    This script simulates what happens on a Level.io endpoint when a launcher runs.
    It tests:
    - Library download from GitHub dev branch
    - Version checking and updates
    - MD5 checksum verification
    - Script download and execution
    - Emoji handling in script names

    Run this locally to verify the dev branch works before pushing to main.

.NOTES
    Version:    2025.12.29.01
    Target:     Local development testing
    Branch:     dev (hardcoded for testing)

.EXAMPLE
    .\testing\Test_AutoUpdate_Dev.ps1
#>

$ErrorActionPreference = "Stop"

# ============================================================
# TEST CONFIGURATION
# ============================================================
$TestBranch = "dev"
$GitHubRepo = "coolnetworks/COOLForge"
$BaseUrl = "https://raw.githubusercontent.com/$GitHubRepo/$TestBranch"
$LibraryUrl = "$BaseUrl/modules/COOLForge-Common.psm1"
$MD5SumsUrl = "$BaseUrl/MD5SUMS"
$ScriptsBaseUrl = "$BaseUrl/scripts"

# Create temp folder for testing
$TestFolder = Join-Path $env:TEMP "COOLForge_AutoUpdate_Test_$(Get-Random)"
New-Item -Path $TestFolder -ItemType Directory -Force | Out-Null
$LibraryFolder = Join-Path $TestFolder "Libraries"
$ScriptsFolder = Join-Path $TestFolder "Scripts"
New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
New-Item -Path $ScriptsFolder -ItemType Directory -Force | Out-Null

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "COOLForge_Lib Auto-Update Test (Dev Branch)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test folder: $TestFolder"
Write-Host "Branch: $TestBranch"
Write-Host "Library URL: $LibraryUrl"
Write-Host ""

$TestsPassed = 0
$TestsFailed = 0

function Test-Result {
    param([string]$Name, [bool]$Passed, [string]$Details = "")
    if ($Passed) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
        if ($Details) { Write-Host "       $Details" -ForegroundColor Gray }
        $script:TestsPassed++
    } else {
        Write-Host "[FAIL] $Name" -ForegroundColor Red
        if ($Details) { Write-Host "       $Details" -ForegroundColor Red }
        $script:TestsFailed++
    }
}

# ============================================================
# TEST 1: Download MD5SUMS
# ============================================================
Write-Host ""
Write-Host "--- Test 1: MD5SUMS Download ---" -ForegroundColor Yellow

$MD5SumsContent = $null
try {
    $Response = Invoke-WebRequest -Uri $MD5SumsUrl -UseBasicParsing -TimeoutSec 10
    $MD5SumsContent = $Response.Content
    Test-Result "MD5SUMS download" $true "Retrieved $(($MD5SumsContent -split "`n").Count) lines"

    # Parse and display checksums
    $Checksums = @{}
    foreach ($line in $MD5SumsContent -split "`n") {
        $line = $line.Trim()
        if ($line -match '^([a-f0-9]{32})\s+(.+)$') {
            $Checksums[$Matches[2].Trim()] = $Matches[1]
        }
    }
    Test-Result "MD5SUMS parsing" ($Checksums.Count -gt 0) "Found $($Checksums.Count) checksums"
}
catch {
    Test-Result "MD5SUMS download" $false $_.Exception.Message
}

# ============================================================
# TEST 2: Download Library
# ============================================================
Write-Host ""
Write-Host "--- Test 2: Library Download ---" -ForegroundColor Yellow

$LibraryPath = Join-Path $LibraryFolder "COOLForge-Common.psm1"
$LibraryContent = $null
$LibraryVersion = $null

try {
    $Response = Invoke-WebRequest -Uri $LibraryUrl -UseBasicParsing -TimeoutSec 10
    $LibraryContent = $Response.Content
    Test-Result "Library download" $true "Downloaded $($LibraryContent.Length) bytes"

    # Extract version
    if ($LibraryContent -match 'Version:\s*([\d\.]+)') {
        $LibraryVersion = $Matches[1]
        Test-Result "Library version extraction" $true "Version: $LibraryVersion"
    } else {
        Test-Result "Library version extraction" $false "Could not find version in content"
    }

    # Verify MD5
    if ($MD5SumsContent) {
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($LibraryContent)
        $hash = $md5.ComputeHash($bytes)
        $ActualMD5 = ([BitConverter]::ToString($hash) -replace '-', '').ToLower()

        $ExpectedMD5 = $Checksums["modules/COOLForge-Common.psm1"]
        if ($ExpectedMD5) {
            $Match = ($ActualMD5 -eq $ExpectedMD5)
            Test-Result "Library MD5 checksum" $Match "Expected: $ExpectedMD5, Got: $ActualMD5"
        } else {
            Test-Result "Library MD5 checksum" $false "No checksum in MD5SUMS for modules/COOLForge-Common.psm1"
        }
    }

    # Save to test folder
    Set-Content -Path $LibraryPath -Value $LibraryContent -Encoding UTF8
    Test-Result "Library save to disk" (Test-Path $LibraryPath) "Saved to: $LibraryPath"
}
catch {
    Test-Result "Library download" $false $_.Exception.Message
}

# ============================================================
# TEST 3: Import Library Module
# ============================================================
Write-Host ""
Write-Host "--- Test 3: Library Import ---" -ForegroundColor Yellow

try {
    $ModuleContent = Get-Content -Path $LibraryPath -Raw
    New-Module -Name "COOLForge-Common-Test" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force
    Test-Result "Library import" $true "Module imported successfully"

    # Check exported functions
    $ExpectedFunctions = @(
        "Initialize-LevelScript",
        "Write-LevelLog",
        "Invoke-LevelScript",
        "Complete-LevelScript",
        "Remove-LevelLockFile",
        "Test-LevelAdmin",
        "Get-LevelDeviceInfo",
        "Invoke-LevelApiCall",
        "Repair-LevelEmoji",
        "Get-LevelUrlEncoded"
    )

    $MissingFunctions = @()
    foreach ($func in $ExpectedFunctions) {
        if (-not (Get-Command -Name $func -ErrorAction SilentlyContinue)) {
            $MissingFunctions += $func
        }
    }

    if ($MissingFunctions.Count -eq 0) {
        Test-Result "Exported functions" $true "All $($ExpectedFunctions.Count) functions available"
    } else {
        Test-Result "Exported functions" $false "Missing: $($MissingFunctions -join ', ')"
    }
}
catch {
    Test-Result "Library import" $false $_.Exception.Message
}

# ============================================================
# TEST 4: Emoji Repair Function
# ============================================================
Write-Host ""
Write-Host "--- Test 4: Emoji Handling ---" -ForegroundColor Yellow

try {
    # Test that emojis pass through correctly
    $TestEmojis = @(
        @{ Input = "👀Test Show Versions.ps1"; Expected = "👀Test Show Versions.ps1" },
        @{ Input = "⛔Force Remove Anydesk.ps1"; Expected = "⛔Force Remove Anydesk.ps1" },
        @{ Input = "🔧Fix Windows 11 Services.ps1"; Expected = "🔧Fix Windows 11 Services.ps1" }
    )

    $AllPassed = $true
    foreach ($test in $TestEmojis) {
        $Result = Repair-LevelEmoji -Text $test.Input
        if ($Result -ne $test.Expected) {
            $AllPassed = $false
            Write-Host "       Emoji mismatch: '$($test.Input)' -> '$Result'" -ForegroundColor Red
        }
    }
    Test-Result "Emoji passthrough" $AllPassed "Clean emojis pass through unchanged"

    # Test URL encoding
    $TestUrl = Get-LevelUrlEncoded -Text "👀Test Show Versions.ps1"
    $ExpectedPattern = "%F0%9F%91%80"  # UTF-8 encoding of 👀
    Test-Result "URL encoding" ($TestUrl -like "*$ExpectedPattern*") "Encoded: $TestUrl"
}
catch {
    Test-Result "Emoji handling" $false $_.Exception.Message
}

# ============================================================
# TEST 5: Script Download
# ============================================================
Write-Host ""
Write-Host "--- Test 5: Script Download ---" -ForegroundColor Yellow

$TestScriptName = "👀Test Show Versions.ps1"
$EncodedName = Get-LevelUrlEncoded -Text $TestScriptName
$ScriptUrl = "$ScriptsBaseUrl/$EncodedName"
$ScriptPath = Join-Path $ScriptsFolder $TestScriptName

try {
    Write-Host "       URL: $ScriptUrl" -ForegroundColor Gray
    $Response = Invoke-WebRequest -Uri $ScriptUrl -UseBasicParsing -TimeoutSec 15
    $ScriptContent = $Response.Content
    Test-Result "Script download" $true "Downloaded $($ScriptContent.Length) bytes"

    # Verify MD5
    if ($MD5SumsContent) {
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($ScriptContent)
        $hash = $md5.ComputeHash($bytes)
        $ActualMD5 = ([BitConverter]::ToString($hash) -replace '-', '').ToLower()

        $ExpectedMD5 = $Checksums["scripts/$TestScriptName"]
        if ($ExpectedMD5) {
            $Match = ($ActualMD5 -eq $ExpectedMD5)
            Test-Result "Script MD5 checksum" $Match "Expected: $ExpectedMD5, Got: $ActualMD5"
        } else {
            Write-Host "       [WARN] No checksum in MD5SUMS for scripts/$TestScriptName" -ForegroundColor Yellow
        }
    }

    # Save to test folder
    Set-Content -Path $ScriptPath -Value $ScriptContent -Encoding UTF8
    Test-Result "Script save to disk" (Test-Path $ScriptPath) "Saved to: $ScriptPath"

    # Check script has version
    if ($ScriptContent -match 'Version:\s*([\d\.]+)') {
        Test-Result "Script version" $true "Version: $($Matches[1])"
    } else {
        Write-Host "       [WARN] Script has no version number" -ForegroundColor Yellow
    }
}
catch {
    Test-Result "Script download" $false $_.Exception.Message
}

# ============================================================
# TEST 6: Version Comparison Logic
# ============================================================
Write-Host ""
Write-Host "--- Test 6: Version Comparison ---" -ForegroundColor Yellow

try {
    # Simulate version comparison
    $OldVersion = "2025.12.27.01"
    $NewVersion = "2025.12.29.02"

    $NeedsUpdate = [version]$NewVersion -gt [version]$OldVersion
    Test-Result "Version comparison" $NeedsUpdate "$OldVersion -> $NewVersion = Update needed"

    # Same version
    $SameCheck = -not ([version]$OldVersion -gt [version]$OldVersion)
    Test-Result "Same version check" $SameCheck "$OldVersion = $OldVersion (no update)"
}
catch {
    Test-Result "Version comparison" $false $_.Exception.Message
}

# ============================================================
# TEST 7: Simulate Full Launcher Flow
# ============================================================
Write-Host ""
Write-Host "--- Test 7: Full Launcher Simulation ---" -ForegroundColor Yellow

try {
    # This simulates what a launcher does
    $SimMspScratchFolder = $TestFolder
    $SimLibraryFolder = Join-Path $SimMspScratchFolder "Libraries"
    $SimLibraryPath = Join-Path $SimLibraryFolder "COOLForge-Common.psm1"

    # Library should already exist from earlier tests
    $LibraryExists = Test-Path $SimLibraryPath
    Test-Result "Launcher: Library exists" $LibraryExists "Path: $SimLibraryPath"

    # Import module
    if ($LibraryExists) {
        $Content = Get-Content $SimLibraryPath -Raw
        Remove-Module "COOLForge-Common-Sim" -Force -ErrorAction SilentlyContinue
        New-Module -Name "COOLForge-Common-Sim" -ScriptBlock ([scriptblock]::Create($Content)) | Import-Module -Force

        $FuncExists = $null -ne (Get-Command "Write-LevelLog" -ErrorAction SilentlyContinue)
        Test-Result "Launcher: Module functions available" $FuncExists "Write-LevelLog accessible"
    }

    # Test a logging call
    Write-LevelLog "Test message from launcher simulation" -Level "INFO"
    Test-Result "Launcher: Logging works" $true "Write-LevelLog executed"
}
catch {
    Test-Result "Launcher simulation" $false $_.Exception.Message
}

# ============================================================
# TEST 8: Check All Scripts Downloadable
# ============================================================
Write-Host ""
Write-Host "--- Test 8: All Scripts Downloadable ---" -ForegroundColor Yellow

$ScriptsToTest = @(
    "👀Test Show Versions.ps1",
    "👀Test Variable Output.ps1",
    "⛔Force Remove Anydesk.ps1",
    "🔧Fix Windows 11 Services.ps1"
)

foreach ($scriptName in $ScriptsToTest) {
    try {
        $encoded = Get-LevelUrlEncoded -Text $scriptName
        $url = "$ScriptsBaseUrl/$encoded"
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
        Test-Result "Download: $scriptName" ($response.StatusCode -eq 200) "$($response.Content.Length) bytes"
    }
    catch {
        Test-Result "Download: $scriptName" $false $_.Exception.Message
    }
}

# ============================================================
# CLEANUP
# ============================================================
Write-Host ""
Write-Host "--- Cleanup ---" -ForegroundColor Yellow

try {
    Remove-Module "COOLForge-Common-Test" -Force -ErrorAction SilentlyContinue
    Remove-Module "COOLForge-Common-Sim" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TestFolder -Recurse -Force -ErrorAction SilentlyContinue
    Test-Result "Cleanup" $true "Test folder removed"
}
catch {
    Test-Result "Cleanup" $false $_.Exception.Message
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "TEST RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Passed: $TestsPassed" -ForegroundColor Green
Write-Host "Failed: $TestsFailed" -ForegroundColor $(if ($TestsFailed -gt 0) { "Red" } else { "Green" })
Write-Host "Total:  $($TestsPassed + $TestsFailed)"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($TestsFailed -gt 0) {
    Write-Host "Some tests failed! Review errors above before pushing to main." -ForegroundColor Red
    Write-Host ""
    Write-Host "If tests pass here but fail in Level.io, check:" -ForegroundColor Yellow
    Write-Host "  1. Custom field values are set correctly" -ForegroundColor Yellow
    Write-Host "  2. Device has internet access to GitHub" -ForegroundColor Yellow
    Write-Host "  3. Emoji encoding in Level.io script deployment" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "All tests passed! Dev branch is ready for Level.io testing." -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Push dev branch: git push origin dev" -ForegroundColor White
    Write-Host "  2. Test in Level.io with version pin: cf_coolforge_pin_psmodule_to_version = dev" -ForegroundColor White
    Write-Host "  3. If Level.io test passes, merge to main" -ForegroundColor White
    exit 0
}
