<#
.SYNOPSIS
    Comprehensive test script for LevelIO-Common library deployed via Level.io.

.DESCRIPTION
    This script tests all 8 exported functions from the LevelIO-Common library
    when deployed and executed through Level.io RMM. It verifies:

    - Write-LevelLog      : Logging with all severity levels
    - Test-LevelAdmin     : Administrator privilege detection
    - Get-LevelDeviceInfo : System information gathering
    - Initialize-LevelScript : Tag gating and lockfile management
    - Remove-LevelLockFile   : Lockfile cleanup
    - Complete-LevelScript   : Script completion handling
    - Invoke-LevelScript     : Main execution wrapper
    - Invoke-LevelApiCall    : REST API call functionality

    The script downloads/updates the library from GitHub before testing,
    using the same auto-update pattern as production scripts.

    TEST RESULTS:
    - Exit 0: All tests passed (Success)
    - Exit 1: One or more tests failed (Alert)

.NOTES
    Version:          2025.12.27.13
    Target Platform:  Level.io RMM
    Exit Codes:       0 = Success (All Tests Passed) | 1 = Alert (Tests Failed)

    This script is designed to run on Level.io managed endpoints.
    It uses Level.io template variables for configuration.

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/LevelLib

.LINK
    https://github.com/coolnetworks/LevelLib

.EXAMPLE
    # Deploy via Level.io as a script
    # The script will automatically download the library and run all tests
    # Results are output to the Level.io script execution log
#>

# Test_From_Level.ps1
# Version: 2025.12.27.13
# Target: Level.io
# Tests all library functions when deployed via Level.io
# Exit 0 = Success (All Tests Passed) | Exit 1 = Alert (Tests Failed)
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/LevelLib
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# LIBRARY AUTO-UPDATE & IMPORT
# ============================================================
# This section mirrors the template's auto-update logic to ensure
# we're testing the same library version that production scripts use.

# Level.io custom fields
# $MspScratchFolder: Persistent storage folder on the endpoint
# $LibraryUrl: URL to download the LevelIO-Common library
$MspScratchFolder = "{{cf_msp_scratch_folder}}"
$LibraryUrl = "{{cf_ps_module_library_source}}"

# Default to official repo if custom field not set
if ([string]::IsNullOrWhiteSpace($LibraryUrl) -or $LibraryUrl -eq "{{cf_ps_module_library_source}}") {
    $LibraryUrl = "https://raw.githubusercontent.com/coolnetworks/LevelLib/main/LevelIO-Common.psm1"
}

# Library storage paths
$LibraryFolder = Join-Path -Path $MspScratchFolder -ChildPath "Libraries"
$LibraryPath = Join-Path -Path $LibraryFolder -ChildPath "LevelIO-Common.psm1"

# Create Libraries folder if needed
if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

# Function to extract version number from module content
# Matches "Version:" followed by version number (handles both .NOTES and comment styles)
function Get-ModuleVersion {
    param([string]$Content, [string]$Source = "unknown")
    if ($Content -match 'Version:\s*([\d\.]+)') {
        return $Matches[1]
    }
    throw "Could not parse version from $Source - invalid or corrupt library content"
}

# Check if library already exists locally and get its version
$NeedsUpdate = $false
$LocalVersion = $null
$LocalContent = $null
$BackupPath = "$LibraryPath.backup"

if (Test-Path $LibraryPath) {
    try {
        $LocalContent = Get-Content -Path $LibraryPath -Raw -ErrorAction Stop
        $LocalVersion = Get-ModuleVersion -Content $LocalContent -Source "local file"
    }
    catch {
        # Local file exists but is corrupt - force redownload
        Write-Host "[!] Local library corrupt - will redownload"
        $NeedsUpdate = $true
    }
}
else {
    # No local copy exists - must download
    $NeedsUpdate = $true
    Write-Host "[*] Library not found - downloading..."
}

# Attempt to fetch the latest version from GitHub
# Compare versions and update if a newer version is available
try {
    $RemoteContent = (Invoke-WebRequest -Uri $LibraryUrl -UseBasicParsing -TimeoutSec 10).Content
    $RemoteVersion = Get-ModuleVersion -Content $RemoteContent -Source "remote URL"

    # Compare versions using PowerShell's [version] type for proper semantic comparison
    if ($null -eq $LocalVersion -or [version]$RemoteVersion -gt [version]$LocalVersion) {
        $NeedsUpdate = $true
        if ($LocalVersion) {
            Write-Host "[*] Update available: $LocalVersion -> $RemoteVersion"
        }
    }

    # Download and save the new version if needed
    if ($NeedsUpdate) {
        # Backup working local copy before updating (if we have a valid one)
        if ($LocalVersion -and $LocalContent) {
            Set-Content -Path $BackupPath -Value $LocalContent -Force -ErrorAction Stop
        }

        # Write new version
        Set-Content -Path $LibraryPath -Value $RemoteContent -Force -ErrorAction Stop

        # Verify the new file is valid before removing backup
        try {
            $VerifyContent = Get-Content -Path $LibraryPath -Raw -ErrorAction Stop
            $null = Get-ModuleVersion -Content $VerifyContent -Source "downloaded file"
            # Success - remove backup
            if (Test-Path $BackupPath) {
                Remove-Item -Path $BackupPath -Force -ErrorAction SilentlyContinue
            }
            Write-Host "[+] Library updated to v$RemoteVersion"
        }
        catch {
            # New file is corrupt - restore backup
            if (Test-Path $BackupPath) {
                Write-Host "[!] Downloaded file corrupt - restoring backup"
                Move-Item -Path $BackupPath -Destination $LibraryPath -Force
            }
            throw "Downloaded library failed verification"
        }
    }
}
catch {
    # GitHub unreachable or remote content invalid
    # Clean up any leftover backup
    if (Test-Path $BackupPath) {
        Move-Item -Path $BackupPath -Destination $LibraryPath -Force -ErrorAction SilentlyContinue
    }

    if (!(Test-Path $LibraryPath) -or $null -eq $LocalVersion) {
        # No valid local copy and can't download - fatal error
        Write-Host "[X] FATAL: Cannot download library and no valid local copy exists"
        Write-Host "[X] Error: $($_.Exception.Message)"
        exit 1
    }
    # Valid local copy exists - continue with potentially outdated version
    Write-Host "[!] Could not check for updates (using local v$LocalVersion)"
}

# Import the library for testing
# Use New-Module with ScriptBlock to bypass execution policy while maintaining module context
$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "LevelIO-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

# ============================================================
# TEST CONFIGURATION
# ============================================================
# Test result tracking structure
# Accumulates pass/fail counts and detailed test information

$global:TestResults = @{
    Passed = 0      # Count of passed tests
    Failed = 0      # Count of failed tests
    Tests  = @()    # Array of individual test results
}

# Helper function to record and display test results
# Parameters:
#   TestName : Descriptive name of the test
#   Passed   : Boolean indicating pass/fail
#   Details  : Optional additional information
function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )

    # Format status indicator (no color - Level.io captures plain text)
    $Status = if ($Passed) { "[PASS]" } else { "[FAIL]" }
    Write-Host "$Status $TestName"
    if ($Details) { Write-Host "       $Details" }

    # Update counters and record test
    if ($Passed) { $global:TestResults.Passed++ } else { $global:TestResults.Failed++ }
    $global:TestResults.Tests += @{ Name = $TestName; Passed = $Passed; Details = $Details }
}

# ============================================================
# TEST SUITE
# ============================================================
Write-Host ""
Write-Host "========================================"
Write-Host "LevelIO-Common Library Test Suite"
Write-Host "Running on Level.io endpoint"
Write-Host "========================================"
Write-Host ""

# Create isolated temp folder for testing
# Uses GUID suffix to avoid conflicts with concurrent executions
$TestScratchFolder = Join-Path -Path $env:TEMP -ChildPath "LevelIO-Tests-$([guid]::NewGuid().ToString().Substring(0,8))"
New-Item -Path $TestScratchFolder -ItemType Directory -Force | Out-Null

# --- TEST 1: Write-LevelLog ---
# Tests logging function with all severity levels
Write-Host ""
Write-Host "--- Testing Write-LevelLog ---"

# Test each supported log level
$LogLevels = @("INFO", "WARN", "ERROR", "SUCCESS", "SKIP", "DEBUG")
foreach ($Level in $LogLevels) {
    try {
        Write-LevelLog "Test message for $Level level" -Level $Level
        Write-TestResult "Write-LevelLog with Level=$Level" $true
    }
    catch {
        Write-TestResult "Write-LevelLog with Level=$Level" $false $_.Exception.Message
    }
}

# Test default level (INFO when not specified)
try {
    Write-LevelLog "Test message with default level"
    Write-TestResult "Write-LevelLog with default level" $true
}
catch {
    Write-TestResult "Write-LevelLog with default level" $false $_.Exception.Message
}

# --- TEST 2: Test-LevelAdmin ---
# Verifies admin detection returns proper boolean
Write-Host ""
Write-Host "--- Testing Test-LevelAdmin ---"

try {
    $IsAdmin = Test-LevelAdmin
    $AdminType = $IsAdmin.GetType().Name
    $ValidResult = $AdminType -eq "Boolean"
    Write-TestResult "Test-LevelAdmin returns boolean" $ValidResult "IsAdmin=$IsAdmin, Type=$AdminType"
}
catch {
    Write-TestResult "Test-LevelAdmin returns boolean" $false $_.Exception.Message
}

# --- TEST 3: Get-LevelDeviceInfo ---
# Tests system information gathering
Write-Host ""
Write-Host "--- Testing Get-LevelDeviceInfo ---"

try {
    $DeviceInfo = Get-LevelDeviceInfo

    # Verify all 8 expected properties exist
    $ExpectedProps = @("Hostname", "Username", "Domain", "OS", "OSVersion", "IsAdmin", "PowerShell", "ScriptPID")
    $AllPropsExist = $true
    $MissingProps = @()

    foreach ($Prop in $ExpectedProps) {
        if (-not $DeviceInfo.ContainsKey($Prop)) {
            $AllPropsExist = $false
            $MissingProps += $Prop
        }
    }

    Write-TestResult "Get-LevelDeviceInfo returns all properties" $AllPropsExist $(if ($MissingProps) { "Missing: $($MissingProps -join ', ')" } else { "All 8 properties present" })

    # Validate specific property values against environment
    Write-TestResult "Get-LevelDeviceInfo.Hostname matches env" ($DeviceInfo.Hostname -eq $env:COMPUTERNAME) "Expected: $env:COMPUTERNAME, Got: $($DeviceInfo.Hostname)"
    Write-TestResult "Get-LevelDeviceInfo.Username matches env" ($DeviceInfo.Username -eq $env:USERNAME) "Expected: $env:USERNAME, Got: $($DeviceInfo.Username)"
    Write-TestResult "Get-LevelDeviceInfo.ScriptPID matches PID" ($DeviceInfo.ScriptPID -eq $PID) "Expected: $PID, Got: $($DeviceInfo.ScriptPID)"
    Write-TestResult "Get-LevelDeviceInfo.OS is not empty" (-not [string]::IsNullOrEmpty($DeviceInfo.OS)) "OS: $($DeviceInfo.OS)"
}
catch {
    Write-TestResult "Get-LevelDeviceInfo execution" $false $_.Exception.Message
}

# --- TEST 4: Initialize-LevelScript ---
# Tests script initialization with various configurations
Write-Host ""
Write-Host "--- Testing Initialize-LevelScript ---"

# Test 4a: Basic initialization with SkipTagCheck
try {
    # Fresh module import to reset state
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw; New-Module -Name "LevelIO-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    $Init = Initialize-LevelScript -ScriptName "TestScript1" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -SkipTagCheck

    Write-TestResult "Initialize-LevelScript basic init" ($Init.Success -eq $true) "Reason: $($Init.Reason)"

    # Verify lockfile creation
    $LockFilePath = Join-Path -Path $TestScratchFolder -ChildPath "lockfiles\TestScript1.lock"
    Write-TestResult "Initialize-LevelScript creates lockfile" (Test-Path $LockFilePath) "Path: $LockFilePath"

    # Validate lockfile content structure
    if (Test-Path $LockFilePath) {
        $LockContent = Get-Content $LockFilePath -Raw | ConvertFrom-Json
        Write-TestResult "Lockfile contains PID" ($LockContent.PID -eq $PID) "PID in lockfile: $($LockContent.PID)"
        Write-TestResult "Lockfile contains ScriptName" ($LockContent.ScriptName -eq "TestScript1") "ScriptName: $($LockContent.ScriptName)"
    }
}
catch {
    Write-TestResult "Initialize-LevelScript basic init" $false $_.Exception.Message
}

# Test 4b: Tag blocking functionality with default ❌ tag
try {
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw; New-Module -Name "LevelIO-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    # Device has ❌ tag which is in BlockingTags - should fail
    $TestTags = "Production, Windows 11, ❌"
    $Init = Initialize-LevelScript -ScriptName "TestScript2" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -DeviceTags $TestTags `
                                   -BlockingTags @("❌")

    Write-TestResult "Initialize-LevelScript blocks on ❌ tag" ($Init.Success -eq $false -and $Init.Reason -eq "TagBlocked") "❌ IS set - if this was not a test, the script would exit here"
}
catch {
    Write-TestResult "Initialize-LevelScript blocks on ❌ tag" $false $_.Exception.Message
}

# Test 4c: SkipTagCheck bypasses ❌ tag blocking
try {
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw; New-Module -Name "LevelIO-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    # Has ❌ tag but SkipTagCheck should allow execution
    $TestTags = "Production, ❌"
    $Init = Initialize-LevelScript -ScriptName "TestScript3" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -DeviceTags $TestTags `
                                   -BlockingTags @("❌") `
                                   -SkipTagCheck

    Write-TestResult "Initialize-LevelScript -SkipTagCheck bypasses ❌" ($Init.Success -eq $true) "❌ tag IS set in tags: '$TestTags' - Bypassed with -SkipTagCheck"
}
catch {
    Write-TestResult "Initialize-LevelScript -SkipTagCheck bypasses ❌" $false $_.Exception.Message
}

# Test 4d: SkipLockFile prevents lockfile creation
try {
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw; New-Module -Name "LevelIO-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    $Init = Initialize-LevelScript -ScriptName "TestScript4" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -SkipTagCheck `
                                   -SkipLockFile

    $LockFilePath = Join-Path -Path $TestScratchFolder -ChildPath "lockfiles\TestScript4.lock"
    Write-TestResult "Initialize-LevelScript -SkipLockFile" ($Init.Success -eq $true -and -not (Test-Path $LockFilePath)) "No lockfile should be created"
}
catch {
    Write-TestResult "Initialize-LevelScript -SkipLockFile" $false $_.Exception.Message
}

# Test 4e: Stale lockfile cleanup (PID no longer running)
try {
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw; New-Module -Name "LevelIO-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    # Create a lockfile with a non-existent PID (stale lock)
    $StaleLockDir = Join-Path -Path $TestScratchFolder -ChildPath "lockfiles"
    if (!(Test-Path $StaleLockDir)) { New-Item -Path $StaleLockDir -ItemType Directory -Force | Out-Null }
    $StaleLockFile = Join-Path -Path $StaleLockDir -ChildPath "TestScript5.lock"

    # PID 999999999 should not exist on any system
    @{ PID = 999999999; ScriptName = "TestScript5"; StartedAt = (Get-Date).ToString("o") } | ConvertTo-Json | Set-Content $StaleLockFile

    $Init = Initialize-LevelScript -ScriptName "TestScript5" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -SkipTagCheck

    Write-TestResult "Initialize-LevelScript stale lockfile cleanup" ($Init.Success -eq $true) "Should remove stale lock and proceed"
}
catch {
    Write-TestResult "Initialize-LevelScript stale lockfile cleanup" $false $_.Exception.Message
}

# --- TEST 5: Remove-LevelLockFile ---
# Tests lockfile removal functionality
Write-Host ""
Write-Host "--- Testing Remove-LevelLockFile ---"

try {
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw; New-Module -Name "LevelIO-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    # Create a lockfile via initialization
    $Init = Initialize-LevelScript -ScriptName "TestScript6" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -SkipTagCheck

    $LockFilePath = Join-Path -Path $TestScratchFolder -ChildPath "lockfiles\TestScript6.lock"
    $ExistsBefore = Test-Path $LockFilePath

    # Remove the lockfile
    Remove-LevelLockFile

    $ExistsAfter = Test-Path $LockFilePath
    Write-TestResult "Remove-LevelLockFile removes lockfile" ($ExistsBefore -and -not $ExistsAfter) "Before: $ExistsBefore, After: $ExistsAfter"
}
catch {
    Write-TestResult "Remove-LevelLockFile removes lockfile" $false $_.Exception.Message
}

# --- TEST 6: Function Exports ---
# Verifies Complete-LevelScript and Invoke-LevelScript are exported
Write-Host ""
Write-Host "--- Testing Function Exports ---"

try {
    $FunctionExists = Get-Command Complete-LevelScript -ErrorAction Stop
    Write-TestResult "Complete-LevelScript function exists" ($null -ne $FunctionExists)
}
catch {
    Write-TestResult "Complete-LevelScript function exists" $false $_.Exception.Message
}

try {
    $FunctionExists = Get-Command Invoke-LevelScript -ErrorAction Stop
    Write-TestResult "Invoke-LevelScript function exists" ($null -ne $FunctionExists)
}
catch {
    Write-TestResult "Invoke-LevelScript function exists" $false $_.Exception.Message
}

# --- TEST 7: Invoke-LevelApiCall ---
# Tests REST API call functionality
Write-Host ""
Write-Host "--- Testing Invoke-LevelApiCall ---"

try {
    $FunctionExists = Get-Command Invoke-LevelApiCall -ErrorAction Stop
    Write-TestResult "Invoke-LevelApiCall function exists" ($null -ne $FunctionExists)

    # Test GET request to public API (httpbin.org)
    $ApiResult = Invoke-LevelApiCall -Uri "https://httpbin.org/get" -ApiKey "test-key" -Method "GET" -TimeoutSec 10
    Write-TestResult "Invoke-LevelApiCall GET request" ($ApiResult.Success -eq $true) $(if ($ApiResult.Success) { "Response received" } else { $ApiResult.Error })

    # Test error handling with invalid domain
    $ApiResultFail = Invoke-LevelApiCall -Uri "https://invalid.nonexistent.domain.test/api" -ApiKey "test" -Method "GET" -TimeoutSec 5
    Write-TestResult "Invoke-LevelApiCall handles errors" ($ApiResultFail.Success -eq $false) "Returns Success=false on failure"
}
catch {
    Write-TestResult "Invoke-LevelApiCall function exists" $false $_.Exception.Message
}

# --- TEST 8: Module Exports ---
# Comprehensive check that all expected functions are exported
Write-Host ""
Write-Host "--- Testing Module Exports ---"

# List of all functions that should be exported by the module
$ExpectedExports = @(
    'Initialize-LevelScript',
    'Write-LevelLog',
    'Invoke-LevelScript',
    'Remove-LevelLockFile',
    'Complete-LevelScript',
    'Test-LevelAdmin',
    'Get-LevelDeviceInfo',
    'Invoke-LevelApiCall'
)

# Fresh import to get accurate export list
Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
$ModuleContent = Get-Content -Path $LibraryPath -Raw; New-Module -Name "LevelIO-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

$ExportedFunctions = (Get-Module LevelIO-Common).ExportedFunctions.Keys

# Test each expected function
foreach ($FuncName in $ExpectedExports) {
    $IsExported = $ExportedFunctions -contains $FuncName
    Write-TestResult "Module exports $FuncName" $IsExported
}

# ============================================================
# CLEANUP
# ============================================================
Write-Host ""
Write-Host "--- Cleanup ---"

# Remove test scratch folder and all contents
try {
    Remove-Item -Path $TestScratchFolder -Recurse -Force -ErrorAction Stop
    Write-TestResult "Test folder cleanup" $true "Removed: $TestScratchFolder"
}
catch {
    Write-TestResult "Test folder cleanup" $false $_.Exception.Message
}

# ============================================================
# TEST SUMMARY
# ============================================================
Write-Host ""
Write-Host "========================================"
Write-Host "TEST RESULTS SUMMARY"
Write-Host "========================================"
Write-Host "Passed: $($global:TestResults.Passed)"
Write-Host "Failed: $($global:TestResults.Failed)"
Write-Host "Total:  $($global:TestResults.Passed + $global:TestResults.Failed)"
Write-Host "========================================"
Write-Host ""

# Report failed tests if any
if ($global:TestResults.Failed -gt 0) {
    Write-Host "Failed Tests:"
    $global:TestResults.Tests | Where-Object { -not $_.Passed } | ForEach-Object {
        Write-Host "  - $($_.Name)"
        if ($_.Details) { Write-Host "    $($_.Details)" }
    }
    Write-Host ""
    exit 1
}

Write-Host "All tests passed!"
exit 0
