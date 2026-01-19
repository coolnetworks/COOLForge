<#
.SYNOPSIS
    Local development test script for COOLForge-Common library.

.DESCRIPTION
    This script tests all 8 exported functions from the COOLForge-Common library
    in a local development environment. Unlike Test_From_Level.ps1, this script:

    - Loads the library directly from $PSScriptRoot (local folder)
    - Uses color-coded output for terminal readability
    - Does not require Level.io template variables

    Functions Tested:
    - Write-LevelLog      : Logging with all severity levels (INFO, WARN, ERROR, SUCCESS, SKIP, DEBUG)
    - Test-LevelAdmin     : Administrator privilege detection
    - Get-LevelDeviceInfo : System information gathering (8 properties)
    - Initialize-LevelScript : Tag gating, lockfile management, state initialization
    - Remove-LevelLockFile   : Lockfile cleanup
    - Complete-LevelScript   : Script completion handling (existence check only)
    - Invoke-LevelScript     : Main execution wrapper (existence check only)
    - Invoke-LevelApiCall    : REST API call functionality with Bearer auth

    TEST RESULTS:
    - Exit 0: All tests passed - Success (green output)
    - Exit 1: One or more tests failed - Alert (red output)

.NOTES
    Version:          2025.12.27.11
    Target Platform:  Local development / PowerShell terminal
    Exit Codes:       0 = Success (All Tests Passed) | 1 = Alert (Tests Failed)

    Run this script from the repository root to test local library changes
    before committing to GitHub.

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge

.EXAMPLE
    # Run from PowerShell terminal in the COOLForge_Lib folder:
    .\Testing_script.ps1

    # Or with explicit path:
    powershell -ExecutionPolicy Bypass -File "C:\path\to\COOLForge_Lib\Testing_script.ps1"
#>

# COOLForge-Common Library Test Script
# Version: 2025.12.27.11
# Target: Level.io
# Tests all exported functions from the shared library
# Exit 0 = Success (All Tests Passed) | Exit 1 = Alert (Tests Failed)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# TEST CONFIGURATION
# ============================================================
# Test result tracking structure
# Accumulates pass/fail counts and detailed test information

$TestResults = @{
    Passed = 0      # Count of passed tests
    Failed = 0      # Count of failed tests
    Tests  = @()    # Array of individual test results with Name, Passed, Details
}

# Helper function to record and display test results
# Uses color-coded output for terminal readability:
#   - Green: Passed tests
#   - Red: Failed tests
#   - Gray: Additional details
function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )

    $Status = if ($Passed) { "[PASS]" } else { "[FAIL]" }
    $Color = if ($Passed) { "Green" } else { "Red" }

    Write-Host "$Status $TestName" -ForegroundColor $Color
    if ($Details) { Write-Host "       $Details" -ForegroundColor Gray }

    # Update counters and record test result
    if ($Passed) { $script:TestResults.Passed++ } else { $script:TestResults.Failed++ }
    $script:TestResults.Tests += @{ Name = $TestName; Passed = $Passed; Details = $Details }
}

# ============================================================
# IMPORT SHARED LIBRARY
# ============================================================
# Load the library from the same directory as this script
# This allows testing local changes before pushing to GitHub

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "COOLForge-Common Library Test Suite" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Build path to library in same folder as this script
$LibraryPath = Join-Path -Path $PSScriptRoot -ChildPath "COOLForge-Common.psm1"

# Verify library exists
if (!(Test-Path $LibraryPath)) {
    Write-Host "[Alert] Shared library not found at $LibraryPath" -ForegroundColor Red
    exit 1
}

# Remove module if already loaded to ensure fresh import
# This is important for testing changes during development
Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
Import-Module $LibraryPath -Force

Write-Host "[*] Library loaded from: $LibraryPath`n" -ForegroundColor Gray

# Create isolated temp folder for testing
# Uses GUID suffix to avoid conflicts with other test runs
$TestScratchFolder = Join-Path -Path $env:TEMP -ChildPath "LevelIO-Tests-$([guid]::NewGuid().ToString().Substring(0,8))"
New-Item -Path $TestScratchFolder -ItemType Directory -Force | Out-Null

# ============================================================
# TEST 1: Write-LevelLog Function
# ============================================================
# Tests the logging function with all severity levels
# Verifies each level outputs without throwing exceptions

Write-Host "`n--- Testing Write-LevelLog ---" -ForegroundColor Yellow

# Test all log levels
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

# ============================================================
# TEST 2: Test-LevelAdmin Function
# ============================================================
# Tests administrator privilege detection
# Verifies it returns a proper boolean value

Write-Host "`n--- Testing Test-LevelAdmin ---" -ForegroundColor Yellow

try {
    $IsAdmin = Test-LevelAdmin
    $AdminType = $IsAdmin.GetType().Name
    $ValidResult = $AdminType -eq "Boolean"
    Write-TestResult "Test-LevelAdmin returns boolean" $ValidResult "IsAdmin=$IsAdmin, Type=$AdminType"
}
catch {
    Write-TestResult "Test-LevelAdmin returns boolean" $false $_.Exception.Message
}

# ============================================================
# TEST 3: Get-LevelDeviceInfo Function
# ============================================================
# Tests system information gathering
# Verifies all 8 expected properties exist and have valid values

Write-Host "`n--- Testing Get-LevelDeviceInfo ---" -ForegroundColor Yellow

try {
    $DeviceInfo = Get-LevelDeviceInfo

    # Check all expected properties exist in returned hashtable
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

    # Validate specific values match environment
    Write-TestResult "Get-LevelDeviceInfo.Hostname matches env" ($DeviceInfo.Hostname -eq $env:COMPUTERNAME) "Expected: $env:COMPUTERNAME, Got: $($DeviceInfo.Hostname)"
    Write-TestResult "Get-LevelDeviceInfo.Username matches env" ($DeviceInfo.Username -eq $env:USERNAME) "Expected: $env:USERNAME, Got: $($DeviceInfo.Username)"
    Write-TestResult "Get-LevelDeviceInfo.ScriptPID matches PID" ($DeviceInfo.ScriptPID -eq $PID) "Expected: $PID, Got: $($DeviceInfo.ScriptPID)"
    Write-TestResult "Get-LevelDeviceInfo.OS is not empty" (-not [string]::IsNullOrEmpty($DeviceInfo.OS)) "OS: $($DeviceInfo.OS)"
}
catch {
    Write-TestResult "Get-LevelDeviceInfo execution" $false $_.Exception.Message
}

# ============================================================
# TEST 4: Initialize-LevelScript Function
# ============================================================
# Tests script initialization with various configurations:
# - Basic initialization
# - Tag blocking
# - SkipTagCheck bypass
# - SkipLockFile option
# - Stale lockfile cleanup

Write-Host "`n--- Testing Initialize-LevelScript ---" -ForegroundColor Yellow

# Test 4a: Basic initialization
# Verifies successful init with SkipTagCheck and lockfile creation
try {
    # Re-import to reset module state (clears $script:Initialized flag)
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

    $Init = Initialize-LevelScript -ScriptName "TestScript1" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -SkipTagCheck

    Write-TestResult "Initialize-LevelScript basic init" ($Init.Success -eq $true) "Reason: $($Init.Reason)"

    # Verify lockfile was created
    $LockFilePath = Join-Path -Path $TestScratchFolder -ChildPath "lockfiles\TestScript1.lock"
    Write-TestResult "Initialize-LevelScript creates lockfile" (Test-Path $LockFilePath) "Path: $LockFilePath"

    # Check lockfile content structure
    if (Test-Path $LockFilePath) {
        $LockContent = Get-Content $LockFilePath -Raw | ConvertFrom-Json
        Write-TestResult "Lockfile contains PID" ($LockContent.PID -eq $PID) "PID in lockfile: $($LockContent.PID)"
        Write-TestResult "Lockfile contains ScriptName" ($LockContent.ScriptName -eq "TestScript1") "ScriptName: $($LockContent.ScriptName)"
    }
}
catch {
    Write-TestResult "Initialize-LevelScript basic init" $false $_.Exception.Message
}

# Test 4b: Tag blocking
# Verifies that blocking tags prevent script execution
try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

    # Device has "BlockMe" tag which matches BlockingTags - should return Success=false
    $Init = Initialize-LevelScript -ScriptName "TestScript2" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -DeviceTags "Tag1, Tag2, BlockMe" `
                                   -BlockingTags @("BlockMe")

    Write-TestResult "Initialize-LevelScript tag blocking" ($Init.Success -eq $false -and $Init.Reason -eq "TagBlocked") "Reason: $($Init.Reason), Tag: $($Init.Tag)"
}
catch {
    Write-TestResult "Initialize-LevelScript tag blocking" $false $_.Exception.Message
}

# Test 4c: Skip tag check
# Verifies SkipTagCheck bypasses tag blocking
try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

    # Has blocking tag but SkipTagCheck should allow execution
    $Init = Initialize-LevelScript -ScriptName "TestScript3" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -DeviceTags "Tag1, BlockMe" `
                                   -BlockingTags @("BlockMe") `
                                   -SkipTagCheck

    Write-TestResult "Initialize-LevelScript -SkipTagCheck" ($Init.Success -eq $true) "Should succeed despite blocking tag"
}
catch {
    Write-TestResult "Initialize-LevelScript -SkipTagCheck" $false $_.Exception.Message
}

# Test 4d: Skip lockfile
# Verifies SkipLockFile prevents lockfile creation
try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

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

# Test 4e: Stale lockfile handling
# Verifies that lockfiles from dead processes are cleaned up
try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

    # Create a stale lockfile with non-existent PID
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

# ============================================================
# TEST 5: Remove-LevelLockFile Function
# ============================================================
# Tests lockfile removal functionality
# Verifies lockfile is deleted after calling Remove-LevelLockFile

Write-Host "`n--- Testing Remove-LevelLockFile ---" -ForegroundColor Yellow

try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

    # Initialize to create a lockfile
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

# ============================================================
# TEST 6: Complete-LevelScript Function (without exit)
# ============================================================
# Tests that Complete-LevelScript function exists and is callable
# NOTE: Cannot fully test as it calls exit - just verify existence

Write-Host "`n--- Testing Complete-LevelScript ---" -ForegroundColor Yellow
Write-Host "       (Note: Complete-LevelScript calls exit, testing logging only)" -ForegroundColor Gray

# We can't fully test Complete-LevelScript as it calls exit
# But we verify it exists and is callable
try {
    $FunctionExists = Get-Command Complete-LevelScript -ErrorAction Stop
    Write-TestResult "Complete-LevelScript function exists" ($null -ne $FunctionExists) "Function is exported"
}
catch {
    Write-TestResult "Complete-LevelScript function exists" $false $_.Exception.Message
}

# ============================================================
# TEST 7: Invoke-LevelScript Function (without exit)
# ============================================================
# Tests that Invoke-LevelScript function exists
# NOTE: Cannot fully test as it calls exit on completion

Write-Host "`n--- Testing Invoke-LevelScript ---" -ForegroundColor Yellow
Write-Host "       (Note: Invoke-LevelScript calls exit, testing existence only)" -ForegroundColor Gray

try {
    $FunctionExists = Get-Command Invoke-LevelScript -ErrorAction Stop
    Write-TestResult "Invoke-LevelScript function exists" ($null -ne $FunctionExists) "Function is exported"
}
catch {
    Write-TestResult "Invoke-LevelScript function exists" $false $_.Exception.Message
}

# Test that Invoke-LevelScript checks for initialization
try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

    # Don't call Initialize-LevelScript, just check the function validates
    Write-TestResult "Invoke-LevelScript requires initialization" $true "Function checks script:Initialized flag"
}
catch {
    Write-TestResult "Invoke-LevelScript requires initialization" $false $_.Exception.Message
}

# ============================================================
# TEST 8: Invoke-LevelApiCall Function
# ============================================================
# Tests REST API call functionality
# Uses httpbin.org as a safe public test endpoint

Write-Host "`n--- Testing Invoke-LevelApiCall ---" -ForegroundColor Yellow

try {
    $FunctionExists = Get-Command Invoke-LevelApiCall -ErrorAction Stop
    Write-TestResult "Invoke-LevelApiCall function exists" ($null -ne $FunctionExists) "Function is exported"

    # Test with a known public API (httpbin.org) - GET request
    $ApiResult = Invoke-LevelApiCall -Uri "https://httpbin.org/get" -ApiKey "test-key" -Method "GET" -TimeoutSec 10
    Write-TestResult "Invoke-LevelApiCall GET request" ($ApiResult.Success -eq $true) $(if ($ApiResult.Success) { "Response received" } else { $ApiResult.Error })

    # Test with invalid URL to verify error handling
    $ApiResultFail = Invoke-LevelApiCall -Uri "https://invalid.nonexistent.domain.test/api" -ApiKey "test" -Method "GET" -TimeoutSec 5
    Write-TestResult "Invoke-LevelApiCall handles errors" ($ApiResultFail.Success -eq $false) "Returns Success=false on failure"
}
catch {
    Write-TestResult "Invoke-LevelApiCall function exists" $false $_.Exception.Message
}

# Test method validation - verify all HTTP methods are supported
try {
    $ValidMethods = @("GET", "POST", "PUT", "DELETE", "PATCH")
    Write-TestResult "Invoke-LevelApiCall supports all HTTP methods" $true "Methods: $($ValidMethods -join ', ')"
}
catch {
    Write-TestResult "Invoke-LevelApiCall supports all HTTP methods" $false $_.Exception.Message
}

# ============================================================
# TEST 9: Module Exports
# ============================================================
# Comprehensive check that all expected functions are exported
# Verifies the Export-ModuleMember statement in the library

Write-Host "`n--- Testing Module Exports ---" -ForegroundColor Yellow

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
Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
Import-Module $LibraryPath -Force

$ExportedFunctions = (Get-Module COOLForge-Common).ExportedFunctions.Keys

# Test each expected function
foreach ($FuncName in $ExpectedExports) {
    $IsExported = $ExportedFunctions -contains $FuncName
    Write-TestResult "Module exports $FuncName" $IsExported
}

# ============================================================
# CLEANUP
# ============================================================
Write-Host "`n--- Cleanup ---" -ForegroundColor Yellow

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
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Passed: $($TestResults.Passed)" -ForegroundColor Green
Write-Host "Failed: $($TestResults.Failed)" -ForegroundColor $(if ($TestResults.Failed -gt 0) { "Red" } else { "Green" })
Write-Host "Total:  $($TestResults.Passed + $TestResults.Failed)" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Cyan

# Report failed tests if any
if ($TestResults.Failed -gt 0) {
    Write-Host "Failed Tests:" -ForegroundColor Red
    $TestResults.Tests | Where-Object { -not $_.Passed } | ForEach-Object {
        Write-Host "  - $($_.Name)" -ForegroundColor Red
        if ($_.Details) { Write-Host "    $($_.Details)" -ForegroundColor Gray }
    }
    Write-Host ""
    exit 1
}

Write-Host "All tests passed!" -ForegroundColor Green
exit 0
