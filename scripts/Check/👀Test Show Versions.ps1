<#
.SYNOPSIS
    Comprehensive test script for COOLForge-Common library via Script Launcher.

.DESCRIPTION
    This script tests all 8 exported functions from the COOLForge-Common library
    and displays version/device information. It verifies:

    - Write-LevelLog      : Logging with all severity levels
    - Test-LevelAdmin     : Administrator privilege detection
    - Get-LevelDeviceInfo : System information gathering (8 properties)
    - Initialize-LevelScript : Tag gating, lockfile management, state initialization
    - Remove-LevelLockFile   : Lockfile cleanup
    - Complete-LevelScript   : Script completion handling
    - Invoke-LevelScript     : Main execution wrapper
    - Invoke-LevelApiCall    : REST API call functionality with Bearer auth

    When run via Script Launcher, this script inherits all Level.io variables
    and the library is already loaded.

    TEST RESULTS:
    - Exit 0: All tests passed (Success)
    - Exit 1: One or more tests failed (Alert)

.NOTES
    Version:          2025.12.27.02
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success (All Tests Passed) | 1 = Alert (Tests Failed)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder  : MSP-defined scratch folder for persistent storage
    - $LibraryUrl        : URL to download COOLForge-Common.psm1 library
    - $DeviceHostname    : Device hostname from Level.io
    - $DeviceTags        : Comma-separated list of device tags

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# 👀Test Show Versions
# Version: 2025.12.27.03
# Target: Level.io (via Script Launcher)
# Exit 0 = Success (All Tests Passed) | Exit 1 = Alert (Tests Failed)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# TEST CONFIGURATION
# ============================================================
# Test result tracking structure

$global:TestResults = @{
    Passed = 0
    Failed = 0
    Tests  = @()
}

# Helper function to record and display test results
function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )

    $Status = if ($Passed) { "[PASS]" } else { "[FAIL]" }
    Write-Host "$Status $TestName"
    if ($Details) { Write-Host "       $Details" }

    if ($Passed) { $global:TestResults.Passed++ } else { $global:TestResults.Failed++ }
    $global:TestResults.Tests += @{ Name = $TestName; Passed = $Passed; Details = $Details }
}

# ============================================================
# VERSION & DEVICE INFORMATION
# ============================================================
Write-Host ""
Write-Host "========================================"
Write-Host "COOLForge_Lib Test Suite & Version Info"
Write-Host "Running via Script Launcher"
Write-Host "========================================"
Write-Host ""

# Get device info
$DeviceInfo = Get-LevelDeviceInfo

# Display device info
Write-Host "--- Device Information ---"
Write-Host "  Hostname:   $($DeviceInfo.Hostname)"
Write-Host "  Username:   $($DeviceInfo.Username)"
Write-Host "  Domain:     $($DeviceInfo.Domain)"
Write-Host "  OS:         $($DeviceInfo.OS)"
Write-Host "  OS Version: $($DeviceInfo.OSVersion)"
Write-Host "  PowerShell: $($DeviceInfo.PowerShell)"
Write-Host "  Is Admin:   $($DeviceInfo.IsAdmin)"
Write-Host ""

# Display library version
Write-Host "--- Library Version ---"
$LibraryPath = Join-Path -Path $MspScratchFolder -ChildPath "Libraries\COOLForge-Common.psm1"
if (Test-Path $LibraryPath) {
    $LibContent = Get-Content -Path $LibraryPath -Raw -ErrorAction SilentlyContinue
    if ($LibContent -match 'Version:\s*([\d\.]+)') {
        Write-Host "  COOLForge-Common.psm1: v$($Matches[1])"
    }
}
Write-Host ""

# Display cached scripts
Write-Host "--- Cached Scripts ---"
$ScriptsFolder = Join-Path -Path $MspScratchFolder -ChildPath "Scripts"
if (Test-Path $ScriptsFolder) {
    $scripts = Get-ChildItem -Path $ScriptsFolder -Filter "*.ps1" -ErrorAction SilentlyContinue
    if ($scripts) {
        foreach ($script in $scripts) {
            $scriptContent = Get-Content -Path $script.FullName -Raw -ErrorAction SilentlyContinue
            if ($scriptContent -match 'Version:\s*([\d\.]+)') {
                Write-Host "  $($script.Name): v$($Matches[1])"
            }
            else {
                Write-Host "  $($script.Name): (no version)"
            }
        }
    }
    else {
        Write-Host "  (no cached scripts)"
    }
}
else {
    Write-Host "  (scripts folder not found)"
}
Write-Host ""

# Display configuration
Write-Host "--- Configuration ---"
Write-Host "  Scratch Folder: $MspScratchFolder"
Write-Host "  Library URL:    $LibraryUrl"
Write-Host "  Device Tags:    $DeviceTags"
Write-Host ""

# Display folder structure
Write-Host "--- Folder Structure ---"
if (Test-Path $MspScratchFolder) {
    $items = Get-ChildItem -Path $MspScratchFolder -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        if ($item.PSIsContainer) {
            $subItems = (Get-ChildItem -Path $item.FullName -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host "  [$($item.Name)/] ($subItems items)"
        }
        else {
            Write-Host "  $($item.Name)"
        }
    }
}
else {
    Write-Host "  (scratch folder not found)"
}
Write-Host ""

# ============================================================
# TEST SUITE
# ============================================================
Write-Host "========================================"
Write-Host "Running Library Tests"
Write-Host "========================================"
Write-Host ""

# Create isolated temp folder for testing
$TestScratchFolder = Join-Path -Path $env:TEMP -ChildPath "LevelIO-Tests-$([guid]::NewGuid().ToString().Substring(0,8))"
New-Item -Path $TestScratchFolder -ItemType Directory -Force | Out-Null

# --- TEST 1: Write-LevelLog ---
Write-Host "--- Testing Write-LevelLog ---"

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

try {
    Write-LevelLog "Test message with default level"
    Write-TestResult "Write-LevelLog with default level" $true
}
catch {
    Write-TestResult "Write-LevelLog with default level" $false $_.Exception.Message
}

# --- TEST 2: Test-LevelAdmin ---
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
Write-Host ""
Write-Host "--- Testing Get-LevelDeviceInfo ---"

try {
    $TestDeviceInfo = Get-LevelDeviceInfo

    $ExpectedProps = @("Hostname", "Username", "Domain", "OS", "OSVersion", "IsAdmin", "PowerShell", "ScriptPID")
    $AllPropsExist = $true
    $MissingProps = @()

    foreach ($Prop in $ExpectedProps) {
        if (-not $TestDeviceInfo.ContainsKey($Prop)) {
            $AllPropsExist = $false
            $MissingProps += $Prop
        }
    }

    Write-TestResult "Get-LevelDeviceInfo returns all properties" $AllPropsExist $(if ($MissingProps) { "Missing: $($MissingProps -join ', ')" } else { "All 8 properties present" })
    Write-TestResult "Get-LevelDeviceInfo.Hostname matches env" ($TestDeviceInfo.Hostname -eq $env:COMPUTERNAME) "Expected: $env:COMPUTERNAME, Got: $($TestDeviceInfo.Hostname)"
    Write-TestResult "Get-LevelDeviceInfo.Username matches env" ($TestDeviceInfo.Username -eq $env:USERNAME) "Expected: $env:USERNAME, Got: $($TestDeviceInfo.Username)"
    Write-TestResult "Get-LevelDeviceInfo.ScriptPID matches PID" ($TestDeviceInfo.ScriptPID -eq $PID) "Expected: $PID, Got: $($TestDeviceInfo.ScriptPID)"
    Write-TestResult "Get-LevelDeviceInfo.OS is not empty" (-not [string]::IsNullOrEmpty($TestDeviceInfo.OS)) "OS: $($TestDeviceInfo.OS)"
}
catch {
    Write-TestResult "Get-LevelDeviceInfo execution" $false $_.Exception.Message
}

# --- TEST 4: Initialize-LevelScript ---
Write-Host ""
Write-Host "--- Testing Initialize-LevelScript ---"

# Test 4a: Basic initialization with SkipTagCheck
try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw
    New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    $Init = Initialize-LevelScript -ScriptName "TestScript1" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -SkipTagCheck

    Write-TestResult "Initialize-LevelScript basic init" ($Init.Success -eq $true) "Reason: $($Init.Reason)"

    $LockFilePath = Join-Path -Path $TestScratchFolder -ChildPath "lockfiles\TestScript1.lock"
    Write-TestResult "Initialize-LevelScript creates lockfile" (Test-Path $LockFilePath) "Path: $LockFilePath"

    if (Test-Path $LockFilePath) {
        $LockContent = Get-Content $LockFilePath -Raw | ConvertFrom-Json
        Write-TestResult "Lockfile contains PID" ($LockContent.PID -eq $PID) "PID in lockfile: $($LockContent.PID)"
        Write-TestResult "Lockfile contains ScriptName" ($LockContent.ScriptName -eq "TestScript1") "ScriptName: $($LockContent.ScriptName)"
    }
}
catch {
    Write-TestResult "Initialize-LevelScript basic init" $false $_.Exception.Message
}

# Test 4b: Tag blocking functionality
try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw
    New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    $TestTags = "Production, Windows 11, NoRun"
    $Init = Initialize-LevelScript -ScriptName "TestScript2" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -DeviceTags $TestTags `
                                   -BlockingTags @("NoRun")

    Write-TestResult "Initialize-LevelScript blocks on tag" ($Init.Success -eq $false -and $Init.Reason -eq "TagBlocked") "NoRun tag blocks execution"
}
catch {
    Write-TestResult "Initialize-LevelScript blocks on tag" $false $_.Exception.Message
}

# Test 4c: SkipTagCheck bypasses blocking
try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw
    New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    $TestTags = "Production, NoRun"
    $Init = Initialize-LevelScript -ScriptName "TestScript3" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -DeviceTags $TestTags `
                                   -BlockingTags @("NoRun") `
                                   -SkipTagCheck

    Write-TestResult "Initialize-LevelScript -SkipTagCheck bypasses block" ($Init.Success -eq $true) "Bypassed with -SkipTagCheck"
}
catch {
    Write-TestResult "Initialize-LevelScript -SkipTagCheck bypasses block" $false $_.Exception.Message
}

# Test 4d: SkipLockFile prevents lockfile creation
try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw
    New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

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

# Test 4e: Stale lockfile cleanup
try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw
    New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    $StaleLockDir = Join-Path -Path $TestScratchFolder -ChildPath "lockfiles"
    if (!(Test-Path $StaleLockDir)) { New-Item -Path $StaleLockDir -ItemType Directory -Force | Out-Null }
    $StaleLockFile = Join-Path -Path $StaleLockDir -ChildPath "TestScript5.lock"

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
Write-Host ""
Write-Host "--- Testing Remove-LevelLockFile ---"

try {
    Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
    $ModuleContent = Get-Content -Path $LibraryPath -Raw
    New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

    $Init = Initialize-LevelScript -ScriptName "TestScript6" `
                                   -MspScratchFolder $TestScratchFolder `
                                   -DeviceHostname "TestHost" `
                                   -SkipTagCheck

    $LockFilePath = Join-Path -Path $TestScratchFolder -ChildPath "lockfiles\TestScript6.lock"
    $ExistsBefore = Test-Path $LockFilePath

    Remove-LevelLockFile

    $ExistsAfter = Test-Path $LockFilePath
    Write-TestResult "Remove-LevelLockFile removes lockfile" ($ExistsBefore -and -not $ExistsAfter) "Before: $ExistsBefore, After: $ExistsAfter"
}
catch {
    Write-TestResult "Remove-LevelLockFile removes lockfile" $false $_.Exception.Message
}

# --- TEST 6: Function Exports ---
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
Write-Host ""
Write-Host "--- Testing Invoke-LevelApiCall ---"

try {
    $FunctionExists = Get-Command Invoke-LevelApiCall -ErrorAction Stop
    Write-TestResult "Invoke-LevelApiCall function exists" ($null -ne $FunctionExists)

    $ApiResult = Invoke-LevelApiCall -Uri "https://httpbin.org/get" -ApiKey "test-key" -Method "GET" -TimeoutSec 10
    Write-TestResult "Invoke-LevelApiCall GET request" ($ApiResult.Success -eq $true) $(if ($ApiResult.Success) { "Response received" } else { $ApiResult.Error })

    $ApiResultFail = Invoke-LevelApiCall -Uri "https://invalid.nonexistent.domain.test/api" -ApiKey "test" -Method "GET" -TimeoutSec 5
    Write-TestResult "Invoke-LevelApiCall handles errors" ($ApiResultFail.Success -eq $false) "Returns Success=false on failure"
}
catch {
    Write-TestResult "Invoke-LevelApiCall function exists" $false $_.Exception.Message
}

# --- TEST 8: Module Exports ---
Write-Host ""
Write-Host "--- Testing Module Exports ---"

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

Remove-Module COOLForge-Common -ErrorAction SilentlyContinue
$ModuleContent = Get-Content -Path $LibraryPath -Raw
New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force

$ExportedFunctions = (Get-Module COOLForge-Common).ExportedFunctions.Keys

foreach ($FuncName in $ExpectedExports) {
    $IsExported = $ExportedFunctions -contains $FuncName
    Write-TestResult "Module exports $FuncName" $IsExported
}

# ============================================================
# CLEANUP
# ============================================================
Write-Host ""
Write-Host "--- Cleanup ---"

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
