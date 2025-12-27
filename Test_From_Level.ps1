# Test_From_Level.ps1
# Version: 2025.12.27.2
# Target: Level.io
# Tests all library functions when deployed via Level.io
# Exit 0 = All Tests Passed | Exit 1 = Tests Failed
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/LevelLib
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# LIBRARY AUTO-UPDATE & IMPORT
# ============================================================
$MspScratchFolder = "{{cf_msp_scratch_folder}}"
$LibraryFolder = Join-Path -Path $MspScratchFolder -ChildPath "Libraries"
$LibraryPath = Join-Path -Path $LibraryFolder -ChildPath "LevelIO-Common.psm1"
$LibraryUrl = "https://raw.githubusercontent.com/coolnetworks/LevelLib/main/LevelIO-Common.psm1"

# Create Libraries folder if needed
if (!(Test-Path $LibraryFolder)) {
    New-Item -Path $LibraryFolder -ItemType Directory -Force | Out-Null
}

# Function to get version from module content
function Get-ModuleVersion {
    param([string]$Content)
    if ($Content -match '# Version:\s*([\d\.]+)') {
        return $Matches[1]
    }
    return "0.0.0"
}

# Check for updates or install
$NeedsUpdate = $false
$LocalVersion = "0.0.0"
$RemoteVersion = "0.0.0"

if (Test-Path $LibraryPath) {
    $LocalContent = Get-Content -Path $LibraryPath -Raw -ErrorAction SilentlyContinue
    $LocalVersion = Get-ModuleVersion -Content $LocalContent
}
else {
    $NeedsUpdate = $true
    Write-Host "[*] Library not found - downloading..."
}

# Try to fetch latest version from GitHub
try {
    $RemoteContent = (Invoke-WebRequest -Uri $LibraryUrl -UseBasicParsing -TimeoutSec 10).Content
    $RemoteVersion = Get-ModuleVersion -Content $RemoteContent

    if ([version]$RemoteVersion -gt [version]$LocalVersion) {
        $NeedsUpdate = $true
        Write-Host "[*] Update available: $LocalVersion -> $RemoteVersion"
    }

    if ($NeedsUpdate) {
        Set-Content -Path $LibraryPath -Value $RemoteContent -Force -ErrorAction Stop
        Write-Host "[+] Library updated to v$RemoteVersion"
    }
}
catch {
    if (!(Test-Path $LibraryPath)) {
        Write-Host "[X] FATAL: Cannot download library and no local copy exists"
        Write-Host "[X] Error: $($_.Exception.Message)"
        exit 1
    }
    Write-Host "[!] Could not check for updates (using local v$LocalVersion)"
}

Import-Module $LibraryPath -Force

# ============================================================
# TEST CONFIGURATION
# ============================================================
$TestResults = @{
    Passed = 0
    Failed = 0
    Tests  = @()
}

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )

    $Status = if ($Passed) { "[PASS]" } else { "[FAIL]" }
    Write-Host "$Status $TestName"
    if ($Details) { Write-Host "       $Details" }

    if ($Passed) { $script:TestResults.Passed++ } else { $script:TestResults.Failed++ }
    $script:TestResults.Tests += @{ Name = $TestName; Passed = $Passed; Details = $Details }
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

# Create temp folder for testing
$TestScratchFolder = Join-Path -Path $env:TEMP -ChildPath "LevelIO-Tests-$([guid]::NewGuid().ToString().Substring(0,8))"
New-Item -Path $TestScratchFolder -ItemType Directory -Force | Out-Null

# --- TEST 1: Write-LevelLog ---
Write-Host ""
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
    $DeviceInfo = Get-LevelDeviceInfo

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
    Write-TestResult "Get-LevelDeviceInfo.Hostname matches env" ($DeviceInfo.Hostname -eq $env:COMPUTERNAME) "Expected: $env:COMPUTERNAME, Got: $($DeviceInfo.Hostname)"
    Write-TestResult "Get-LevelDeviceInfo.Username matches env" ($DeviceInfo.Username -eq $env:USERNAME) "Expected: $env:USERNAME, Got: $($DeviceInfo.Username)"
    Write-TestResult "Get-LevelDeviceInfo.ScriptPID matches PID" ($DeviceInfo.ScriptPID -eq $PID) "Expected: $PID, Got: $($DeviceInfo.ScriptPID)"
    Write-TestResult "Get-LevelDeviceInfo.OS is not empty" (-not [string]::IsNullOrEmpty($DeviceInfo.OS)) "OS: $($DeviceInfo.OS)"
}
catch {
    Write-TestResult "Get-LevelDeviceInfo execution" $false $_.Exception.Message
}

# --- TEST 4: Initialize-LevelScript ---
Write-Host ""
Write-Host "--- Testing Initialize-LevelScript ---"

# Test 4a: Basic initialization
try {
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

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

# Test 4b: Tag blocking
try {
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

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
try {
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

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
try {
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
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
try {
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

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
    Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
    Import-Module $LibraryPath -Force

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

Remove-Module LevelIO-Common -ErrorAction SilentlyContinue
Import-Module $LibraryPath -Force

$ExportedFunctions = (Get-Module LevelIO-Common).ExportedFunctions.Keys

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
Write-Host "Passed: $($TestResults.Passed)"
Write-Host "Failed: $($TestResults.Failed)"
Write-Host "Total:  $($TestResults.Passed + $TestResults.Failed)"
Write-Host "========================================"
Write-Host ""

if ($TestResults.Failed -gt 0) {
    Write-Host "Failed Tests:"
    $TestResults.Tests | Where-Object { -not $_.Passed } | ForEach-Object {
        Write-Host "  - $($_.Name)"
        if ($_.Details) { Write-Host "    $($_.Details)" }
    }
    Write-Host ""
    exit 1
}

Write-Host "All tests passed!"
exit 0
