<#
.SYNOPSIS
    Tests all methods for writing back to Level.io automation variables.

.DESCRIPTION
    This script demonstrates how to output values that Level.io captures and
    stores as automation variables. These variables can then be used in
    subsequent automation steps.

    Level.io Syntax: {{variable_name=value}}

    When Level.io sees this pattern in script output, it:
    1. Captures the variable name and value
    2. Stores it as an automation variable
    3. Makes it available to subsequent steps in the workflow

    This script tests:
    - Simple string values
    - Numeric values
    - Boolean values
    - Date/time values
    - JSON-formatted data
    - Multi-line values
    - Special characters
    - Empty/null handling

.NOTES
    Version:          2025.12.29.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/LevelLib

.LINK
    https://docs.level.io/en/articles/11509659-set-variables-directly-from-scripts
#>

# Test Variable Output
# Version: 2025.12.29.01
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/LevelLib

# ============================================================
# LEVEL.IO VARIABLE OUTPUT SYNTAX
# ============================================================
# Level.io captures variables from script output using this format:
#
#   {{variable_name=value}}
#
# The variable is then available in subsequent automation steps as:
#   {{variable_name}}
#
# IMPORTANT: The output must be on its own line for reliable parsing
# ============================================================

Write-Host "============================================================"
Write-Host "Level.io Variable Output Test Script"
Write-Host "============================================================"
Write-Host ""

# ============================================================
# TEST 1: Simple String Values
# ============================================================
Write-Host "[TEST 1] Simple String Values"
Write-Host "------------------------------------------------------------"

$SimpleString = "Hello from LevelLib"
Write-Host "Setting test_string = $SimpleString"
Write-Output "{{test_string=$SimpleString}}"

$Hostname = $env:COMPUTERNAME
Write-Host "Setting test_hostname = $Hostname"
Write-Output "{{test_hostname=$Hostname}}"

Write-Host ""

# ============================================================
# TEST 2: Numeric Values
# ============================================================
Write-Host "[TEST 2] Numeric Values"
Write-Host "------------------------------------------------------------"

$IntegerValue = 42
Write-Host "Setting test_integer = $IntegerValue"
Write-Output "{{test_integer=$IntegerValue}}"

$FloatValue = 3.14159
Write-Host "Setting test_float = $FloatValue"
Write-Output "{{test_float=$FloatValue}}"

$NegativeValue = -100
Write-Host "Setting test_negative = $NegativeValue"
Write-Output "{{test_negative=$NegativeValue}}"

Write-Host ""

# ============================================================
# TEST 3: Boolean Values
# ============================================================
Write-Host "[TEST 3] Boolean Values"
Write-Host "------------------------------------------------------------"

$BoolTrue = "true"
Write-Host "Setting test_bool_true = $BoolTrue"
Write-Output "{{test_bool_true=$BoolTrue}}"

$BoolFalse = "false"
Write-Host "Setting test_bool_false = $BoolFalse"
Write-Output "{{test_bool_false=$BoolFalse}}"

# PowerShell boolean to string
$PSBool = $true
Write-Host "Setting test_ps_bool = $($PSBool.ToString().ToLower())"
Write-Output "{{test_ps_bool=$($PSBool.ToString().ToLower())}}"

Write-Host ""

# ============================================================
# TEST 4: Date/Time Values
# ============================================================
Write-Host "[TEST 4] Date/Time Values"
Write-Host "------------------------------------------------------------"

$IsoDate = (Get-Date).ToString("o")
Write-Host "Setting test_iso_date = $IsoDate"
Write-Output "{{test_iso_date=$IsoDate}}"

$SimpleDate = (Get-Date).ToString("yyyy-MM-dd")
Write-Host "Setting test_simple_date = $SimpleDate"
Write-Output "{{test_simple_date=$SimpleDate}}"

$UnixTimestamp = [int][double]::Parse((Get-Date -UFormat %s))
Write-Host "Setting test_unix_timestamp = $UnixTimestamp"
Write-Output "{{test_unix_timestamp=$UnixTimestamp}}"

Write-Host ""

# ============================================================
# TEST 5: System Information
# ============================================================
Write-Host "[TEST 5] System Information"
Write-Host "------------------------------------------------------------"

# Get IP Address
$IPAddress = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
              Select-Object -First 1 -ExpandProperty IPAddress)
if ($IPAddress) {
    Write-Host "Setting test_ip_address = $IPAddress"
    Write-Output "{{test_ip_address=$IPAddress}}"
}

# Get OS Info
$OSInfo = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "Setting test_os_info = $OSInfo"
Write-Output "{{test_os_info=$OSInfo}}"

# Get Free Disk Space (GB)
$FreeDiskGB = [math]::Round((Get-PSDrive C).Free / 1GB, 2)
Write-Host "Setting test_free_disk_gb = $FreeDiskGB"
Write-Output "{{test_free_disk_gb=$FreeDiskGB}}"

# Get Total RAM (GB)
$TotalRAMGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
Write-Host "Setting test_total_ram_gb = $TotalRAMGB"
Write-Output "{{test_total_ram_gb=$TotalRAMGB}}"

Write-Host ""

# ============================================================
# TEST 6: JSON-Formatted Data
# ============================================================
Write-Host "[TEST 6] JSON-Formatted Data"
Write-Host "------------------------------------------------------------"

# Create a hashtable and convert to JSON (single line)
$DeviceInfo = @{
    hostname = $env:COMPUTERNAME
    domain = $env:USERDOMAIN
    user = $env:USERNAME
    timestamp = (Get-Date).ToString("o")
} | ConvertTo-Json -Compress

Write-Host "Setting test_json_data = $DeviceInfo"
Write-Output "{{test_json_data=$DeviceInfo}}"

Write-Host ""

# ============================================================
# TEST 7: Special Characters
# ============================================================
Write-Host "[TEST 7] Special Characters"
Write-Host "------------------------------------------------------------"

# Note: Some special characters may need escaping or encoding
$PathValue = "C:\Program Files\LevelLib"
Write-Host "Setting test_path = $PathValue"
Write-Output "{{test_path=$PathValue}}"

# Spaces in values
$SpacedValue = "This has spaces"
Write-Host "Setting test_spaced = $SpacedValue"
Write-Output "{{test_spaced=$SpacedValue}}"

# URL value
$UrlValue = "https://github.com/coolnetworks/LevelLib"
Write-Host "Setting test_url = $UrlValue"
Write-Output "{{test_url=$UrlValue}}"

Write-Host ""

# ============================================================
# TEST 8: Computed/Dynamic Values
# ============================================================
Write-Host "[TEST 8] Computed/Dynamic Values"
Write-Host "------------------------------------------------------------"

# Script run count (would need to be read from file/registry in real scenario)
$RunCount = 1
Write-Host "Setting test_run_count = $RunCount"
Write-Output "{{test_run_count=$RunCount}}"

# Last run timestamp
$LastRun = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "Setting test_last_run = $LastRun"
Write-Output "{{test_last_run=$LastRun}}"

# Script version
$ScriptVersion = "2025.12.29.01"
Write-Host "Setting test_script_version = $ScriptVersion"
Write-Output "{{test_script_version=$ScriptVersion}}"

Write-Host ""

# ============================================================
# TEST 9: Empty/Null Handling
# ============================================================
Write-Host "[TEST 9] Empty/Null Handling"
Write-Host "------------------------------------------------------------"

# Empty string
$EmptyValue = ""
Write-Host "Setting test_empty = (empty string)"
Write-Output "{{test_empty=$EmptyValue}}"

# Clearing a variable (set to empty)
Write-Host "Setting test_cleared = (empty to clear)"
Write-Output "{{test_cleared=}}"

Write-Host ""

# ============================================================
# TEST 10: Status/Result Variables
# ============================================================
Write-Host "[TEST 10] Status/Result Variables"
Write-Host "------------------------------------------------------------"

# Common pattern: Set a status variable at the end of script
$ScriptStatus = "completed"
Write-Host "Setting test_status = $ScriptStatus"
Write-Output "{{test_status=$ScriptStatus}}"

# Error count (0 = success)
$ErrorCount = 0
Write-Host "Setting test_error_count = $ErrorCount"
Write-Output "{{test_error_count=$ErrorCount}}"

# Success flag
$Success = "true"
Write-Host "Setting test_success = $Success"
Write-Output "{{test_success=$Success}}"

Write-Host ""

# ============================================================
# SUMMARY
# ============================================================
Write-Host "============================================================"
Write-Host "VARIABLE OUTPUT TEST COMPLETE"
Write-Host "============================================================"
Write-Host ""
Write-Host "Variables set in this test:"
Write-Host "  - test_string, test_hostname"
Write-Host "  - test_integer, test_float, test_negative"
Write-Host "  - test_bool_true, test_bool_false, test_ps_bool"
Write-Host "  - test_iso_date, test_simple_date, test_unix_timestamp"
Write-Host "  - test_ip_address, test_os_info, test_free_disk_gb, test_total_ram_gb"
Write-Host "  - test_json_data"
Write-Host "  - test_path, test_spaced, test_url"
Write-Host "  - test_run_count, test_last_run, test_script_version"
Write-Host "  - test_empty, test_cleared"
Write-Host "  - test_status, test_error_count, test_success"
Write-Host ""
Write-Host "To use these in subsequent automation steps, reference them as:"
Write-Host "  {{test_variable_name}}"
Write-Host ""
Write-Host "[+] Test completed successfully"

exit 0
