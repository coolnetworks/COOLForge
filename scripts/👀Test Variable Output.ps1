<#
.SYNOPSIS
    Tests methods for writing back to Level.io automation variables.

.DESCRIPTION
    This script demonstrates how to output values that Level.io captures and
    stores as automation variables. These variables can then be used in
    subsequent automation steps.

    Level.io Syntax: {{variable_name=value}}

    When Level.io sees this pattern in script output, it:
    1. Captures the variable name and value
    2. Stores it as an automation variable
    3. Makes it available to subsequent steps in the workflow

    CONFIGURATION:
    Set the $VariablesToSet array to control which variables are output.
    Use "all" to output all test variables, or specify individual variable names.

    Available variables:
    - test_string, test_hostname (strings)
    - test_integer, test_float, test_negative (numbers)
    - test_bool_true, test_bool_false, test_ps_bool (booleans)
    - test_iso_date, test_simple_date, test_unix_timestamp (dates)
    - test_ip_address, test_os_info, test_free_disk_gb, test_total_ram_gb (system)
    - test_json_data (JSON)
    - test_path, test_spaced, test_url (special chars)
    - test_run_count, test_last_run, test_script_version (dynamic)
    - test_empty, test_cleared (empty/null)
    - test_status, test_error_count, test_success (status)

.NOTES
    Version:          2025.12.29.02
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Copyright (c) COOLNETWORKS
    https://coolnetworks.au
    https://github.com/coolnetworks/LevelLib

.LINK
    https://docs.level.io/en/articles/11509659-set-variables-directly-from-scripts
#>

# Test Variable Output
# Version: 2025.12.29.02
# Target: Level.io (via Script Launcher)
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://coolnetworks.au
# https://github.com/coolnetworks/LevelLib

# ============================================================
# CONFIGURATION - VARIABLES TO SET
# ============================================================
# Specify which variables to output. Options:
#   - "all" : Output all test variables
#   - Comma-separated list: "test_hostname,test_os_info,test_free_disk_gb"
#   - Array: @("test_hostname", "test_os_info")
#
# This can be set via Level.io custom field:
#   $VariablesToSet = "{{cf_test_variables}}"
#
# Or passed from the launcher by adding to the variables section.
# ============================================================

# Check if VariablesToSet was passed from launcher, otherwise use default
if (-not (Get-Variable -Name 'VariablesToSet' -ErrorAction SilentlyContinue) -or
    [string]::IsNullOrWhiteSpace($VariablesToSet)) {
    # Default: run all tests
    $VariablesToSet = "all"
}

# Parse the variables list
if ($VariablesToSet -is [string]) {
    if ($VariablesToSet.Trim().ToLower() -eq "all") {
        $SelectedVariables = @("all")
    } else {
        # Split by comma and trim whitespace
        $SelectedVariables = $VariablesToSet -split ',' | ForEach-Object { $_.Trim().ToLower() }
    }
} else {
    $SelectedVariables = $VariablesToSet | ForEach-Object { $_.Trim().ToLower() }
}

# Helper function to check if a variable should be output
function Should-OutputVariable {
    param([string]$VariableName)
    if ($SelectedVariables -contains "all") { return $true }
    return $SelectedVariables -contains $VariableName.ToLower()
}

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
Write-Host "Level.io Variable Output Test Script v2025.12.29.02"
Write-Host "============================================================"
Write-Host ""

if ($SelectedVariables -contains "all") {
    Write-Host "[*] Mode: Output ALL test variables"
} else {
    Write-Host "[*] Mode: Output selected variables only"
    Write-Host "[*] Selected: $($SelectedVariables -join ', ')"
}
Write-Host ""

$VariablesSet = @()

# ============================================================
# TEST 1: Simple String Values
# ============================================================
if ((Should-OutputVariable "test_string") -or (Should-OutputVariable "test_hostname")) {
    Write-Host "[TEST 1] Simple String Values"
    Write-Host "------------------------------------------------------------"

    if (Should-OutputVariable "test_string") {
        $SimpleString = "Hello from LevelLib"
        Write-Host "Setting test_string = $SimpleString"
        Write-Output "{{test_string=$SimpleString}}"
        $VariablesSet += "test_string"
    }

    if (Should-OutputVariable "test_hostname") {
        $Hostname = $env:COMPUTERNAME
        Write-Host "Setting test_hostname = $Hostname"
        Write-Output "{{test_hostname=$Hostname}}"
        $VariablesSet += "test_hostname"
    }

    Write-Host ""
}

# ============================================================
# TEST 2: Numeric Values
# ============================================================
if ((Should-OutputVariable "test_integer") -or (Should-OutputVariable "test_float") -or (Should-OutputVariable "test_negative")) {
    Write-Host "[TEST 2] Numeric Values"
    Write-Host "------------------------------------------------------------"

    if (Should-OutputVariable "test_integer") {
        $IntegerValue = 42
        Write-Host "Setting test_integer = $IntegerValue"
        Write-Output "{{test_integer=$IntegerValue}}"
        $VariablesSet += "test_integer"
    }

    if (Should-OutputVariable "test_float") {
        $FloatValue = 3.14159
        Write-Host "Setting test_float = $FloatValue"
        Write-Output "{{test_float=$FloatValue}}"
        $VariablesSet += "test_float"
    }

    if (Should-OutputVariable "test_negative") {
        $NegativeValue = -100
        Write-Host "Setting test_negative = $NegativeValue"
        Write-Output "{{test_negative=$NegativeValue}}"
        $VariablesSet += "test_negative"
    }

    Write-Host ""
}

# ============================================================
# TEST 3: Boolean Values
# ============================================================
if ((Should-OutputVariable "test_bool_true") -or (Should-OutputVariable "test_bool_false") -or (Should-OutputVariable "test_ps_bool")) {
    Write-Host "[TEST 3] Boolean Values"
    Write-Host "------------------------------------------------------------"

    if (Should-OutputVariable "test_bool_true") {
        $BoolTrue = "true"
        Write-Host "Setting test_bool_true = $BoolTrue"
        Write-Output "{{test_bool_true=$BoolTrue}}"
        $VariablesSet += "test_bool_true"
    }

    if (Should-OutputVariable "test_bool_false") {
        $BoolFalse = "false"
        Write-Host "Setting test_bool_false = $BoolFalse"
        Write-Output "{{test_bool_false=$BoolFalse}}"
        $VariablesSet += "test_bool_false"
    }

    if (Should-OutputVariable "test_ps_bool") {
        $PSBool = $true
        Write-Host "Setting test_ps_bool = $($PSBool.ToString().ToLower())"
        Write-Output "{{test_ps_bool=$($PSBool.ToString().ToLower())}}"
        $VariablesSet += "test_ps_bool"
    }

    Write-Host ""
}

# ============================================================
# TEST 4: Date/Time Values
# ============================================================
if ((Should-OutputVariable "test_iso_date") -or (Should-OutputVariable "test_simple_date") -or (Should-OutputVariable "test_unix_timestamp")) {
    Write-Host "[TEST 4] Date/Time Values"
    Write-Host "------------------------------------------------------------"

    if (Should-OutputVariable "test_iso_date") {
        $IsoDate = (Get-Date).ToString("o")
        Write-Host "Setting test_iso_date = $IsoDate"
        Write-Output "{{test_iso_date=$IsoDate}}"
        $VariablesSet += "test_iso_date"
    }

    if (Should-OutputVariable "test_simple_date") {
        $SimpleDate = (Get-Date).ToString("yyyy-MM-dd")
        Write-Host "Setting test_simple_date = $SimpleDate"
        Write-Output "{{test_simple_date=$SimpleDate}}"
        $VariablesSet += "test_simple_date"
    }

    if (Should-OutputVariable "test_unix_timestamp") {
        $UnixTimestamp = [int][double]::Parse((Get-Date -UFormat %s))
        Write-Host "Setting test_unix_timestamp = $UnixTimestamp"
        Write-Output "{{test_unix_timestamp=$UnixTimestamp}}"
        $VariablesSet += "test_unix_timestamp"
    }

    Write-Host ""
}

# ============================================================
# TEST 5: System Information
# ============================================================
if ((Should-OutputVariable "test_ip_address") -or (Should-OutputVariable "test_os_info") -or
    (Should-OutputVariable "test_free_disk_gb") -or (Should-OutputVariable "test_total_ram_gb")) {
    Write-Host "[TEST 5] System Information"
    Write-Host "------------------------------------------------------------"

    if (Should-OutputVariable "test_ip_address") {
        $IPAddress = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                      Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
                      Select-Object -First 1 -ExpandProperty IPAddress)
        if ($IPAddress) {
            Write-Host "Setting test_ip_address = $IPAddress"
            Write-Output "{{test_ip_address=$IPAddress}}"
            $VariablesSet += "test_ip_address"
        }
    }

    if (Should-OutputVariable "test_os_info") {
        $OSInfo = (Get-CimInstance Win32_OperatingSystem).Caption
        Write-Host "Setting test_os_info = $OSInfo"
        Write-Output "{{test_os_info=$OSInfo}}"
        $VariablesSet += "test_os_info"
    }

    if (Should-OutputVariable "test_free_disk_gb") {
        $FreeDiskGB = [math]::Round((Get-PSDrive C).Free / 1GB, 2)
        Write-Host "Setting test_free_disk_gb = $FreeDiskGB"
        Write-Output "{{test_free_disk_gb=$FreeDiskGB}}"
        $VariablesSet += "test_free_disk_gb"
    }

    if (Should-OutputVariable "test_total_ram_gb") {
        $TotalRAMGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        Write-Host "Setting test_total_ram_gb = $TotalRAMGB"
        Write-Output "{{test_total_ram_gb=$TotalRAMGB}}"
        $VariablesSet += "test_total_ram_gb"
    }

    Write-Host ""
}

# ============================================================
# TEST 6: JSON-Formatted Data
# ============================================================
if (Should-OutputVariable "test_json_data") {
    Write-Host "[TEST 6] JSON-Formatted Data"
    Write-Host "------------------------------------------------------------"

    $DeviceInfo = @{
        hostname = $env:COMPUTERNAME
        domain = $env:USERDOMAIN
        user = $env:USERNAME
        timestamp = (Get-Date).ToString("o")
    } | ConvertTo-Json -Compress

    Write-Host "Setting test_json_data = $DeviceInfo"
    Write-Output "{{test_json_data=$DeviceInfo}}"
    $VariablesSet += "test_json_data"

    Write-Host ""
}

# ============================================================
# TEST 7: Special Characters
# ============================================================
if ((Should-OutputVariable "test_path") -or (Should-OutputVariable "test_spaced") -or (Should-OutputVariable "test_url")) {
    Write-Host "[TEST 7] Special Characters"
    Write-Host "------------------------------------------------------------"

    if (Should-OutputVariable "test_path") {
        $PathValue = "C:\Program Files\LevelLib"
        Write-Host "Setting test_path = $PathValue"
        Write-Output "{{test_path=$PathValue}}"
        $VariablesSet += "test_path"
    }

    if (Should-OutputVariable "test_spaced") {
        $SpacedValue = "This has spaces"
        Write-Host "Setting test_spaced = $SpacedValue"
        Write-Output "{{test_spaced=$SpacedValue}}"
        $VariablesSet += "test_spaced"
    }

    if (Should-OutputVariable "test_url") {
        $UrlValue = "https://github.com/coolnetworks/LevelLib"
        Write-Host "Setting test_url = $UrlValue"
        Write-Output "{{test_url=$UrlValue}}"
        $VariablesSet += "test_url"
    }

    Write-Host ""
}

# ============================================================
# TEST 8: Computed/Dynamic Values
# ============================================================
if ((Should-OutputVariable "test_run_count") -or (Should-OutputVariable "test_last_run") -or (Should-OutputVariable "test_script_version")) {
    Write-Host "[TEST 8] Computed/Dynamic Values"
    Write-Host "------------------------------------------------------------"

    if (Should-OutputVariable "test_run_count") {
        $RunCount = 1
        Write-Host "Setting test_run_count = $RunCount"
        Write-Output "{{test_run_count=$RunCount}}"
        $VariablesSet += "test_run_count"
    }

    if (Should-OutputVariable "test_last_run") {
        $LastRun = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Write-Host "Setting test_last_run = $LastRun"
        Write-Output "{{test_last_run=$LastRun}}"
        $VariablesSet += "test_last_run"
    }

    if (Should-OutputVariable "test_script_version") {
        $ScriptVersion = "2025.12.29.02"
        Write-Host "Setting test_script_version = $ScriptVersion"
        Write-Output "{{test_script_version=$ScriptVersion}}"
        $VariablesSet += "test_script_version"
    }

    Write-Host ""
}

# ============================================================
# TEST 9: Empty/Null Handling
# ============================================================
if ((Should-OutputVariable "test_empty") -or (Should-OutputVariable "test_cleared")) {
    Write-Host "[TEST 9] Empty/Null Handling"
    Write-Host "------------------------------------------------------------"

    if (Should-OutputVariable "test_empty") {
        $EmptyValue = ""
        Write-Host "Setting test_empty = (empty string)"
        Write-Output "{{test_empty=$EmptyValue}}"
        $VariablesSet += "test_empty"
    }

    if (Should-OutputVariable "test_cleared") {
        Write-Host "Setting test_cleared = (empty to clear)"
        Write-Output "{{test_cleared=}}"
        $VariablesSet += "test_cleared"
    }

    Write-Host ""
}

# ============================================================
# TEST 10: Status/Result Variables
# ============================================================
if ((Should-OutputVariable "test_status") -or (Should-OutputVariable "test_error_count") -or (Should-OutputVariable "test_success")) {
    Write-Host "[TEST 10] Status/Result Variables"
    Write-Host "------------------------------------------------------------"

    if (Should-OutputVariable "test_status") {
        $ScriptStatus = "completed"
        Write-Host "Setting test_status = $ScriptStatus"
        Write-Output "{{test_status=$ScriptStatus}}"
        $VariablesSet += "test_status"
    }

    if (Should-OutputVariable "test_error_count") {
        $ErrorCount = 0
        Write-Host "Setting test_error_count = $ErrorCount"
        Write-Output "{{test_error_count=$ErrorCount}}"
        $VariablesSet += "test_error_count"
    }

    if (Should-OutputVariable "test_success") {
        $Success = "true"
        Write-Host "Setting test_success = $Success"
        Write-Output "{{test_success=$Success}}"
        $VariablesSet += "test_success"
    }

    Write-Host ""
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host "============================================================"
Write-Host "VARIABLE OUTPUT TEST COMPLETE"
Write-Host "============================================================"
Write-Host ""
Write-Host "Variables set ($($VariablesSet.Count) total):"
foreach ($var in $VariablesSet) {
    Write-Host "  - $var"
}
Write-Host ""
Write-Host "To use these in subsequent automation steps, reference them as:"
Write-Host "  {{variable_name}}"
Write-Host ""
Write-Host "[+] Test completed successfully"

exit 0
