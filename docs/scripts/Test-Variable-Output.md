# Test Variable Output Script

**Script:** `scripts/Check/👀Test Variable Output.ps1`
**Launcher:** `launchers/👀Test Variable Output.ps1`
**Version:** 2025.12.29.02
**Category:** Check

## Purpose

Demonstrates how to output values that Level.io captures and stores as automation variables for use in subsequent workflow steps.

## Features

- **Level.io variable syntax**: `{{variable_name=value}}`
- **Configurable output**: Control which variables are set
- **10 test categories** with various data types

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Variables output successfully |
| 1 | Alert | Failure |

## Configuration

```powershell
$VariablesToSet = "all"  # Or comma-separated list: "test_hostname,test_os_info"
```

## Test Categories

### 1. Simple String Values
- `test_string` - Static string
- `test_hostname` - Computer name

### 2. Numeric Values
- `test_integer` - Whole number (42)
- `test_float` - Decimal (3.14159)
- `test_negative` - Negative number (-100)

### 3. Boolean Values
- `test_bool_true`, `test_bool_false`
- `test_ps_bool` - PowerShell boolean

### 4. Date/Time Values
- `test_iso_date` - ISO 8601 format
- `test_simple_date` - YYYY-MM-DD
- `test_unix_timestamp` - Unix epoch

### 5. System Information
- `test_ip_address` - Primary IPv4
- `test_os_info` - OS caption
- `test_free_disk_gb` - Free space on C:
- `test_total_ram_gb` - Total RAM

### 6. JSON Data
- `test_json_data` - Compressed JSON object

### 7. Special Characters
- `test_path` - File path with backslashes
- `test_spaced` - String with spaces
- `test_url` - URL

### 8. Computed/Dynamic Values
- `test_run_count` - Execution counter
- `test_last_run` - Timestamp
- `test_script_version` - Version string

### 9. Empty/Null Handling
- `test_empty` - Empty string
- `test_cleared` - Clear a variable

### 10. Status/Result Variables
- `test_status` - Script status
- `test_error_count` - Error counter
- `test_success` - Success boolean

## Level.io Syntax

Output format:
```
{{variable_name=value}}
```

Use in subsequent steps:
```
{{variable_name}}
```

## Reference

[Level.io Documentation: Set Variables from Scripts](https://docs.level.io/en/articles/11509659-set-variables-directly-from-scripts)
