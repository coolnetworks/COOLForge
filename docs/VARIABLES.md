# Variables Reference

This document covers Level.io variables used by COOLForge_Lib and how to set automation variables from scripts.

---

## Table of Contents

- [Level.io Custom Fields](#levelio-custom-fields)
- [Level.io System Variables](#levelio-system-variables)
- [Setting Automation Variables](#setting-automation-variables)
- [Test Script](#test-script)

---

## Level.io Custom Fields

These custom fields are used by COOLForge_Lib scripts:

| Variable | Description | Required |
|----------|-------------|----------|
| `{{cf_CoolForge_msp_scratch_folder}}` | Base path for MSP files (e.g., `C:\ProgramData\MSP`) | **Yes** |
| `{{cf_CoolForge_ps_module_library_source}}` | URL to download library (leave empty for official repo) | No |
| `{{cf_CoolForge_pin_psmodule_to_version}}` | Pin to specific version tag (e.g., `v2025.12.29`) | No |
| `{{cf_CoolForge_screenconnect_instance_id}}` | Your MSP's ScreenConnect instance ID | No |
| `{{cf_CoolForge_is_screenconnect_server}}` | Set to "true" on ScreenConnect server devices | No |

---

## Level.io System Variables

These are built-in Level.io variables available to all scripts:

| Variable | Description | Example |
|----------|-------------|---------|
| `{{level_device_id}}` | Internal unique device identifier | `abc123` |
| `{{level_device_hostname}}` | Device hostname | `WORKSTATION01` |
| `{{level_device_nickname}}` | Custom nickname | `John's Laptop` |
| `{{level_device_public_ip_address}}` | External IP address | `203.0.113.50` |
| `{{level_device_private_ip_addresses}}` | Internal IP addresses (comma-separated) | `192.168.1.100,10.0.0.5` |
| `{{level_group_id}}` | Group ID | `grp_123` |
| `{{level_group_name}}` | Group name | `Servers` |
| `{{level_group_path}}` | Full group path | `HQ/Servers` |
| `{{level_tag_names}}` | Tag names (comma-separated) | `Production, Windows 11` |
| `{{level_tag_ids}}` | Tag IDs (comma-separated) | `tag_1,tag_2` |

---

## Setting Automation Variables

Level.io allows scripts to set variables during execution that persist and can be used by subsequent automation steps.

### Syntax

Output variables using this format on their own line:

```
{{variable_name=value}}
```

Use `Write-Output` (not `Write-Host`) to set variables:

```powershell
# Set a simple string variable
$Hostname = $env:COMPUTERNAME
Write-Output "{{device_hostname=$Hostname}}"

# Set a numeric value
$DiskFreeGB = [math]::Round((Get-PSDrive C).Free / 1GB, 2)
Write-Output "{{disk_free_gb=$DiskFreeGB}}"

# Set a boolean
$IsCompliant = "true"
Write-Output "{{is_compliant=$IsCompliant}}"

# Set JSON data
$Info = @{ hostname = $env:COMPUTERNAME; timestamp = (Get-Date).ToString("o") } | ConvertTo-Json -Compress
Write-Output "{{device_info=$Info}}"
```

### Using Variables in Subsequent Steps

After a script sets a variable, it's available in later automation steps as:

```
{{variable_name}}
```

---

## Test Script

Use `👀Test Variable Output.ps1` to test all variable output methods. It demonstrates:

- Simple strings and numbers
- Boolean values
- Date/time formats (ISO 8601, Unix timestamp)
- System information (IP, OS, disk space, RAM)
- JSON-formatted data
- Special characters and paths
- Empty/null handling
- Status/result patterns

**Documentation:** [Level.io - Set Variables Directly from Scripts](https://docs.level.io/en/articles/11509659-set-variables-directly-from-scripts)

---

## See Also

- [Main README](../README.md)
- [Function Reference](FUNCTIONS.md)
