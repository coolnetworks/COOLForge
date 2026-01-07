# COOLForge_Lib Function Reference

This document provides detailed documentation for all functions exported by the COOLForge-Common module.

---

## Table of Contents

- [Initialize-LevelScript](#initialize-levelscript)
- [Write-LevelLog](#write-levellog)
- [Invoke-LevelScript](#invoke-levelscript)
- [Complete-LevelScript](#complete-levelscript)
- [Remove-LevelLockFile](#remove-levellockfile)
- [Test-LevelAdmin](#test-leveladmin)
- [Get-LevelDeviceInfo](#get-leveldeviceinfo)
- [Invoke-LevelApiCall](#invoke-levelapicall)
- [Repair-LevelEmoji](#repair-levelemoji)
- [Get-LevelUrlEncoded](#get-levelurlencoded)
- [Get-LevelGroups](#get-levelgroups)
- [Get-LevelDevices](#get-leveldevices)
- [Find-LevelDevice](#find-leveldevice)
- [Send-LevelWakeOnLan](#send-levelwakeonlan)

---

## Initialize-LevelScript

Initializes the script environment, checks blocking tags, and creates a lockfile.

```powershell
$Init = Initialize-LevelScript -ScriptName "MyScript" `
                               -MspScratchFolder "{{cf_coolforge_msp_scratch_folder}}" `
                               -DeviceHostname "{{level_device_hostname}}" `
                               -DeviceTags "{{level_tag_names}}"
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ScriptName` | String | Yes | — | Unique identifier for the script (used for lockfile) |
| `-MspScratchFolder` | String | Yes | — | Base path for MSP files |
| `-DeviceHostname` | String | No | `$env:COMPUTERNAME` | Device hostname for logging |
| `-DeviceTags` | String | No | `""` | Comma-separated list of device tags |
| `-BlockingTags` | String[] | No | `@("❌")` | Tags that block script execution |
| `-SkipTagCheck` | Switch | No | `$false` | Bypass tag gate check |
| `-SkipLockFile` | Switch | No | `$false` | Don't create a lockfile |

### Return Values

```powershell
# Success
@{ Success = $true; Reason = "Initialized" }

# Blocked by tag
@{ Success = $false; Reason = "TagBlocked"; Tag = "BlockedTag" }

# Already running
@{ Success = $false; Reason = "AlreadyRunning"; PID = 1234 }
```

---

## Write-LevelLog

Outputs a timestamped, formatted log message.

```powershell
Write-LevelLog "This is a message"
Write-LevelLog "Something went wrong" -Level "ERROR"
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Message` | String | Yes | — | The message to log |
| `-Level` | String | No | `"INFO"` | Severity level |

### Log Levels

| Level | Prefix | Use Case |
|-------|--------|----------|
| `INFO` | `[*]` | General information |
| `WARN` | `[!]` | Warnings (non-fatal issues) |
| `ERROR` | `[X]` | Errors and failures |
| `SUCCESS` | `[+]` | Successful completions |
| `SKIP` | `[-]` | Skipped operations |
| `DEBUG` | `[D]` | Debug/verbose output |

### Output Example

```
2025-12-27 14:32:01 [*] Starting cleanup process
2025-12-27 14:32:02 [+] Removed 15 temporary files
2025-12-27 14:32:03 [!] Could not access C:\Locked\File.tmp
2025-12-27 14:32:04 [X] Failed to clear browser cache
```

---

## Invoke-LevelScript

Wraps your main script logic with automatic error handling and cleanup.

```powershell
Invoke-LevelScript -ScriptBlock {
    Write-LevelLog "Doing work..."
    # Your code here
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ScriptBlock` | ScriptBlock | Yes | — | The code to execute |
| `-NoCleanup` | Switch | No | `$false` | Don't remove lockfile on completion |

### Behavior

- Executes the script block
- On success: logs completion, removes lockfile, exits with code `0`
- On error: logs the exception, removes lockfile, exits with code `1`

---

## Complete-LevelScript

Manually complete the script with a custom exit code and message.

```powershell
Complete-LevelScript -ExitCode 0 -Message "All files processed"
Complete-LevelScript -ExitCode 1 -Message "Database connection failed"
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ExitCode` | Int | No | `0` | Exit code (0 = success, 1 = alert/failure) |
| `-Message` | String | No | `"Script completed"` | Final log message |

---

## Remove-LevelLockFile

Manually remove the current script's lockfile.

```powershell
Remove-LevelLockFile
```

> **Note:** Called automatically by `Invoke-LevelScript` and `Complete-LevelScript`.

---

## Test-LevelAdmin

Checks if the script is running with administrator privileges.

```powershell
if (-not (Test-LevelAdmin)) {
    Write-LevelLog "This script requires admin rights!" -Level "ERROR"
    Complete-LevelScript -ExitCode 1 -Message "Admin required"
}
```

**Returns:** `$true` if running as administrator, `$false` otherwise.

---

## Get-LevelDeviceInfo

Returns a hashtable of common device information.

```powershell
$Info = Get-LevelDeviceInfo
Write-LevelLog "Running on: $($Info.OS) ($($Info.OSVersion))"
```

### Returns

```powershell
@{
    Hostname   = "WORKSTATION01"
    Username   = "SYSTEM"
    Domain     = "COOLNETWORKS"
    OS         = "Microsoft Windows 11 Pro"
    OSVersion  = "10.0.22631"
    IsAdmin    = $true
    PowerShell = "5.1.22621.2506"
    ScriptPID  = 4832
}
```

---

## Invoke-LevelApiCall

Makes authenticated REST API calls with standardized error handling.

```powershell
$Result = Invoke-LevelApiCall -Uri "https://api.example.com/endpoint" `
                              -ApiKey "{{cf_apikey}}" `
                              -Method "GET"

if ($Result.Success) {
    $Data = $Result.Data
} else {
    Write-LevelLog "API Error: $($Result.Error)" -Level "ERROR"
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Uri` | String | Yes | — | Full API endpoint URL |
| `-ApiKey` | String | Yes | — | Bearer token for authentication |
| `-Method` | String | No | `"GET"` | HTTP method (GET, POST, PUT, DELETE, PATCH) |
| `-Body` | Hashtable | No | — | Request body (converted to JSON) |
| `-TimeoutSec` | Int | No | `30` | Request timeout in seconds |

### Returns

```powershell
# Success
@{ Success = $true; Data = <API Response Object> }

# Failure
@{ Success = $false; Error = "Connection timed out" }
```

### POST Example

```powershell
$Result = Invoke-LevelApiCall -Uri "https://api.example.com/tickets" `
                              -ApiKey "{{cf_apikey}}" `
                              -Method "POST" `
                              -Body @{
                                  title = "Automated Alert"
                                  description = "Disk space low"
                                  priority = "high"
                              }
```

---

## Repair-LevelEmoji

Repairs corrupted UTF-8 emojis in strings. Level.io and other deployment systems may corrupt UTF-8 emojis when deploying scripts. This function detects common corruption patterns and fixes them.

```powershell
$ScriptName = Repair-LevelEmoji -Text $ScriptName
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Text` | String | Yes | The text string that may contain corrupted emojis |

### Supported Emojis

| Emoji | Name | Unicode |
|-------|------|---------|
| ⛔ | Stop sign | U+26D4 |
| 👀 | Eyes | U+1F440 |
| 🙏 | Folded hands | U+1F64F |
| 🚨 | Police light | U+1F6A8 |
| 🛑 | Stop sign octagon | U+1F6D1 |
| ✅ | Check mark | U+2705 |
| 🔚 | End arrow | U+1F51A |
| 🆕 | New button | U+1F195 |
| 🔧 | Wrench | U+1F527 |

### Example

```powershell
# The launcher uses this automatically to fix corrupted script names
$ScriptToRun = Repair-LevelEmoji -Text $ScriptToRun
```

> **Note:** This function is called automatically by the Script Launcher after loading the library. You typically don't need to call it directly unless working with emoji-containing strings in your own scripts.

---

## Get-LevelUrlEncoded

URL-encodes a string with proper UTF-8 handling for emojis. Unlike `[System.Uri]::EscapeDataString()`, this function correctly encodes UTF-8 bytes for use in URLs.

```powershell
$EncodedName = Get-LevelUrlEncoded -Text "👀Test Script.ps1"
# Returns: %F0%9F%91%80Test%20Script.ps1
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Text` | String | Yes | The text string to URL-encode |

**Returns:** URL-encoded string safe for use in HTTP requests.

### Example

```powershell
# Build a URL with an emoji-containing filename
$ScriptUrl = "$BaseUrl/$(Get-LevelUrlEncoded $ScriptToRun)"
```

> **Note:** This function is called automatically by the Script Launcher when downloading scripts. You typically don't need to call it directly unless building custom URLs.

---

## Get-LevelGroups

Retrieves all groups (organizations and folders) from the Level.io API with automatic pagination.

```powershell
$Groups = Get-LevelGroups -ApiKey "{{cf_apikey}}"
$RootGroups = $Groups | Where-Object { -not $_.parent_id }
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ApiKey` | String | Yes | — | Level.io API key (Bearer token) |
| `-BaseUrl` | String | No | `https://api.level.io/v2` | API base URL |

### Returns

Array of group objects with properties: `id`, `name`, `parent_id`, `type` (organization/folder), etc.

Returns `$null` on error.

---

## Get-LevelDevices

Retrieves devices from the Level.io API with automatic pagination.

```powershell
# Get all devices
$AllDevices = Get-LevelDevices -ApiKey "{{cf_apikey}}"

# Get devices in a specific group
$GroupDevices = Get-LevelDevices -ApiKey "{{cf_apikey}}" -GroupId "grp_123abc"

# Include network interface details (for MAC addresses)
$DevicesWithNIC = Get-LevelDevices -ApiKey "{{cf_apikey}}" -IncludeNetworkInterfaces
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ApiKey` | String | Yes | — | Level.io API key (Bearer token) |
| `-GroupId` | String | No | — | Filter by group ID |
| `-IncludeNetworkInterfaces` | Switch | No | `$false` | Include NIC details (MAC addresses) |
| `-BaseUrl` | String | No | `https://api.level.io/v2` | API base URL |

### Returns

Array of device objects with properties: `id`, `hostname`, `os_name`, `group_id`, `network_interfaces` (if requested), etc.

Returns `$null` on error.

---

## Find-LevelDevice

Searches for a specific device by hostname.

```powershell
$Device = Find-LevelDevice -ApiKey "{{cf_apikey}}" -Hostname "WORKSTATION01"
if ($Device) {
    Write-LevelLog "Found device: $($Device.id)"
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ApiKey` | String | Yes | — | Level.io API key (Bearer token) |
| `-Hostname` | String | Yes | — | Exact hostname to search for |
| `-BaseUrl` | String | No | `https://api.level.io/v2` | API base URL |

### Returns

Device object if found, `$null` otherwise.

---

## Send-LevelWakeOnLan

Sends Wake-on-LAN magic packets to wake a device by MAC address.

```powershell
# Wake a device
$Success = Send-LevelWakeOnLan -MacAddress "AA:BB:CC:DD:EE:FF"

# Multiple attempts with longer delay
$Success = Send-LevelWakeOnLan -MacAddress "AA-BB-CC-DD-EE-FF" -Attempts 15 -DelayMs 1000
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-MacAddress` | String | Yes | — | MAC address (accepts `:` or `-` delimiters) |
| `-Attempts` | Int | No | `10` | Number of magic packets to send |
| `-DelayMs` | Int | No | `500` | Delay between packets (milliseconds) |

### Returns

`$true` if packets sent successfully, `$false` on error.

### Requirements

- Target device must have Wake-on-LAN enabled in BIOS/UEFI
- Target NIC must support WOL and have it enabled in device properties
- Sending device must be on the same network segment (or use directed broadcast)

---

## See Also

- [Main README](../README.md)
- [Script Launcher Guide](LAUNCHER.md)
- [Emoji Handling](EMOJI-HANDLING.md)
