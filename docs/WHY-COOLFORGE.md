# Why Use COOLForge Library

This document covers the benefits of using COOLForge-Common.psm1 for Level.io automation scripts.

---

## Table of Contents

- [Script Infrastructure](#script-infrastructure)
- [Level.io API Integration](#levelio-api-integration)
- [Software Policy System](#software-policy-system)
- [Software Detection & Removal](#software-detection--removal)
- [Resilience & Caching](#resilience--caching)
- [Launcher System](#launcher-system)
- [Technician Alerts](#technician-alerts)
- [Admin Tools](#admin-tools)
- [URL & Text Handling](#url--text-handling)

---

## Script Infrastructure

### Lockfile Management
Prevents multiple instances of the same script running simultaneously. No more "script already running" conflicts or race conditions.

### Tag-Based Gating
Block scripts from running on certain devices with tags. Apply a blocking tag and that script won't execute. Instant kill switch without redeploying.

### Standardized Logging
`Write-LevelLog` gives you timestamped, prefixed output:
- `[*]` INFO - General information
- `[+]` SUCCESS - Successful completions
- `[!]` WARN - Warnings (non-fatal)
- `[X]` ERROR - Errors and failures

Consistent output across all scripts.

### Exit Code Handling
`Complete-LevelScript` ensures clean exit with proper lockfile cleanup. No orphaned lockfiles from crashed scripts.

---

## Level.io API Integration

### Device Management
Find devices, get device info, rename devices via API:
- `Find-LevelDevice` - Search by hostname
- `Get-LevelDeviceById` - Get device by ID
- `Set-LevelDeviceName` - Rename devices

### Tag Operations
Full tag CRUD operations:
- `Get-LevelTags` - List all tags
- `Find-LevelTag` - Find tag by name
- `Add-LevelTagToDevice` - Apply tag to device
- `Remove-LevelTagFromDevice` - Remove tag from device

Scripts can self-tag devices based on conditions.

### Custom Field Management
Read/write custom fields programmatically:
- `Get-LevelCustomFields` - List fields
- `Find-LevelCustomField` - Find by name
- `Set-LevelCustomFieldValue` - Update values
- `New-LevelCustomField` - Create fields

Scripts can store state in Level.io.

### Group/Hierarchy Navigation
Walk the Level.io tree for bulk operations:
- `Get-LevelOrganizations` - List orgs
- `Get-LevelOrganizationFolders` - List folders
- `Get-LevelFolderDevices` - Get devices in folder

---

## Software Policy System

### Emoji Tag Parsing
Device tags like `🙏chrome`, `🚫anydesk`, `📌huntress` control software state. `Get-SoftwarePolicy` parses tags with priority resolution.

### Emoji Corruption Handling
Level.io corrupts UTF-8 emojis in variables. `Get-EmojiMap` and `Repair-LevelEmoji` fix this automatically. Tags work even when mangled.

### Policy Field + Tag Override
Custom fields set baseline policy (`policy_chrome = install`), but tags override for individual devices. Hierarchical control with per-device exceptions.

### Install Mode Logic
`Invoke-SoftwarePolicyCheck` handles "install if missing" vs "reinstall always" modes. One function, consistent behavior across all software scripts.

---

## Software Detection & Removal

### Multi-Source Detection
`Test-SoftwareInstalled` checks multiple locations:
- Running processes
- Windows services
- Registry uninstall entries
- File system paths

Catches software that hides from any single detection method.

### Process/Service Stopping
Kill running software before removal:
- `Stop-SoftwareProcesses` - Kill matching processes
- `Stop-SoftwareServices` - Stop and optionally disable services

Prevents "file in use" errors during uninstall.

### Uninstall String Discovery
`Get-SoftwareUninstallString` finds uninstall commands from registry. Works with both x64 and x86 installs, supports quiet uninstall strings.

---

## Resilience & Caching

### Registry Cache Fallback
Store and retrieve values from `HKLM:\SOFTWARE\COOLForge\Cache`:
- `Set-LevelCacheValue` - Cache a value
- `Get-LevelCacheValue` - Retrieve cached value

If Level.io variable injection fails, scripts use cached values. Scripts don't break from one-off Level.io hiccups.

### Installer Retry Logic
Handle transient installation failures:
- `Install-MsiWithRetry` - MSI with automatic retry
- `Install-ExeWithRetry` - EXE with automatic retry

Automatic retry with backoff for network/timing issues.

### API Call Standardization
`Invoke-LevelApiCall` handles:
- Authentication headers
- Error handling
- Timeouts
- Response parsing

No raw `Invoke-RestMethod` calls scattered everywhere.

---

## Launcher System

### Single Deployment Model
Deploy launcher once to Level.io, scripts live in GitHub. Update GitHub = all endpoints get updates automatically. No per-script redeployment.

### MD5 Verification
Scripts verified against `MD5SUMS` before execution. Tampered or corrupt downloads are detected and rejected. Integrity guaranteed.

### Version Checking
Launchers self-check against `LAUNCHER-VERSIONS.json`. Tells you when the Level.io copy is outdated and needs updating.

### Automatic Library Updates
Library updates itself when hash changes in `MD5SUMS`. No manual redeployment for library fixes.

---

## Technician Alerts

### Toast Notifications to Techs
`Send-TechnicianAlert` pushes alerts to technician workstations. Script failures become desktop notifications instead of buried in logs.

### Alert Queuing
`Add-TechnicianAlert` queues alerts during script execution. All alerts sent in a single API call at script completion. Efficient batching.

### Priority & Routing
Alerts support:
- Priority levels (Low, Normal, High, Critical)
- Routing to specific technicians
- Expiration times

Critical issues get attention.

---

## Admin Tools

### Config Storage
Persist API keys and settings securely for admin tools:
- `Save-Config` - Store configuration
- `Get-SavedConfig` - Retrieve configuration
- `Protect-ApiKey` / `Unprotect-ApiKey` - Secure storage

### Backup/Restore
Disaster recovery for Level.io configuration:
- `Backup-AllCustomFields` - Export all fields
- `Restore-CustomFields` - Import from backup
- `Compare-BackupWithCurrent` - Diff backups

### UI Helpers
Interactive admin scripts with consistent formatting:
- `Write-Header` - Section headers
- `Read-YesNo` - Yes/No prompts
- `Read-UserInput` - Text input

---

## URL & Text Handling

### Proper URL Encoding
`Get-LevelUrlEncoded` correctly encodes UTF-8 emojis in URLs. GitHub raw URLs with emoji filenames work correctly.

### Wake-on-LAN
`Send-LevelWakeOnLan` sends magic packets to wake devices. Useful for maintenance windows on sleeping machines.

---

## Summary

The COOLForge library eliminates boilerplate, handles edge cases, and provides consistent patterns across all scripts. Write the business logic, not the infrastructure.

| Without Library | With Library |
|-----------------|--------------|
| Write lockfile logic every script | `Initialize-LevelScript` |
| Parse emoji tags manually | `Get-SoftwarePolicy` |
| Handle API auth/errors everywhere | `Invoke-LevelApiCall` |
| Hope downloads aren't corrupt | MD5 verification built-in |
| Scripts break when Level.io hiccups | Registry cache fallback |
| Different logging in every script | `Write-LevelLog` standard |

---

## See Also

- [Function Reference](FUNCTIONS.md)
- [Script Launcher Guide](LAUNCHER.md)
- [Variables Reference](VARIABLES.md)
- [Policy Fields](POLICY-FIELDS.md)
