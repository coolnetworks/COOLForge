# Test Show Versions Script

**Script:** `scripts/Check/👀Test Show Versions.ps1`
**Launcher:** `launchers/👀Test Show Versions.ps1`
**Version:** 2025.12.27.03
**Category:** Check

## Purpose

Comprehensive test script that verifies all COOLForge-Common library functions and displays version/device information.

## Features

Tests all exported library functions:

| Function | Test Coverage |
|----------|--------------|
| `Write-LevelLog` | All severity levels (INFO, WARN, ERROR, SUCCESS, SKIP, DEBUG) |
| `Test-LevelAdmin` | Returns boolean administrator status |
| `Get-LevelDeviceInfo` | All 8 properties (Hostname, Username, Domain, OS, etc.) |
| `Initialize-LevelScript` | Tag gating, lockfile management, stale lockfile cleanup |
| `Remove-LevelLockFile` | Lockfile removal verification |
| `Complete-LevelScript` | Function existence check |
| `Invoke-LevelScript` | Function existence check |
| `Invoke-LevelApiCall` | HTTP GET request and error handling |

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | All tests passed |
| 1 | Alert | One or more tests failed |

## Output Sections

### Device Information
- Hostname, Username, Domain
- OS and OS Version
- PowerShell version
- Administrator status

### Library Version
- COOLForge-Common.psm1 version from cached library

### Cached Scripts
- Lists all scripts in `$MspScratchFolder\Scripts\` with versions

### Configuration
- Scratch folder path
- Library URL
- Device tags

### Folder Structure
- Contents of MSP scratch folder

### Test Results
- Individual test pass/fail status
- Summary with total passed/failed count

## Use Cases

1. **Verify deployment** - Confirm library is correctly installed
2. **Troubleshoot issues** - Check function availability and behavior
3. **Version audit** - See all component versions across endpoints
4. **API connectivity** - Verify API calls work (tests httpbin.org)
