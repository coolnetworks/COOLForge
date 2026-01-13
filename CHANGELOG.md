# Changelog

All notable changes to COOLForge_Lib will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Calendar Versioning](https://calver.org/) (YYYY.MM.DD.N).

## [Unreleased]

## [v2025.12.30] - 2025-12-30

### Added
- **Terminology section** in README explaining Module, Script, Launcher, Template, Custom Field
- **Module functions summary** table in README showing all 14 exported functions
- **Launcher usage guide** with step-by-step instructions for deploying to Level.io
- **Auto-update test script** (`testing/Test_AutoUpdate_Dev.ps1`) for dev branch testing
- **Documentation for 4 additional functions**: `Get-LevelGroups`, `Get-LevelDevices`, `Find-LevelDevice`, `Send-LevelWakeOnLan`

### Changed
- Renamed project from COOLForgeLib to COOLForge_Lib throughout codebase
- Config filename changed from `.COOLForgeLib-setup.json` to `.COOLForge_Lib-setup.json`
- Fixed regex bug in launchers: URL path now uses `/COOLForge/` instead of `/COOLForgeLib/`
- Updated benefits section to emphasize Git-based script management

## [v2025.12.29] - 2025-12-29

### Added
- **Version pinning** via `CoolForge_pin_psmodule_to_version` custom field
  - Pin devices to specific release tags (e.g., `v2025.12.29`)
  - Enables staged rollouts, rollback capability, and production stability
  - Launchers v2025.12.29.01 updated with version pinning support
- **Setup wizard** (`start_here/Setup-COOLForge.ps1`)
  - Interactive script to create and configure Level.io custom fields
  - Uses Level.io API to check existing fields and create missing ones
  - Suggests version pinning for stability
  - Handles both required and optional fields

### Changed
- Launcher template and all launchers updated to v2025.12.29.01
- README updated with Version Pinning section and Automated Setup instructions

## [v2025.12.29-prev] - 2025-12-29

### Added
- **Test Variable Output script** (`👀Test Variable Output.ps1`) - Demonstrates all methods for setting Level.io automation variables
  - Configurable via `$VariablesToSet` parameter (use "all" or comma-separated list)
  - Tests strings, numbers, booleans, dates, system info, JSON, special characters, and more
- **Automation Variables documentation** - New README section explaining `{{variable_name=value}}` syntax
- **tools/ folder** with `Update-MD5SUMS.ps1` for generating file checksums

### Fixed
- Launcher `$ScriptToRun` values now correctly point to their respective scripts
  - `⛔Force Remove Anydesk.ps1`
  - `⛔Force Remove Non MSP ScreenConnect.ps1`
  - `👀Check for Unauthorized Remote Access Tools.ps1`

## [v2025.12.27] - 2025-12-27

### Added
- **Emoji encoding repair** - `Repair-LevelEmoji` function fixes UTF-8 emoji corruption from Level.io deployment
  - Supports: ⛔ 👀 🙏 🚨 🛑 ✅ 🔚 🆕
  - Handles multiple corruption patterns (UTF-8 byte interpretation, Level.io-specific encoding)
- **URL encoding** - `Get-LevelUrlEncoded` function for proper UTF-8 emoji handling in URLs
- **MD5 checksum verification** - Scripts and library are verified against `MD5SUMS` file
- **Script Launcher** - Run scripts from GitHub without redeploying to Level.io
  - Automatic version checking and updates
  - Backup/restore safety for corrupted downloads
  - All Level.io variables passed to downloaded scripts
- **RAT detection script** (`👀Check for Unauthorized Remote Access Tools.ps1`)
  - Detects 60+ remote access tools
  - ScreenConnect whitelisting via instance ID
  - Authorized RMM tools whitelist
- **ScreenConnect removal script** (`⛔Force Remove Non MSP ScreenConnect.ps1`)
  - 5-phase removal process (graceful to forceful)
  - MSP instance ID whitelisting
- **Default library URL** - Scripts work without `ps_module_library_source` custom field

### Changed
- Library URL is now optional (defaults to official repository)
- Improved library auto-update with backup/restore logic

## [v2025.12.27-initial] - 2025-12-27

### Added
- Initial release of COOLForge_Lib
- **Core library** (`COOLForge-Common.psm1`) with functions:
  - `Initialize-LevelScript` - Tag gate system, lockfile management
  - `Write-LevelLog` - Standardized timestamped logging
  - `Invoke-LevelScript` - Wrapped execution with error handling
  - `Complete-LevelScript` - Clean exit with custom messages
  - `Remove-LevelLockFile` - Manual lockfile cleanup
  - `Test-LevelAdmin` - Administrator privilege check
  - `Get-LevelDeviceInfo` - Common device properties
  - `Invoke-LevelApiCall` - REST API helper with bearer auth
- **Script template** for creating new scripts
- **Launcher template** for GitHub-based script deployment
- **AnyDesk removal script** (`⛔Force Remove Anydesk.ps1`)
- **Test script** (`👀Test Show Versions.ps1`)
