# Changelog

All notable changes to COOLForge_Lib will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Calendar Versioning](https://calver.org/) (YYYY.MM.DD.N).

## [Unreleased]

## [2026.02.01.01] - 2026-02-01

### Added
- **CIPP browser extension policy** (`👀cipp.ps1`) — manages CyberDrain CIPP extension for Chrome and Edge via ExtensionSettings registry policies, 3rdparty managed storage with custom branding, and tenant ID binding via `policy_cipp_tenantid`
- **Bitwarden browser extension policy** (`👀bitwarden.ps1`) — manages Bitwarden extension for Chrome and Edge, cleans up user-installed duplicates from ExtensionInstallForcelist
- **Force Remove Dropbox** (`⛔Force Remove Dropbox.ps1`) — standalone removal script
- **Force Remove Foxit** (`⛔Force Remove Foxit.ps1`) — standalone removal script
- **Force Remove McAfee** (`⛔Force Remove McAfee.ps1`) — standalone removal script
- **`policy_ok_rats` whitelist** — RAT detection script now supports auto-baseline on first run, storing approved tools in a custom field
- **`policy_other_msp_screenconnect`** field for whitelisting partner ScreenConnect instances in Non MSP removal script
- **Field self-bootstrapping** for CIPP (`policy_cipp_tenantid`), RAT detection (`policy_ok_rats`), and Non MSP ScreenConnect removal (`policy_other_msp_screenconnect`)
- Launchers for all new scripts

### Changed
- **RAT detection script** upgraded with comprehensive removal capabilities for AnyDesk, TeamViewer, RustDesk, Splashtop, and Chrome Remote Desktop
- **Non MSP ScreenConnect removal** now supports partner instance whitelisting

### Removed
- **Standalone AnyDesk removal script** — consolidated into the RAT detection script

## [2026.01.31] - 2026-01-31

### Added
- **`TagName` parameter** on `Initialize-SoftwarePolicyInfrastructure` — allows scripts to use a different name for tags vs custom fields (e.g. ScreenConnect uses `SC` tags but `policy_screenconnect` fields)
- **Stale field cleanup** — when `TagName` differs from `SoftwareName`, any leftover `policy_$TagName` field (e.g. `policy_sc`) is automatically detected and deleted
- **`Get-BinariesFolder`** function in library — shared installer storage under the scratch folder's `binaries/` directory
- **PE header validation** in MeshCentral script — verifies downloaded `.exe` starts with `MZ` before attempting install

### Changed
- **ScreenConnect script** now passes `-SoftwareName "screenconnect" -TagName "sc"` to `Initialize-SoftwarePolicyInfrastructure`, fixing the `policy_sc` vs `policy_screenconnect` field name mismatch
- **ScreenConnect script** version bumped to `2026.01.31.01`
- **MeshCentral script** installer changed from `.msh` to `.exe` with `-fullinstall` flag, added `Unblock-File` for MOTW, uses `Get-BinariesFolder` for storage
- **MeshCentral script** version bumped to `2026.01.31.01`

### Fixed
- **`tools/Update-MD5Sums.ps1`** now strips UTF-8 BOM before hashing, matching the launcher's `Get-ContentMD5` verification method — previously generated incorrect hashes for BOM files causing perpetual library re-downloads
- **MD5SUMS** recomputed with BOM-stripped method for all files

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
