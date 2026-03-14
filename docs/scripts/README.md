# Script Documentation

Detailed documentation for each COOLForge script.

## Policy Scripts

See [Policy Documentation](../policy/README.md) for the complete policy enforcement system.

| Script | Documentation | Description |
|--------|---------------|-------------|
| 👀bitwarden | [Bitwarden.md](../policy/Bitwarden.md) | Bitwarden browser extension policy enforcement |
| 👀chrome | [Chrome.md](../policy/Chrome.md) | Google Chrome Enterprise policy enforcement |
| 👀cipp | — | CIPP integration policy script |
| 👀debug | [Debug.md](../policy/Debug.md) | Debug script for policy testing |
| 👀dns | [DNS-Compliance.md](DNS-Compliance.md) | DNS server compliance policy |
| 👀dnsfilter | [DNSFilter.md](../policy/DNSFilter.md) | DNSFilter agent policy enforcement |
| 👀huntress | [Huntress.md](../policy/Huntress.md) | Huntress agent policy enforcement |
| 👀meshcentral | [MeshCentral.md](../policy/MeshCentral.md) | MeshCentral agent policy enforcement |
| 👀screenconnect | [ScreenConnect.md](../policy/ScreenConnect.md) | ScreenConnect agent policy enforcement |
| 👀unchecky | [Unchecky.md](../policy/Unchecky.md) | Unchecky software policy enforcement |
| Windows policies | [Windows.md](../policy/Windows.md) | Windows configuration policies (location services) |
| Chrome policies | [Chrome.md](../policy/Chrome.md#chrome-configuration-policies) | Chrome configuration policies (location services) |

## Check Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| 👀Check for Unauthorized Remote Access Tools | [RAT-Detection.md](RAT-Detection.md) | Detects 60+ RATs with whitelisting support |
| 👀Check Windows Location Services | [Check-Windows-Location.md](Check-Windows-Location.md) | Checks Windows Location Services status |
| 👀Hostname Mismatch | [Hostname-Mismatch.md](Hostname-Mismatch.md) | Detects hostname mismatches with Level.io, auto-renames via API |
| 👀Test Show Versions | [Test-Show-Versions.md](Test-Show-Versions.md) | Library test suite and version info |
| 👀Test Variable Output | [Test-Variable-Output.md](Test-Variable-Output.md) | Level.io automation variable testing |

## Configure Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| ⚙️Configure Power Management for Workstation | — | Configures power management settings |
| ⚙️Configure Wake-on-LAN | [Configure-WOL.md](Configure-WOL.md) | Enables Wake-on-LAN on network adapters |
| ⚙️Extract and Set ScreenConnect Device URL | [ScreenConnect-Device-URL.md](ScreenConnect-Device-URL.md) | Extracts ScreenConnect GUID and sets custom field |

## Fix Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| 🔧Enable System Restore | [System-Restore.md](System-Restore.md) | Enables System Restore and creates restore point |
| 🔧Ensure Windows Defender Enabled | [Defender-Enabled.md](Defender-Enabled.md) | Ensures Windows Defender is enabled and running |
| 🔧Fix Windows 11/10/8.1/8/7 Services | [Fix-Windows-Services.md](Fix-Windows-Services.md) | Restores Windows services to defaults |
| 🔧Fix Windows Location Services | [Fix-Location-Services.md](Fix-Location-Services.md) | Configures Windows Location Services state |
| 🔧Prevent Sleep | [Prevent-Sleep.md](Prevent-Sleep.md) | Temporarily prevents device sleep with auto-restore |

## Remove Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| ⛔Force Remove Adobe Creative Cloud | [Force-Remove-Adobe-CC.md](Force-Remove-Adobe-CC.md) | 6-phase Adobe CC removal with official cleaner tool |
| ⛔Force Remove Dropbox | [Force-Remove-Dropbox.md](Force-Remove-Dropbox.md) | 5-phase Dropbox removal |
| ⛔Force Remove Foxit | [Force-Remove-Foxit.md](Force-Remove-Foxit.md) | Complete Foxit PDF Reader removal |
| ⛔Force Remove McAfee | [Force-Remove-McAfee.md](Force-Remove-McAfee.md) | McAfee security product removal with MCPR fallback |
| ⛔Force Remove Non MSP ScreenConnect | [Force-Remove-Non-MSP-ScreenConnect.md](Force-Remove-Non-MSP-ScreenConnect.md) | Removes unauthorized ScreenConnect instances |
| ⛔Remove All RATs | [Remove-All-RATs.md](Remove-All-RATs.md) | Detects and removes 70+ remote access tools |

### Deprecated Remove Scripts

| Script | Documentation | Status |
|--------|---------------|--------|
| ⛔Force Remove AnyDesk | [Force-Remove-AnyDesk.md](Force-Remove-AnyDesk.md) | Replaced by Remove All RATs |

## Utility Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| ⚙️COOLForge Cache Sync | [Cache-Sync.md](Cache-Sync.md) | Synchronizes local registry cache with Level.io |
| ⚙️Cleanup VoyagerPACS Studies | [VoyagerPACS-Cleanup.md](VoyagerPACS-Cleanup.md) | Cleans up old PACS imaging studies |
| ⚙️Remove COOLForge Scratch Folder | — | Removes the COOLForge scratch folder from a device |
| ⚙️Universal Disk Cleaner | [Disk-Cleaner.md](Disk-Cleaner.md) | Cleans temporary files and frees disk space |
| 🙏Wake all devices | [Wake-Devices.md](Wake-Devices.md) | Wake-on-LAN for folder hierarchy |
| 🔔Technician Alert Monitor | [Technician-Alert-Monitor.md](Technician-Alert-Monitor.md) | Toast notifications for tech alerts |
| 🔔Wake tagged devices | [Wake-Tagged-Devices.md](Wake-Tagged-Devices.md) | Sends WOL packets to devices with specific tags |

### Moved/Replaced Scripts

| Script | Documentation | Status |
|--------|---------------|--------|
| 👀Check DNS Server Compliance | [Check-DNS-Compliance.md](Check-DNS-Compliance.md) | Replaced by DNS policy script (`👀dns.ps1`) |

## Documentation Format

Each script documentation includes:

- **Purpose** - What the script does
- **Features** - Key capabilities
- **Exit Codes** - Return values and meanings
- **Custom Fields** - Required/optional Level.io fields
- **Tag Support** - Emoji tags that affect behavior
- **Usage** - How to deploy and use
- **Related Scripts** - Links to related functionality
