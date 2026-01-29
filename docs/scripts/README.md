# Script Documentation

Detailed documentation for each COOLForge script.

## Policy Scripts

See [Policy Documentation](../policy/README.md) for the complete policy enforcement system.

| Script | Documentation | Description |
|--------|---------------|-------------|
| 👀chrome | [Chrome.md](../policy/Chrome.md) | Google Chrome Enterprise policy enforcement |
| 👀dnsfilter | [DNSFilter.md](../policy/DNSFilter.md) | DNSFilter policy enforcement |
| 👀huntress | [Huntress.md](../policy/Huntress.md) | Huntress agent policy enforcement |
| 👀meshcentral | [MeshCentral.md](../policy/MeshCentral.md) | MeshCentral agent policy enforcement |
| 👀screenconnect | [ScreenConnect.md](../policy/ScreenConnect.md) | ScreenConnect agent policy enforcement |
| 👀unchecky | [Unchecky.md](../policy/Unchecky.md) | Unchecky software policy enforcement |
| 👀debug | [Debug.md](../policy/Debug.md) | Debug script for policy testing |

## Check Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| 👀Check DNS Server Compliance | [Check-DNS-Compliance.md](Check-DNS-Compliance.md) | Validates device DNS settings match expected config |
| 👀Check for Unauthorized Remote Access Tools | [RAT-Detection.md](RAT-Detection.md) | Detects 60+ RATs with whitelisting support |
| 👀Check Windows Location Services | [Check-Windows-Location.md](Check-Windows-Location.md) | Checks Windows Location Services status |
| 👀Hostname Mismatch | [Hostname-Mismatch.md](Hostname-Mismatch.md) | Detects hostname mismatches with Level.io |
| 👀Test Show Versions | [Test-Show-Versions.md](Test-Show-Versions.md) | Library test suite and version info |
| 👀Test Variable Output | [Test-Variable-Output.md](Test-Variable-Output.md) | Level.io automation variable testing |

## Configure Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| ⚙️Configure Wake-on-LAN | [Configure-WOL.md](Configure-WOL.md) | Enables Wake-on-LAN on network adapters |
| ⚙️Extract and Set ScreenConnect Device URL | [ScreenConnect-Device-URL.md](ScreenConnect-Device-URL.md) | Extracts ScreenConnect GUID and sets custom field |

## Fix Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| 🔧Ensure Windows Defender Enabled | [Defender-Enabled.md](Defender-Enabled.md) | Ensures Windows Defender is enabled and running |
| 🔧Fix Windows 11/10/8.1/8/7 Services | [Fix-Windows-Services.md](Fix-Windows-Services.md) | Restores Windows services to defaults |
| 🔧Fix Windows Location Services | [Fix-Location-Services.md](Fix-Location-Services.md) | Configures Windows Location Services state |
| 🔧Prevent Sleep | [Prevent-Sleep.md](Prevent-Sleep.md) | Temporarily prevents device sleep with auto-restore |
| 🔧Enable System Restore | [System-Restore.md](System-Restore.md) | Enables System Restore and creates restore point |

## Remove Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| ⛔Force Remove Adobe Creative Cloud | [Force-Remove-Adobe-CC.md](Force-Remove-Adobe-CC.md) | 6-phase Adobe CC removal with official cleaner tool |
| ⛔Force Remove Anydesk | [Force-Remove-AnyDesk.md](Force-Remove-AnyDesk.md) | 5-phase AnyDesk removal |
| ⛔Force Remove Non MSP ScreenConnect | [Force-Remove-Non-MSP-ScreenConnect.md](Force-Remove-Non-MSP-ScreenConnect.md) | Removes unauthorized ScreenConnect instances |

## Utility Scripts

| Script | Documentation | Description |
|--------|---------------|-------------|
| ⚙️COOLForge Cache Sync | [Cache-Sync.md](Cache-Sync.md) | Synchronizes local registry cache with Level.io |
| ⚙️Cleanup VoyagerPACS Studies | [VoyagerPACS-Cleanup.md](VoyagerPACS-Cleanup.md) | Cleans up old PACS imaging studies |
| ⚙️Universal Disk Cleaner | [Disk-Cleaner.md](Disk-Cleaner.md) | Cleans temporary files and frees disk space |
| 🙏Wake all devices | [Wake-Devices.md](Wake-Devices.md) | Wake-on-LAN for folder hierarchy |
| 🔔Technician Alert Monitor | [Technician-Alert-Monitor.md](Technician-Alert-Monitor.md) | Toast notifications for tech alerts |
| 🔔Wake tagged devices | [Wake-Tagged-Devices.md](Wake-Tagged-Devices.md) | Sends WOL packets to devices with specific tags |

## Documentation Format

Each script documentation includes:

- **Purpose** - What the script does
- **Features** - Key capabilities
- **Exit Codes** - Return values and meanings
- **Custom Fields** - Required/optional Level.io fields
- **Tag Support** - Emoji tags that affect behavior
- **Usage** - How to deploy and use
- **Related Scripts** - Links to related functionality
