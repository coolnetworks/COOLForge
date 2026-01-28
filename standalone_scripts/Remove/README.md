# Offline RAT Removal & Security Toolkit

Standalone tools for detecting and removing unauthorized remote access tools (RATs) from Windows systems. Designed for offline/field use - no COOLForge library or internet required after USB creation.

## Quick Start

### Option 1: Full Security Toolkit (Recommended)

1. Run `Copy-SecurityToolkit-ToUSB.cmd` on a computer with internet
2. Insert the USB into the target computer
3. Right-click `Run-SecurityScan.cmd` → "Run as administrator"
4. Follow the 8-step guided process

### Option 2: RAT Removal Only

1. Run `Copy-ToUSB.cmd` on a computer with internet
2. Insert the USB into the target computer
3. Right-click `Remove-AllRATs-Launcher.cmd` → "Run as administrator"
4. Review scan results, confirm removal if needed

## Files

### Launchers & Copiers

| File | Description |
|------|-------------|
| `Copy-SecurityToolkit-ToUSB.cmd` | Creates full toolkit USB with 5 scanning tools |
| `Copy-ToUSB.cmd` | Creates simple USB with RAT removal + MRT only |
| `Remove-AllRATs-Launcher.cmd` | Main entry point - runs scan then removal |

### PowerShell Scripts

| File | Description |
|------|-------------|
| `Remove-AllRATs-Standalone.ps1` | Comprehensive RAT removal (70+ tools) |
| `Check-SecurityBaseline.ps1` | 36-section Windows security audit |
| `Remove-AnyDesk-Standalone.ps1` | Single-tool AnyDesk remover |
| `Remove-NonMspScreenConnect-Standalone.ps1` | ScreenConnect remover (preserves authorized instance) |

## Full Security Toolkit Contents

When using `Copy-SecurityToolkit-ToUSB.cmd`, the USB will contain:

### Detection Tools (Phase 1 - No Changes Made)
1. **Security Baseline Checker** - Defender, exclusions, UAC, keyloggers, firewall, persistence
2. **Autoruns** (Sysinternals) - Enumerate all auto-start locations
3. **PersistenceSniper** - PowerShell persistence detector (MITRE ATT&CK mapped)
4. **Trawler** - IR-focused persistence scanner with allow lists
5. **LOKI** - IOC and YARA signature scanner

### Remediation Tools (Phase 2 - Requires Confirmation)
6. **Microsoft MRT** - Malicious Software Removal Tool
7. **RAT Removal Toolkit** - Remove unauthorized remote access tools

### System Integrity (Phase 3 - Repair)
8. **SFC/DISM/CHKDSK** - System file and disk repair

## Security Baseline Checker (36 Sections)

### Core Security (1-14)
- Windows Defender status, exclusions, tamper protection
- Firewall profiles (Domain, Private, Public)
- UAC configuration
- User accounts audit
- Keylogger indicators (hooks, processes, drivers)
- SMBv1, RDP, Secure Boot, BitLocker
- DNS hijacking, hosts file, proxy settings
- Rogue root certificates (Superfish, eDellRoot, etc.)
- Credential protection (LSA, WDigest, Credential Guard)
- Advanced persistence (WMI, IFEO, AppInit_DLLs)
- System recovery (VSS, Windows RE)
- Scheduled tasks and startup items

### Advanced Checks (15-22)
- Browser extensions (Chrome, Edge, Firefox)
- Recently modified executables
- Alternate Data Streams (ADS)
- Print Monitor DLLs
- Security Support Providers (SSP)
- Netsh Helper DLLs
- Office add-ins
- Recently accessed files and Prefetch

### Incident Response (23-36)
- Temp files audit
- Proxy hijacking
- Browser hijacking
- File association hijacking
- Event log analysis
- SMART disk health
- Executables in suspicious locations
- Network indicators
- USB device history
- Ransomware indicators
- PowerShell history
- IFEO extended checks
- Broken shortcuts
- Windows policies hijacking

## RAT Detection Coverage

### High Priority
- AnyDesk, TeamViewer, RustDesk, Splashtop
- ScreenConnect/ConnectWise Control (with instance verification)
- LogMeIn, GoToAssist, GoToMyPC, RemotePC
- BeyondTrust/Bomgar, DWService

### VNC Variants
- RealVNC, TightVNC, UltraVNC, TigerVNC

### Other Remote Tools
- Radmin, Chrome Remote Desktop, Ammyy Admin
- SimpleHelp, Supremo, Zoho Assist, ISL Online
- Parsec, Meshcentral, Fleetdeck, Tactical RMM
- UltraViewer, ToDesk, Sunlogin, HopToDesk
- AweSun, Dameware, NetSupport, Remote Utilities
- NoMachine, LiteManager, and more...

### Known Malicious RATs (Critical Priority)
- Remcos RAT, QuasarRAT, AsyncRAT
- njRAT, NanoCore, DarkComet
- Orcus RAT, NetWire RAT, Warzone RAT
- Gh0st RAT, Cobalt Strike

### Whitelisted (Never Removed)
- **Level.io** - Authorized RMM

### Verified Before Removal
- **ScreenConnect** - Prompts to confirm if it's your authorized instance

## Usage Examples

### Run Security Baseline Check Only
```powershell
powershell -ExecutionPolicy Bypass -File .\Check-SecurityBaseline.ps1
powershell -ExecutionPolicy Bypass -File .\Check-SecurityBaseline.ps1 -OutputPath "C:\Reports"
```

### Run RAT Removal (Interactive)
```powershell
powershell -ExecutionPolicy Bypass -File .\Remove-AllRATs-Standalone.ps1
```

### Run RAT Removal (Scan Only - No Changes)
```powershell
powershell -ExecutionPolicy Bypass -File .\Remove-AllRATs-Standalone.ps1 -WhatIf
```

### Run RAT Removal (Automated - Skip Prompts)
```powershell
powershell -ExecutionPolicy Bypass -File .\Remove-AllRATs-Standalone.ps1 -Force
```

### Pre-authorize ScreenConnect Instance
```powershell
powershell -ExecutionPolicy Bypass -File .\Remove-AllRATs-Standalone.ps1 -ScreenConnectInstanceId "abc123def456"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - No RATs found or all removed |
| 1 | Alert - RATs detected or removal failed |

## Requirements

- Windows 7/8/8.1/10/11
- Administrator privileges
- PowerShell 5.0+ (built into Windows 10+)

## Offline Operation

All tools work offline after USB creation:
- Security Baseline: Fully offline
- Autoruns: Fully offline
- PersistenceSniper: Fully offline
- Trawler: Fully offline
- LOKI: Offline with pre-downloaded signatures
- MRT: Fully offline
- RAT Removal: Fully offline

To update LOKI signatures when online:
```
Loki\loki\loki-upgrader.exe
```

## License

AGPL-3.0 - See [LICENSE](../../LICENSE)

Copyright (c) 2025-2026 COOLNETWORKS
