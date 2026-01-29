# Wake-on-LAN Configuration

Configures Windows workstations for Wake-on-LAN (WOL) with intelligent power settings based on adapter capabilities.

## Quick Start

1. Deploy the script via Level.io
2. Run on target devices
3. Restart devices for changes to take effect
4. Ensure BIOS/UEFI has WOL enabled

## What It Does

### Network Adapter Configuration

| Setting | Wired | Wireless | Purpose |
|---------|-------|----------|---------|
| WakeOnMagicPacket | Yes | Yes | Wake when magic packet received |
| WakeOnPattern | Yes | Yes | Wake on pattern match |
| WoWLAN | No | Yes | Wireless Wake-on-LAN |
| Energy Efficient Ethernet | Disabled | N/A | EEE can block WOL |
| Power Saving Mode | Disabled | Disabled | Keeps NIC active |

### Adaptive Power Settings

The script intelligently configures power settings based on detected adapter capabilities:

#### Always Applied

| Setting | Action | Why |
|---------|--------|-----|
| Hibernation | Disabled | Hibernating devices can't receive WOL |
| Fast Startup | Disabled | Hybrid shutdown blocks WOL |
| Hybrid Sleep | Disabled | Combination of sleep and hibernate |
| Wake Timers | Enabled | Allows scheduled tasks to wake device |

#### Modern Standby-Compatible Devices

The script preserves Modern Standby when it detects adapters that support wake from it:

**WoWLAN (Wireless)**
- Wireless adapters with `*WoWLAN` or `Wake on WLAN` properties
- Common on modern laptops

**Wired D0ix/Directed WoL**
- Intel I219, I225, I226 series NICs
- Realtek 2.5G gaming NICs
- Killer E3100/E3200 NICs
- Any NIC with `*ModernStandbyWoLMagicPacket` property

| Setting | Action | Why |
|---------|--------|-----|
| Modern Standby | **Preserved** | Adapter supports wake from Modern Standby |
| Connected Standby | **Preserved** | Required for Modern Standby wake |

Benefits: Better battery life, instant wake, no S3 compatibility issues.

#### Legacy Wired Adapters

If no Modern Standby-compatible adapter is found:

| Setting | Action | Why |
|---------|--------|-----|
| Modern Standby | Disabled | Traditional WOL requires S3 sleep |
| Connected Standby | Disabled | Not compatible with legacy WOL |

This ensures traditional magic packet WOL works on older NICs that need S3 sleep state.

## Requirements

### BIOS/UEFI Settings

WOL must be enabled at the hardware level. Common BIOS setting names:
- Wake on LAN
- Wake on PCI/PCIe
- Power On by PME
- Resume by LAN
- Boot on LAN

### Network Requirements

- Device must be connected to network (wired or wireless)
- Router/switch must support WOL pass-through for remote wake
- For wireless WOL (WoWLAN): device must stay associated with AP during sleep

## Files

| File | Path | Purpose |
|------|------|---------|
| Configure WOL | `scripts/Configure/Configure Wake-on-LAN.ps1` | Configure adapters and power settings |
| Wake Tagged | `scripts/Utility/Wake tagged devices.ps1` | Wake devices with `🔔WAKEME` tag |
| Wake Tagged Launcher | `launchers/🔔Wake tagged devices.ps1` | Deploy to Level.io as policy monitor |
| Wake Folder | `scripts/Utility/Wake all devices in parent to level.io folder.ps1` | Wake all devices in folder hierarchy |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - at least one adapter configured |
| 1 | Failure - no adapters found or admin rights missing |

## Sending WOL Packets

### Wake Tagged Devices (Recommended)

Tag a device with `🔔WAKEME` to request wake. Online peer devices in the same folder will send WOL packets.

**How it works:**
1. Deploy `scripts/Utility/Wake tagged devices.ps1` as a policy monitor (runs every 2 min)
2. Each online device checks its **parent folder** and all subfolders for peers with `🔔WAKEME` tag
3. Online devices send WOL packets to tagged peers from the local network
4. State is saved to `WakeState` folder in MSP scratch directory
5. On subsequent runs, script checks if devices came online
6. After 5 minutes, creates an alert if device still offline
7. Remove the tag manually once the device is online

**State tracking:**
- State files stored in `{{cf_coolforge_msp_scratch_folder}}\WakeState\`
- Each pending wake has a JSON file with device ID, name, MAC, and timestamp
- State is cleaned up when tag is removed or device comes online

**Why this approach:**
- WOL packets originate from the same subnet (much more reliable)
- No central server needed to reach across network boundaries
- Every online device acts as a WOL relay for its folder group
- Non-blocking: script runs quickly every 2 minutes
- Automatic alerting when devices need manual intervention

Use cases:
- User requests wake before arriving at office
- Technician needs specific device online
- Scheduled wake without affecting entire site

### Wake All Devices in Folder

Use to wake all devices in a folder hierarchy:
`scripts/Utility/Wake all devices in parent to level.io folder.ps1`

### Wake Methods Used

The `Send-LevelWakeOnLan` function uses all available methods:

| Method | Description |
|--------|-------------|
| UDP Port 9 | Standard WOL port |
| UDP Port 7 | Echo port (fallback) |
| Directed Subnet Broadcast | Sends to each local subnet's broadcast address |
| Global Broadcast | Sends to 255.255.255.255 |

This multi-method approach increases reliability across different network configurations.

### From PowerShell (using COOLForge)

```powershell
# Import the module
Import-Module "C:\ProgramData\MSP\Libraries\COOLForge-Common.psm1"

# Send WOL using all methods
Send-LevelWakeOnLan -MacAddress "AA:BB:CC:DD:EE:FF"

# With SecureOn password (if NIC requires it)
Send-LevelWakeOnLan -MacAddress "AA:BB:CC:DD:EE:FF" -SecureOn "11:22:33:44:55:66"
```

## Troubleshooting

### Device Won't Wake

1. **Check BIOS** - WOL must be enabled at hardware level
2. **Restart required** - Power settings changes need reboot
3. **Check adapter** - Some adapters don't support WOL
4. **Network path** - Router may block broadcast packets

### Wireless WOL Not Working

- Not all wireless adapters support WoWLAN
- Device must maintain AP association during sleep
- Some APs don't forward WOL to sleeping clients

### Verifying WOL is Enabled

```powershell
# Check adapter WOL settings
Get-NetAdapterAdvancedProperty -Name "Ethernet" | Where-Object { $_.DisplayName -like "*Wake*" }

# Check power management
powercfg /availablesleepstates
```

## Version History

| Version | Changes |
|---------|---------|
| 2026.01.13.04 | Wake tagged devices: state-based tracking, non-blocking 2-min poll, alert on failure |
| 2026.01.13.03 | Add wired Modern Standby wake detection (Intel I219/I225/I226, Realtek 2.5G) |
| 2026.01.13.02 | Adaptive power settings - preserve Modern Standby when WoWLAN available |
| 2026.01.13.01 | Initial release |
