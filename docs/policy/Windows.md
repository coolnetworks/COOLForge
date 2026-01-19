# Windows Configuration Policies

**Folder:** `scripts/Policy/Windows/`
**Launchers:** `launchers/Policy/Windows/`
**Category:** Configuration Policy

## Purpose

Windows configuration policies manage OS-level settings that affect all applications on the device.

## Available Policies

| Script | Custom Field | Description |
|--------|--------------|-------------|
| `👀locationservices.ps1` | `policy_device_locationservices` | Windows Location Services |

---

## Location Services

**Script:** `scripts/Policy/Windows/👀locationservices.ps1`
**Launcher:** `launchers/Policy/Windows/👀locationservices.ps1`

### Policy Tags

| Tag | Action |
|-----|--------|
| 🙏LOCATIONSERVICES | Enable location services |
| 🚫LOCATIONSERVICES | Disable location services |
| 📌LOCATIONSERVICES | Pin current state |
| 🔄LOCATIONSERVICES | Re-apply current policy |
| ✅LOCATIONSERVICES | Status: location is enabled |

### Custom Field

| Level.io Field | Values | Description |
|----------------|--------|-------------|
| `policy_device_locationservices` | `install` / `remove` / `pin` | `install` = enable, `remove` = disable |

### What It Controls

**When enabled (`install`):**

| Component | Setting |
|-----------|---------|
| Windows Policy | `DisableLocation = 0` |
| ConsentStore | `Allow` (if present) |
| Geolocation Service (lfsvc) | Running, Startup = Manual |

**When disabled (`remove`):**

| Component | Setting |
|-----------|---------|
| Windows Policy | `DisableLocation = 1` |
| ConsentStore | `Deny` (if present) |
| Geolocation Service (lfsvc) | Stopped, Startup = Disabled |

### Registry Keys Modified

- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors`
- `HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors`
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location` (if present)

### Related Policies

For browser-specific location settings:
- [Chrome Location Services](Chrome.md#chrome-configuration-policies)

---

## Adding New Windows Policies

When adding new Windows configuration policies:

1. Create the script: `scripts/Policy/Windows/👀<policyname>.ps1`
2. Create the launcher: `launchers/Policy/Windows/👀<policyname>.ps1`
3. Add the custom field: `policy_device_<policyname>`
4. Update this document with the new policy details
