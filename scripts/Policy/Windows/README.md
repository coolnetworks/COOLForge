# Windows Configuration Policies

This folder contains Windows OS-level configuration policies.

## Scripts

| Script | Custom Field | Description |
|--------|--------------|-------------|
| `👀locationservices.ps1` | `policy_device_locationservices` | Windows Location Services (policy keys, ConsentStore, lfsvc) |

## Policy Tags

These scripts use the standard 5-tag model:

| Tag | Action |
|-----|--------|
| 🙏LOCATIONSERVICES | Enable location services |
| 🚫LOCATIONSERVICES | Disable location services |
| 📌LOCATIONSERVICES | Pin current state |
| 🔄LOCATIONSERVICES | Re-apply current policy |
| ✅LOCATIONSERVICES | Status: location is enabled |

## Custom Fields

| Field | Values | Description |
|-------|--------|-------------|
| `policy_device_locationservices` | `install` / `remove` / `pin` | `install` = enable, `remove` = disable |

## What Location Services Controls

When **enabled** (`install`):
- Windows Location policy: `DisableLocation = 0`
- ConsentStore: `Allow` (if present)
- Geolocation Service (lfsvc): Running, Startup = Manual

When **disabled** (`remove`):
- Windows Location policy: `DisableLocation = 1`
- ConsentStore: `Deny` (if present)
- Geolocation Service (lfsvc): Stopped, Startup = Disabled

## Related Policies

For browser-specific location settings, see:
- [Chrome Location Services](../Chrome/README.md) - Controls Chrome's geolocation prompt behavior
