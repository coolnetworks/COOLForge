# Chrome Configuration Policies

This folder contains Chrome browser configuration policies that configure Chrome behavior and settings.

## Looking for Chrome Install/Remove?

The software enforcement script (install, remove, reinstall, pin) is located in the parent folder:

**[../👀chrome.ps1](../👀chrome.ps1)** - Google Chrome Enterprise software policy

## Scripts in this folder

| Script | Custom Field | Description |
|--------|--------------|-------------|
| `👀locationservices.ps1` | `policy_chrome_locationservices` | Chrome geolocation policy (DefaultGeolocationSetting) |

## Policy Tags

These scripts use the standard 5-tag model:

| Tag | Action |
|-----|--------|
| 🙏CHROME_LOCATIONSERVICES | Enable Chrome location (Allow) |
| 🚫CHROME_LOCATIONSERVICES | Disable Chrome location (Block) |
| 📌CHROME_LOCATIONSERVICES | Pin current state |
| 🔄CHROME_LOCATIONSERVICES | Re-apply current policy |
| ✅CHROME_LOCATIONSERVICES | Status: Chrome location is enabled |

## Custom Fields

| Field | Values | Description |
|-------|--------|-------------|
| `policy_chrome_locationservices` | `install` / `remove` / `pin` | `install` = Allow, `remove` = Block |

## Location Services Details

**Chrome Location (`👀locationservices.ps1`):**

| Action | Chrome Policy | Device Location |
|--------|--------------|-----------------|
| `install` (Allow) | DefaultGeolocationSetting = 1 | Auto-enabled if disabled |
| `remove` (Block) | DefaultGeolocationSetting = 2 | Left unchanged |

**Important:** When enabling Chrome location, the script will also enable Windows Location Services if they are disabled, since Chrome requires OS-level location access to function.

For device-level location control, see: [../Windows/README.md](../Windows/README.md)

## Adding New Chrome Policies

When adding new Chrome configuration policies:

1. Create the script: `👀<policyname>.ps1`
2. Create the launcher: `launchers/Policy/Chrome/👀<policyname>.ps1`
3. Add the custom field: `policy_chrome_<policyname>`
4. Update this README with the new policy details
