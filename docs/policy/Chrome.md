# Google Chrome Enterprise Policy Script

**Script:** `scripts/Policy/👀chrome.ps1`
**Launcher:** `launchers/Policy/👀chrome.ps1`
**Version:** 2026.01.16.01
**Category:** Policy

## Flow

```
+--------------------+
| Launcher Start     |
+--------+-----------+
         |
         v
+--------------------+
| Load Level.io Vars |
| (API Key, Tags,    |
|  Policy Fields)    |
+--------+-----------+
         |
         v
+--------------------+
| Download MD5SUMS   |
| & Verify Library   |
+--------+-----------+
         |
         v
+--------------------+
| Import COOLForge   |
| Common Module      |
+--------+-----------+
         |
         v
+--------------------+
| Invoke-Script      |
| Launcher           |
+========+===========+
         |
    SCRIPT LOGIC
         |
         v
+--------------------+
| Check Tags &       |
| Policy Field       |
+--------+-----------+
         |
    +----+----+----+----+
    |    |    |    |    |
    v    v    v    v    v
+----+ +----+ +---+ +----+ +---+
|Skip| |Pin | |Rem| |Inst| |Has|
+----+ +--+-+ +-+-+ +-+--+ +-+-+
           |    |     |     |
           v    v     v     v
        +------+ +------+ +------+
        |No-op | |Remove| |Install|
        +------+ +------+ +------+
                   |        |
                   v        v
          +--------------------+
          | Update Has Tag     |
          +--------+-----------+
                   |
                   v
          +--------------------+
          |  Exit 0/1          |
          +--------------------+
```

## Purpose

Tag-based policy enforcement script for Google Chrome Enterprise management. Ensures the **enterprise/corporate version** (64-bit MSI-based installation) is deployed rather than the consumer per-user installation.

## Features

- **Enterprise-only installation** - Downloads and installs the 64-bit enterprise MSI
- **Consumer version detection** - Detects and upgrades consumer Chrome to enterprise
- **Policy-based management** via device tags
- **Tag auto-management** - Updates tags based on action results (requires API key)

## Policy Tags

| Tag | Action |
|-----|--------|
| 🙏chrome | Install Chrome Enterprise if missing |
| 🚫chrome | Remove Chrome |
| 📌chrome | Pin state - no changes allowed |
| 🔄chrome | Reinstall Chrome Enterprise |
| ✅chrome | Verify Chrome Enterprise is installed |

> **Note:** `⛔chrome` also works for Remove but is **deprecated**. Use `🚫chrome` instead.

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Policy action completed successfully |
| 1 | Alert | Action failed or configuration missing |

## Custom Fields

| Level.io Field | Script Variable | Required | Description |
|----------------|-----------------|----------|-------------|
| `policy_chrome` | `{{cf_policy_chrome}}` | No | Policy action: `install` / `remove` / `pin` |
| `apikey` | `{{cf_apikey}}` | No | Level.io API key for tag auto-management |

> **Note:** Level.io adds `cf_` prefix automatically when referencing in scripts.

## Enterprise vs Consumer Chrome

This script specifically manages **Google Chrome Enterprise**:

| Feature | Enterprise | Consumer |
|---------|-----------|----------|
| Installation | MSI-based, system-wide | EXE, per-user or system |
| Location | `C:\Program Files\Google\Chrome\` | `C:\Program Files (x86)\` or user profile |
| Architecture | 64-bit | May be 32-bit |
| Management | GPO-manageable | Limited |
| Update control | Admin-controlled | Auto-updates |

## Detection Method

The script detects Chrome by:
1. **Enterprise path check** - `C:\Program Files\Google\Chrome\Application\chrome.exe`
2. **Consumer path check** - `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`
3. **Registry check** - HKLM uninstall entries for "Google Chrome"

If consumer Chrome is found with an `install` policy, it will be upgraded to enterprise.

## Installation Source

Downloads the official 64-bit enterprise MSI directly from Google:
```
https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi
```

## Status Outputs

| Status | Description |
|--------|-------------|
| `Enterprise installed` | 64-bit Chrome in Program Files |
| `Consumer installed (needs upgrade)` | 32-bit or per-user Chrome detected |
| `Not installed` | No Chrome installation found |
| `INSTALLED` | Fresh installation completed |
| `REMOVED` | Successfully uninstalled |
| `PINNED` | State locked by pin tag |

## Files

| File | Path | Purpose |
|------|------|---------|
| Launcher | `launchers/Policy/👀chrome.ps1` | Deploy to Level.io |
| Script | `scripts/Policy/👀chrome.ps1` | Policy enforcement logic |
| Module | `modules/COOLForge-Common.psm1` | Shared library |

## Troubleshooting

### Debug Mode

Set `debug_scripts = true` on the device for verbose output.

### Common Issues

| Issue | Solution |
|-------|----------|
| Install fails | Check network connectivity to dl.google.com |
| Download timeout | Increase timeout or check firewall rules |
| Consumer not upgrading | Ensure `install` policy is set; consumer is detected and replaced |
| Tags not updating | Set `apikey` custom field |
| Chrome processes blocking | Script will close Chrome before install/uninstall |

## Chrome Configuration Policies

In addition to software enforcement (install/remove/pin), Chrome has configuration policies for managing browser settings.

These are located in: `scripts/Policy/Chrome/`

### Location Services

| Script | Custom Field | Values | Description |
|--------|--------------|--------|-------------|
| `👀locationservices.ps1` | `policy_chrome_locationservices` | `install` / `remove` / `pin` | Chrome geolocation policy |

**Tags:** 🙏CHROME_LOCATIONSERVICES, 🚫CHROME_LOCATIONSERVICES, 📌CHROME_LOCATIONSERVICES

**Behavior:**
- `install` = Allow sites to ask for location (DefaultGeolocationSetting = 1)
- `remove` = Block all sites from requesting location (DefaultGeolocationSetting = 2)

**Note:** When enabling Chrome location, the script will also enable Windows Location Services if they are disabled.

For device-level location control, see: [Windows Location Services](Windows.md)

See [scripts/Policy/Chrome/README.md](../../scripts/Policy/Chrome/README.md) for details.
