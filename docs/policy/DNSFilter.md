# DNSFilter Policy Script

**Script:** `scripts/Policy/👀dnsfilter.ps1`
**Launcher:** `launchers/Policy/👀dnsfilter.ps1`
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
|  DNSFilter NKEY)   |
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

Tag-based policy enforcement script for DNSFilter Agent management. Handles installation, removal, and verification based on Level.io device tags.

## Features

- **Policy-based management** via device tags
- **Site key configuration** via custom field
- **Service health monitoring** - Checks DNS Agent service status
- **Tag auto-management** - Updates tags based on action results (requires API key)

## Policy Tags

| Tag | Action |
|-----|--------|
| 🙏dnsfilter | Install DNSFilter agent |
| 🚫dnsfilter | Remove DNSFilter agent |
| 📌dnsfilter | Pin state - no changes allowed |
| 🔄dnsfilter | Reinstall DNSFilter agent |
| ✅dnsfilter | Verify DNSFilter is installed and healthy |

> **Note:** `⛔dnsfilter` also works for Remove but is **deprecated**. Use `🚫dnsfilter` instead.

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Policy action completed successfully |
| 1 | Alert | Action failed or configuration missing |

## Custom Fields

| Level.io Field | Script Variable | Required | Description |
|----------------|-----------------|----------|-------------|
| `policy_dnsfilter` | `{{cf_policy_dnsfilter}}` | No | Policy action: `install` / `remove` / `pin` |
| `policy_dnsfilter_sitekey` | `{{cf_policy_dnsfilter_sitekey}}` | For Install | DNSFilter NKEY from your portal |
| `apikey` | `{{cf_apikey}}` | No | Level.io API key for tag auto-management |

> **Note:** Level.io adds `cf_` prefix automatically when referencing in scripts.

## Installation Requirements

DNSFilter requires a **Site Key (NKEY)** for installation:

1. Log into your DNSFilter portal
2. Navigate to **Sites** → Select your site
3. Copy the **NKEY** value
4. Set `policy_dnsfilter_sitekey` custom field to this value

## Status Outputs

| Status | Description |
|--------|-------------|
| `INSTALLED_HEALTHY` | DNSFilter installed and DNS Agent service running |
| `INSTALLED` | Fresh installation completed |
| `INSTALL_FAILED` | Installation failed |
| `REMOVED` | Successfully uninstalled |
| `SKIPPED` | Hands-off mode active |
| `PINNED` | State locked by pin tag |

## Detection Method

The script detects DNSFilter by:
1. **Service check** - `DNS Agent` service exists and running
2. **Registry check** - Uninstall entries containing "DNS Agent" or "DNSFilter"

## Files

| File | Path | Purpose |
|------|------|---------|
| Launcher | `launchers/Policy/👀dnsfilter.ps1` | Deploy to Level.io |
| Script | `scripts/Policy/👀dnsfilter.ps1` | Policy enforcement logic |
| Module | `modules/COOLForge-Common.psm1` | Shared library |

## Troubleshooting

### Debug Mode

Set `debug_scripts = true` on the device for verbose output.

### Common Issues

| Issue | Solution |
|-------|----------|
| Install fails | Set `policy_dnsfilter_sitekey` custom field with your NKEY |
| Tags not updating | Set `apikey` custom field |
| Service not starting | Check Windows Event Log for DNS Agent errors |
