# Bitwarden Policy Script

**Script:** `scripts/Policy/👀bitwarden.ps1`
**Launcher:** `launchers/Policy/👀bitwarden.ps1`
**Version:** 2026.02.01.01
**Category:** Policy

## Purpose

Tag-based policy enforcement script for the Bitwarden browser extension. Manages Bitwarden as a force-installed browser extension via Chrome and Edge ExtensionSettings registry policies, rather than a traditional installer.

## Features

- **ExtensionSettings approach** — Uses per-extension subkey with installation_mode, update_url, and toolbar settings
- **Multi-browser support** — Manages Chrome and Edge simultaneously
- **Legacy cleanup** — Detects and cleans up old ExtensionInstallForcelist entries
- **Policy-based management** via device tags
- **Tag auto-management** — Updates tags based on action results (requires API key)

## Policy Tags

| Tag | Action |
|-----|--------|
| 🙏BITWARDEN | Install Bitwarden extension |
| 🚫BITWARDEN | Remove Bitwarden extension |
| 📌BITWARDEN | Pin state - no changes allowed |
| 🔄BITWARDEN | Reinstall Bitwarden extension |
| ✅BITWARDEN | Status: currently installed |

## Custom Fields

| Level.io Field | Script Variable | Required | Description |
|----------------|-----------------|----------|-------------|
| `policy_bitwarden` | `{{cf_policy_bitwarden}}` | No | Policy action: `install` / `remove` / `pin` |
| `apikey` | `{{cf_apikey}}` | No | Level.io API key for tag auto-management |

## Installation Method

Unlike traditional software policies, Bitwarden is deployed as a browser extension:

1. Sets `ExtensionSettings` registry key for the Bitwarden extension ID
2. Configures `installation_mode` to `force_installed`
3. Sets `update_url` to Chrome Web Store
4. Enables toolbar pin

## Files

| File | Path | Purpose |
|------|------|---------|
| Launcher | `launchers/Policy/👀bitwarden.ps1` | Deploy to Level.io |
| Script | `scripts/Policy/👀bitwarden.ps1` | Policy enforcement logic |
| Module | `modules/COOLForge-Common.psm1` | Shared library |

## Related

- [Policy System](README.md)
- [Tag System](TAGS.md)
- [Policy Fields Reference](../POLICY-FIELDS.md)
