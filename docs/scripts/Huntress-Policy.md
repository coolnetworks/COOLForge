# Huntress Policy Script

**Script:** `scripts/Check/👀huntress.ps1`
**Launcher:** `launchers/👀huntress.ps1`
**Version:** 2026.01.08.03
**Category:** Check

## Purpose

Tag-based policy enforcement script for Huntress agent management. Handles installation, removal (with tamper protection awareness), and verification based on Level.io device tags.

## Features

- **Policy-based management** via device tags
- **Tamper Protection awareness** - Detects when TP blocks uninstall
- **Unhealthy iteration tracking** - Escalates after 3 failed health checks
- **Service repair** - Attempts to restart stopped services
- **Tag auto-management** - Updates tags based on action results (requires API key)

## Policy Tags

| Tag | Action |
|-----|--------|
| 🙏huntress | Install Huntress agent |
| ⛔huntress | Remove Huntress agent (checks TP first) |
| ✅huntress | Verify Huntress is installed and healthy |
| 📌huntress | Pin state - no changes allowed |
| 🚫huntress | Block installs (allow remove) |

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Policy action completed successfully |
| 1 | Alert | Action failed or device needs restart |

## Custom Fields

| Field | Required | Description |
|-------|----------|-------------|
| `cf_huntress_account_key` | Yes | Huntress account key (32 characters) |
| `cf_huntress_organization_key` | Yes | Organization name for Huntress |
| `cf_huntress_tags` | No | Comma-separated tags to apply to agent |
| `cf_apikey` | No | Level.io API key for tag auto-management |

## Tamper Protection Handling

When removing Huntress:
1. Script checks if HuntressRio (EDR) service is running
2. Attempts the uninstall
3. If files still exist after uninstall, Tamper Protection likely blocked it
4. Outputs `STATUS: TP_ENABLED` with instructions to disable TP in Huntress Dashboard
5. Script will retry automatically on next policy run

## Status Outputs

| Status | Description |
|--------|-------------|
| `INSTALLED_HEALTHY` | Huntress installed and services running |
| `INSTALLED` | Fresh installation completed |
| `INSTALL_FAILED` | Installation failed |
| `REMOVED` | Successfully uninstalled |
| `TP_ENABLED` | Tamper Protection blocking removal |
| `NEEDS_RESTART` | Device needs reboot (unhealthy 3+ cycles) |
| `SKIPPED` | Hands-off mode active |
| `PINNED` | State locked by pin tag |

## State Tracking

The script tracks unhealthy iterations in:
```
$MspScratchFolder\State\huntress-unhealthy-count.txt
```

After 3 consecutive unhealthy checks, escalates to alert requiring device restart.
