# Technician Alerts System

**Version:** 2026.01.08.02

A real-time notification system that sends Windows toast notifications to technician workstations when scripts on client machines need attention.

---

## Quick Start - Set Up Your Workstation in 5 Minutes

### What You Need

1. Your technician workstation enrolled in Level.io
2. Level.io API key (`cf_apikey` custom field)
3. The `cf_coolforge_technician_alerts` custom field created

### Step 1: Tag Your Workstation

In Level.io, add this tag to your workstation:

```
🧑‍💻
```

That's it - just the emoji. Copy/paste it from here.

**How to add the tag:**
1. Go to Level.io → Devices → Find your workstation
2. Click on the device
3. Add tag: Copy/paste `🧑‍💻`
4. Save

**Optional - add your name for routing:**
| Tag | What You'll Receive |
|-----|---------------------|
| `🧑‍💻` | All alerts (broadcast) |
| `🧑‍💻Allen` | Alerts for "Allen" + all broadcast alerts |
| `🧑‍💻John` | Alerts for "John" + all broadcast alerts |

### Step 2: Create the Custom Field

In Level.io, create this custom field if it doesn't exist:

1. Go to Level.io → Settings → Custom Fields
2. Create new field:
   - **Name:** `coolforge_technician_alerts`
   - **Type:** Text
3. Save

### Step 3: Deploy the Alert Monitor

Create an automation in Level.io to run the monitor script:

1. Go to Level.io → Automations → Scripts → New Script
2. **Name:** `🔔Technician Alert Monitor`
3. **Language:** PowerShell
4. **Code:** Copy contents from `scripts/Utility/🔔Technician Alert Monitor.ps1`
5. Save

Create an automation to run it:

1. Go to Level.io → Automations → New Automation
2. **Trigger:** Schedule (every 30-60 seconds)
3. **Filter:** Devices with tag containing `🧑‍💻` (technician emoji)
4. **Action:** Run the `🔔Technician Alert Monitor` script
5. **Run as:** Current user (important for toast notifications!)
6. Save and enable

### Step 4: Test It

Run this on any client device to send a test alert:

```powershell
# Quick test - replace with your actual values
$LevelApiKey = "{{cf_apikey}}"

# This will appear on your workstation
Send-TechnicianAlert -ApiKey $LevelApiKey `
    -Title "Test Alert" `
    -Message "If you see this, alerts are working!" `
    -ClientName "Test Client" `
    -Priority "Normal"
```

You should see a Windows toast notification within 30-60 seconds.

### Done!

Your workstation is now set up to receive alerts. Any script that calls `Send-TechnicianAlert` will trigger a notification on your screen.

---

## Table of Contents

- [Overview](#overview)
- [Use Cases](#use-cases)
- [Architecture](#architecture)
- [Setup Guide](#setup-guide)
- [Sending Alerts](#sending-alerts)
- [Alert Monitor Script](#alert-monitor-script)
- [Alert Routing](#alert-routing)
- [Priority Levels](#priority-levels)
- [Alert Lifecycle](#alert-lifecycle)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)

---

## Overview

The Technician Alerts system solves a common MSP problem: **scripts run silently on client machines, and technicians don't know when something needs manual intervention**.

### The Problem

When a script fails or encounters a situation requiring human decision-making:
- The script output is buried in Level.io logs
- Technicians don't know until they manually check
- Client issues go unnoticed for hours or days
- No way to get real-time notifications on your workstation

### The Solution

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────────┐
│  Client Device  │────▶│  Level.io    │────▶│  Tech Workstation   │
│                 │     │  Custom      │     │                     │
│  Script fails   │     │  Field       │     │  Toast notification │
│  or needs help  │     │  (JSON)      │     │  pops up instantly  │
└─────────────────┘     └──────────────┘     └─────────────────────┘
```

1. **Script on client machine** detects an issue requiring tech attention
2. **Calls `Send-TechnicianAlert`** with title, message, and priority
3. **Alert stored in Level.io** custom field as JSON
4. **Alert Monitor** on tech workstation polls for new alerts
5. **Windows toast notification** appears on technician's screen

---

## Use Cases

### Installation Failures

```powershell
try {
    Install-Huntress -OrgKey $OrgKey
}
catch {
    Send-TechnicianAlert -ApiKey $LevelApiKey `
        -Title "Huntress Install Failed" `
        -Message "Error: $($_.Exception.Message). Manual install required." `
        -ClientName $ClientName `
        -Priority "High"
}
```

### Security Alerts

```powershell
$UnauthorizedRATs = Find-UnauthorizedRemoteAccessTools
if ($UnauthorizedRATs) {
    Send-TechnicianAlert -ApiKey $LevelApiKey `
        -Title "Unauthorized RAT Detected" `
        -Message "Found: $($UnauthorizedRATs -join ', ')" `
        -ClientName $ClientName `
        -Priority "Critical"
}
```

### Pending Decisions

```powershell
if ($DiskSpace -lt 10GB -and $HasImportantData) {
    Send-TechnicianAlert -ApiKey $LevelApiKey `
        -Title "Low Disk - Needs Review" `
        -Message "Only $([math]::Round($DiskSpace/1GB, 1))GB free. Large files found - need decision on cleanup." `
        -ClientName $ClientName `
        -Priority "Normal"
}
```

### Scheduled Task Completion

```powershell
# After a long-running maintenance task
Send-TechnicianAlert -ApiKey $LevelApiKey `
    -Title "Backup Complete" `
    -Message "Weekly backup finished. 847 files, 23.4 GB total." `
    -ClientName $ClientName `
    -Priority "Low"
```

### Hardware Issues

```powershell
$SmartStatus = Get-DiskSmartStatus
if ($SmartStatus.PredictingFailure) {
    Send-TechnicianAlert -ApiKey $LevelApiKey `
        -Title "DISK FAILURE PREDICTED" `
        -Message "SMART status indicates imminent failure on $($SmartStatus.DriveLetter)" `
        -ClientName $ClientName `
        -Priority "Critical" `
        -TechnicianName "Allen"  # Route to specific tech
}
```

---

## Architecture

### Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `Send-TechnicianAlert` | COOLForge-Common.psm1 | Function to create and send alerts |
| `Test-TechnicianWorkstation` | COOLForge-Common.psm1 | Check if device should receive alerts |
| Alert Monitor Script | scripts/Utility/ | Polls for alerts, shows notifications |
| Custom Fields | Level.io | Store alert data and tech workstation flags |

### Data Flow

```
                                    Level.io API
                                         │
     ┌───────────────────────────────────┼───────────────────────────────────┐
     │                                   │                                   │
     ▼                                   │                                   ▼
┌─────────────┐                          │                          ┌─────────────┐
│   Client    │  Send-TechnicianAlert    │    Alert Monitor polls   │    Tech     │
│   Device    │ ────────────────────────▶│◀──────────────────────── │ Workstation │
│             │                          │                          │             │
│ Script runs │                          │                          │ Toast pops  │
│ Detects     │      cf_technician_      │      cf_technician_      │ up with     │
│ issue       │      alerts (JSON)       │      alerts (JSON)       │ alert info  │
└─────────────┘                          │                          └─────────────┘
                                         │
                                    Level.io
                                   Custom Fields
```

### Alert JSON Structure

Alerts are stored as a JSON array in the `cf_coolforge_technician_alerts` custom field:

```json
[
  {
    "id": "a1b2c3d4",
    "title": "Huntress Install Failed",
    "message": "Error: Access denied. Manual install required.",
    "client": "ACME Corp",
    "device": "ACME-PC01",
    "priority": "High",
    "technician": "",
    "created": "2026-01-08T14:32:01.000Z",
    "expires": "2026-01-09T14:32:01.000Z",
    "acknowledged": false
  },
  {
    "id": "e5f6g7h8",
    "title": "Disk Space Low",
    "message": "C: drive has only 5.2 GB free",
    "client": "ACME Corp",
    "device": "ACME-SERVER01",
    "priority": "Normal",
    "technician": "John",
    "created": "2026-01-08T15:45:22.000Z",
    "expires": "2026-01-09T15:45:22.000Z",
    "acknowledged": false
  }
]
```

---

## Setup Guide

### Step 1: Create the Custom Field in Level.io

Create this custom field in Level.io (Settings → Custom Fields):

| Field Name | Type | Description |
|------------|------|-------------|
| `cf_coolforge_technician_alerts` | Text | JSON array of pending alerts (managed by scripts) |

> **Note:** The setup wizard (`Setup-COOLForgeCustomFields.ps1`) will create this automatically if you run it.

### Step 2: Tag Your Workstation

Add the technician tag to your workstation in Level.io:

1. Go to your device in Level.io
2. Add the tag: `🧑‍💻technician` (or `🧑‍💻YourName` for routing)
3. That's it!

**Tag Format:**
- `🧑‍💻technician` - Receive all alerts
- `🧑‍💻John` - Receive alerts routed to "John" + all unrouted alerts
- `🧑‍💻Allen` - Receive alerts routed to "Allen" + all unrouted alerts

The emoji is: 🧑‍💻 (U+1F9D1 U+200D U+1F4BB - technician/person at computer)

### Step 3: Deploy the Alert Monitor

Create a new automation in Level.io:

1. **Script:** Copy contents of `scripts/Utility/🔔Technician Alert Monitor.ps1`
2. **Schedule:** Run every 30-60 seconds
3. **Filter:** Only run on devices with the `🧑‍💻technician` tag
4. **Run as:** Current user (for toast notifications to appear)

### Step 4: Test the System

Run this test script on any client device:

```powershell
# Test alert
Send-TechnicianAlert -ApiKey "{{cf_apikey}}" `
    -Title "Test Alert" `
    -Message "If you see this notification, the alert system is working!" `
    -ClientName "Test" `
    -Priority "Normal"
```

You should see a Windows toast notification on your workstation within 30-60 seconds.

---

## Sending Alerts

There are two ways to send alerts:

| Method | When to Use |
|--------|-------------|
| `Add-TechnicianAlert` | **Recommended.** Queue alerts to send when script completes. Batches multiple alerts into one API call. |
| `Send-TechnicianAlert` | Send alert immediately. Use when you need instant notification or aren't using `Invoke-LevelScript`. |

### Recommended: Queue Alerts (Add-TechnicianAlert)

Queue alerts during script execution - they're automatically sent when the script completes:

```powershell
$Init = Initialize-LevelScript -ScriptName "MyScript" `
                               -MspScratchFolder "{{cf_coolforge_msp_scratch_folder}}" `
                               -ApiKey "{{cf_apikey}}"  # Required for alerts

Invoke-LevelScript -ScriptBlock {
    try {
        Install-Software -Name "Huntress"
    }
    catch {
        # Queue alert - sent automatically when script ends
        Add-TechnicianAlert -Title "Install Failed" `
                            -Message "Huntress: $($_.Exception.Message)" `
                            -Priority "High"
    }
}
# Alerts sent here automatically
```

**Benefits:**
- Multiple alerts batched into single API call
- Alerts sent even if script crashes
- No API key needed in each call (uses key from Initialize-LevelScript)

### Alternative: Send Immediately (Send-TechnicianAlert)

```powershell
Send-TechnicianAlert -ApiKey "{{cf_apikey}}" `
    -Title "Alert Title" `
    -Message "Detailed message about what happened and what action is needed"
```

### Full Parameters

```powershell
# For Add-TechnicianAlert (queued)
Add-TechnicianAlert -Title "Alert Title" `
    -Message "Detailed message" `
    -ClientName "Client Name" `
    -Priority "Normal" `
    -TechnicianName "" `
    -ExpiresInMinutes 1440

# For Send-TechnicianAlert (immediate)
Send-TechnicianAlert -ApiKey "{{cf_apikey}}" `
    -Title "Alert Title" `
    -Message "Detailed message" `
    -ClientName "Client Name" `
    -DeviceHostname $env:COMPUTERNAME `
    -Priority "Normal" `
    -TechnicianName "" `
    -ExpiresInMinutes 1440 `
    -BaseUrl "https://api.level.io/v2"
```

### Parameter Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ApiKey` | String | **Yes** | — | Level.io API key (`{{cf_apikey}}`) |
| `-Title` | String | **Yes** | — | Short title for notification header |
| `-Message` | String | **Yes** | — | Detailed message explaining the situation |
| `-ClientName` | String | No | `""` | Client/organization name |
| `-DeviceHostname` | String | No | `$env:COMPUTERNAME` | Source device hostname |
| `-Priority` | String | No | `"Normal"` | `Low`, `Normal`, `High`, or `Critical` |
| `-TechnicianName` | String | No | `""` | Route to specific tech (empty = all) |
| `-ExpiresInMinutes` | Int | No | `1440` | Alert expiration (default: 24 hours) |
| `-BaseUrl` | String | No | `https://api.level.io/v2` | API endpoint |

### Return Value

```powershell
$Result = Send-TechnicianAlert -ApiKey $Key -Title "Test" -Message "Test message"

# Success
$Result.Success   # $true
$Result.AlertId   # "a1b2c3d4"
$Result.Error     # $null

# Failure
$Result.Success   # $false
$Result.AlertId   # $null
$Result.Error     # "Custom field not found"
```

---

## Alert Monitor Script

The Alert Monitor runs on technician workstations and displays notifications for new alerts.

### How It Works

1. **Polls Level.io API** every run (typically 30-60 seconds)
2. **Checks for new alerts** by comparing against previously seen alert IDs
3. **Displays Windows toast notifications** for each new alert
4. **Tracks seen alerts** in a local cache file to avoid duplicates

### Notification Methods

The monitor uses two methods depending on what's available:

1. **BurntToast Module** (preferred) - Rich toast notifications with icons
2. **Windows Forms** (fallback) - Basic balloon notifications

To get better notifications, install BurntToast on your workstation:

```powershell
Install-Module -Name BurntToast -Scope CurrentUser
```

### Cache Location

Seen alert IDs are stored in:
```
{{cf_coolforge_msp_scratch_folder}}\TechAlerts\seen_alerts.json
```

This prevents the same alert from showing multiple times.

---

## Alert Routing

### Broadcast to All Technicians

By default, alerts go to ALL technician workstations:

```powershell
Send-TechnicianAlert -ApiKey $Key `
    -Title "Alert for everyone" `
    -Message "All techs will see this"
```

### Route to Specific Technician

Route to a specific tech by name:

```powershell
Send-TechnicianAlert -ApiKey $Key `
    -Title "Alert for John" `
    -Message "Only John will see this" `
    -TechnicianName "John"
```

The tech workstation must be tagged with `🧑‍💻John` to receive this alert.

### Tag-Based Routing

Technician names are extracted from the tag:

| Tag | Receives Alerts For |
|-----|---------------------|
| `🧑‍💻technician` | All alerts (no name = broadcast) |
| `🧑‍💻John` | Alerts for "John" + unrouted alerts |
| `🧑‍💻Allen` | Alerts for "Allen" + unrouted alerts |

### Routing Logic

```
Alert received by tech workstation:
  │
  ├─ Alert.technician is empty?
  │     └─ YES: Show to all tech workstations
  │
  └─ Alert.technician matches tag name?
        ├─ YES: Show notification
        └─ NO: Skip (not for this tech)
```

---

## Priority Levels

| Priority | Badge | Use Case | Examples |
|----------|-------|----------|----------|
| `Low` | ℹ️ | Informational, can wait | Task completed, status update |
| `Normal` | ⚠️ | Standard issues | Install failed, needs review |
| `High` | 🔶 | Needs attention soon | Security tool missing, service down |
| `Critical` | 🔴 | Immediate action required | Ransomware detected, disk failing |

### Setting Priority

```powershell
# Low priority - informational
Send-TechnicianAlert ... -Priority "Low"

# Normal priority - default
Send-TechnicianAlert ... -Priority "Normal"

# High priority - needs attention
Send-TechnicianAlert ... -Priority "High"

# Critical - drop everything
Send-TechnicianAlert ... -Priority "Critical"
```

### Priority-Based Behavior (Future Enhancement)

Potential enhancements based on priority:
- **Critical:** Play sound, stay on screen longer, flash taskbar
- **High:** Standard toast with longer duration
- **Normal:** Standard toast notification
- **Low:** Silent notification, grouped with others

---

## Alert Lifecycle

### Creation

1. Script calls `Send-TechnicianAlert`
2. Function generates unique 8-character alert ID
3. Alert object created with timestamp and expiration
4. Current alerts fetched from Level.io custom field
5. Expired alerts automatically removed
6. New alert appended to array
7. Updated JSON written back to custom field

### Display

1. Alert Monitor polls Level.io
2. New alert IDs compared against local cache
3. New alerts trigger Windows toast notification
4. Alert ID added to seen cache

### Expiration

- Default expiration: **24 hours** (1440 minutes)
- Expired alerts automatically removed when new alerts are added
- Configurable via `-ExpiresInMinutes` parameter

### Acknowledgment (Future Enhancement)

The alert structure includes an `acknowledged` field for future use:
- Acknowledged alerts could be hidden from future notifications
- Could enable "mark as handled" functionality
- Could sync acknowledgment across all tech workstations

---

## Best Practices

### Writing Good Alert Titles

| ❌ Bad | ✅ Good |
|--------|---------|
| "Error" | "Huntress Install Failed" |
| "Check this" | "Low Disk Space - Needs Review" |
| "Problem" | "Unauthorized RAT Detected" |
| "Alert" | "Backup Completed Successfully" |

Keep titles under 50 characters - they appear as notification headers.

### Writing Good Alert Messages

Include:
- **What happened** - Clear description of the issue
- **Where** - Device/client context (often automatic)
- **What action is needed** - Tell the tech what to do

```powershell
# ❌ Bad
-Message "Error occurred"

# ✅ Good
-Message "Huntress installer returned error 1603. Check if another install is in progress. May need to run manually as admin."
```

### When to Send Alerts

**DO send alerts for:**
- Script failures requiring manual intervention
- Security issues detected
- Decisions that need human judgment
- Completion of important long-running tasks

**DON'T send alerts for:**
- Every successful script run
- Minor issues that auto-resolve
- Situations where no action is possible
- High-frequency events (would cause alert fatigue)

### Avoid Alert Fatigue

```powershell
# ❌ Bad - alerts on every check
if (Get-Service -Name "Spooler" | Where-Object Status -ne "Running") {
    Send-TechnicianAlert -Title "Spooler not running" ...
}

# ✅ Good - alert once, then only if status changes
$StatusFile = "$MspScratchFolder\spooler_alerted.flag"
$SpoolerDown = (Get-Service -Name "Spooler").Status -ne "Running"

if ($SpoolerDown -and -not (Test-Path $StatusFile)) {
    Send-TechnicianAlert -Title "Print Spooler Down" ...
    New-Item $StatusFile -Force
}
elseif (-not $SpoolerDown -and (Test-Path $StatusFile)) {
    Remove-Item $StatusFile  # Reset for next detection
}
```

---

## Troubleshooting

### Alerts Not Appearing

**Check 1: Is the workstation tagged correctly?**
```powershell
# Check if device has technician tag
"{{level_tag_names}}"
# Should contain something starting with the technician emoji
```

**Check 2: Is the Alert Monitor running?**
- Check Level.io automation history
- Verify it's scheduled correctly
- Check filter conditions (should filter by technician tag)

**Check 3: Is the custom field created?**
- Go to Level.io Settings → Custom Fields
- Look for `cf_coolforge_technician_alerts`

**Check 4: Check the cache file**
```powershell
# View seen alerts
Get-Content "$MspScratchFolder\TechAlerts\seen_alerts.json"

# Clear cache to see all alerts again
Remove-Item "$MspScratchFolder\TechAlerts\seen_alerts.json"
```

### Alerts Showing Multiple Times

- Check if multiple Alert Monitor instances are running
- Verify the cache file is being written correctly
- Ensure the scratch folder path is consistent

### API Errors

**"Custom field not found"**
- Create `cf_coolforge_technician_alerts` in Level.io

**"Device not found"**
- Verify the device hostname is correct
- Check Level.io API key permissions

**"Failed to get custom fields"**
- Verify API key is valid
- Check network connectivity

### Tag Not Recognized

If the technician tag isn't being detected:
- Ensure the exact emoji is used: 🧑‍💻 (U+1F9D1 U+200D U+1F4BB)
- Check for emoji corruption (see EMOJI-HANDLING.md)
- Try copying the tag directly from this documentation

---

## API Reference

### Add-TechnicianAlert (Recommended)

Queues an alert to be sent when the script completes via `Invoke-LevelScript`.

```powershell
Add-TechnicianAlert
    -Title <String>
    -Message <String>
    [-ClientName <String>]
    [-Priority <String>]
    [-TechnicianName <String>]
    [-ExpiresInMinutes <Int>]
```

**Returns:** `@{ Success = $bool; QueueLength = $int; AlertId = $string }`

**Requires:** `Initialize-LevelScript` called with `-ApiKey` parameter.

### Send-TechnicianAlert

Creates and sends an alert immediately to technician workstations.

```powershell
Send-TechnicianAlert
    -ApiKey <String>
    -Title <String>
    -Message <String>
    [-ClientName <String>]
    [-DeviceHostname <String>]
    [-Priority <String>]
    [-TechnicianName <String>]
    [-ExpiresInMinutes <Int>]
    [-BaseUrl <String>]
```

**Returns:** `@{ Success = $bool; AlertId = $string; Error = $string }`

### Send-TechnicianAlertQueue

Manually sends all queued alerts. Called automatically by `Invoke-LevelScript`.

```powershell
Send-TechnicianAlertQueue
    [-ApiKey <String>]
    [-Force]
    [-BaseUrl <String>]
```

**Returns:** `@{ Success = $bool; AlertsSent = $int; Error = $string }`

### Test-TechnicianWorkstation

Checks if the current device is tagged as a technician workstation.

```powershell
Test-TechnicianWorkstation
    [-DeviceTags <String>]
```

**Parameters:**
- `-DeviceTags` — Comma-separated list of device tags from `{{level_tag_names}}`

**Returns:** `$true` if device has technician tag, `$false` otherwise.

### Get-TechnicianName

Extracts the technician name from the device tags.

```powershell
Get-TechnicianName
    [-DeviceTags <String>]
```

**Parameters:**
- `-DeviceTags` — Comma-separated list of device tags from `{{level_tag_names}}`

**Returns:** Technician name string (e.g., "John" from `🧑‍💻John`), or empty string.

### Required Tag

- `🧑‍💻technician` or `🧑‍💻{Name}` — Tag on tech workstations (U+1F9D1 U+200D U+1F4BB)

### Required Custom Field

- `cf_coolforge_technician_alerts` — JSON array of pending alerts

---

## See Also

- [Function Reference](FUNCTIONS.md) - Complete function documentation
- [Custom Fields](../definitions/custom-fields.json) - Field definitions
- [Variables Reference](VARIABLES.md) - Level.io variables
- [Main README](../README.md) - Project overview
