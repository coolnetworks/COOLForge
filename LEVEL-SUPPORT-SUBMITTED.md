# Level.io Support - Submitted Requests

Requests that have been submitted to Level.io support. Track responses here.

---

## Install Keys / Enrollment Tokens

**Submitted:** 2026-01-15

**Question:** Is there an API endpoint to retrieve the install key (enrollment token) for a group or account?

**Use Case:** We want to generate reinstall commands programmatically for stale devices. Currently the install key must be manually copied from the Level UI (Devices > Select Group > Install New Agent > Copy API Key).

**Current Workaround:** Users must manually copy the install key from the UI and substitute it into generated commands.

**Response:**

---

## Device Last Seen Timestamp

**Submitted:** 2026-01-15

**Question:** Is there a `last_seen_at` or similar field returned by the `/v2/devices` endpoint that indicates when a device was last online/connected?

**Use Case:** We want to identify stale devices that haven't checked in for X days. The `online` boolean only shows current status, not when the device was last seen. The `last_reboot_time` field doesn't help because a device can be offline without rebooting.

**Current Workaround:** Using `last_reboot_time` as a fallback, but this is inaccurate - a device could be offline for months without rebooting showing as "Never seen".

**Response:**

---

## Script Name Variable

**Submitted:** 2026-01-15

**Question:** Is there a variable like `{{level_current_scriptname}}` that returns the name of the script as it appears in Level.io?

**Use Case:** We want to create a universal script launcher that auto-detects which script to run based on its name in Level.io. Currently each launcher requires a hardcoded `$ScriptToRun = "scriptname.ps1"` variable. With a script name variable, we could:
1. Deploy one generic launcher to Level.io
2. Name it whatever the target script is (e.g., "Check Huntress")
3. The launcher reads its own name and downloads/runs the matching script from GitHub

This would eliminate the need to maintain separate launchers for each script - just copy/rename the universal launcher.

**Current Workaround:** Each script in Level.io requires its own launcher with hardcoded `$ScriptToRun` variable. Updating the launcher template requires updating all deployed scripts.

**Response:**

---

## Scripts and Automations API Endpoints

**Submitted:** 2026-01-15

**Question:** Are there API endpoints for managing scripts, automations, and their organizational folders?

**Use Case:** We want to programmatically deploy and manage scripts and automations in Level.io. Specifically, we need:

1. **Scripts API:**
   - List all scripts
   - Create/update/delete scripts
   - List/create/update/delete script folders

2. **Automations API:**
   - List all automations
   - Create/update/delete automations
   - List/create/update/delete automation folders

This would enable:
- Automated deployment of script libraries from GitHub to Level.io
- Keeping scripts in sync between source control and Level.io
- Programmatic organization of scripts into folders (e.g., Policy/Software, Check, Fix, etc.)
- CI/CD pipelines that push updated scripts directly to Level.io

**Current Workaround:** Scripts and automations must be created, updated, and organized manually through the Level.io UI. For a large script library, this is time-consuming and error-prone.

**Response:**

---

## NOT Modifier for Tag Filters

**Submitted:** 2026-01-16

**Question:** Is there a way to filter devices by the absence of a tag (NOT modifier)?

**Use Case:** We need to find devices that are missing a specific tag. For example:
- Show all devices WITHOUT the `DNSFILTER` tag (to identify devices needing DNS protection)
- Show all devices WITHOUT the `✅` managed tag (to find unmanaged devices)
- Show all devices WITHOUT the `🙏huntress` tag (to find devices missing endpoint protection)

This is essential for compliance reporting and identifying gaps in coverage.

**Current Workaround:** Must manually export all devices and all tags, then use external tools (Excel, PowerShell) to find devices missing specific tags. No way to do this in the Level.io UI or API.

**Response:**
