# Software Management

COOLForge uses an emoji-based tag system for software policy enforcement. Device tags in Level.io control what actions are taken for each software package.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         LEVEL.IO DEVICE                             │
│                                                                     │
│  Tags: 🪟Windows, 🌀AdelaideMRI, 🙏unchecky, 🚫bloatware, etc.      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      LAUNCHER (👀software.ps1)                      │
│  1. Downloads COOLForge-Common.psm1 module                          │
│  2. Loads module into memory                                        │
│  3. Downloads target script (scripts/Policy/👀software.ps1)         │
│  4. Passes variables: $DeviceTags, $MspScratchFolder, etc.          │
│  5. Sets $RunningFromLauncher = $true                               │
│  6. Executes script, captures exit code                             │
│  7. Displays log file contents                                      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      SCRIPT (👀software.ps1)                        │
│  1. Initialize-LevelScript (logging, lockfile, etc.)                │
│  2. Get-SoftwarePolicy → Returns resolved action                    │
│  3. Execute action based on ResolvedAction                          │
│  4. Run verification if ShouldVerify = true                         │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   POLICY RESOLUTION (Library)                       │
│                                                                     │
│  Get-EmojiMap() ─► Single source of truth for emoji patterns        │
│  Get-SoftwarePolicy() ─► Parses tags, resolves priority, returns:   │
│    - ResolvedAction: "Install", "Remove", "Skip", or $null          │
│    - ShouldVerify: $true if ✅ tag present                          │
│    - IsPinned/IsBlocked: State flags                                │
└─────────────────────────────────────────────────────────────────────┘
```

## Policy Tags

See [TAGS.md](TAGS.md) for the complete tag reference, priority resolution, and combination examples.

## Get-SoftwarePolicy Return Object

```powershell
@{
    # Raw detection
    SoftwareName   = "unchecky"
    HasPolicy      = $true
    MatchedTags    = @("🙏unchecky", "✅unchecky")
    PolicyActions  = @("Install", "Has")
    RawTags        = @("🪟Windows", "🙏unchecky", "✅unchecky")

    # Resolved state
    IsSkipped      = $false
    IsPinned       = $false
    IsBlocked      = $false
    CanInstall     = $true
    CanRemove      = $true
    ResolvedAction = "Install"    # "Install", "Remove", "Skip", or $null
    ShouldVerify   = $true        # ✅ present and not being removed
}
```

## Creating a New Software Script

### Step 1: Create the Launcher

Copy an existing launcher (e.g., `launchers/Policy/👀unchecky.ps1`) and update the script URL:

```powershell
$ScriptUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/$Branch/scripts/Policy/👀newsoftware.ps1"
```

### Step 2: Create the Policy Script

Create `scripts/Policy/👀newsoftware.ps1`:

```powershell
# ============================================================
# CONFIGURATION
# ============================================================
$SoftwareName = "newsoftware"

# Install mode: "Reinstall" = always uninstall first (for config updates)
#               "Install"   = only install if missing
$InstallMode = "Reinstall"

# ============================================================
# SOFTWARE-SPECIFIC ROUTINES
# ============================================================

function Install-Software {
    # Install logic here
}

function Remove-Software {
    # Uninstall logic here
}

function Test-SoftwareInstalled {
    # Return $true/$false
}

function Test-SoftwareHealthy {
    # Check services, etc. Return $true/$false
}

# ============================================================
# INITIALIZE
# ============================================================
$Init = Initialize-LevelScript -ScriptName "SoftwarePolicy-$SoftwareName" `
                               -MspScratchFolder $MspScratchFolder `
                               -DeviceHostname $DeviceHostname `
                               -DeviceTags $DeviceTags

if (-not $Init.Success) {
    exit 0
}

# ============================================================
# MAIN SCRIPT LOGIC
# ============================================================
$ScriptVersion = "2026.01.01.01"
$InvokeParams = @{ ScriptBlock = {

    Write-LevelLog "Policy Check Script (v$ScriptVersion)"
    Write-Host ""

    # Get policy and resolved action
    $Policy = Invoke-SoftwarePolicyCheck -SoftwareName $SoftwareName -DeviceTags $DeviceTags

    # Execute based on resolved action
    switch ($Policy.ResolvedAction) {
        "Skip" {
            Write-LevelLog "SKIP: Hands off"
        }
        "Install" {
            $Installed = Test-SoftwareInstalled

            if ($InstallMode -eq "Reinstall") {
                if ($Installed) {
                    Write-LevelLog "Reinstall mode - removing existing..."
                    Remove-Software
                }
                Install-Software
            }
            else {
                if (-not $Installed) {
                    Install-Software
                }
            }
        }
        "Remove" {
            Remove-Software
        }
        $null {
            if ($Policy.IsPinned) { Write-LevelLog "PINNED: State locked" }
            elseif ($Policy.IsBlocked) { Write-LevelLog "BLOCKED: Install prevented" }
            else { Write-LevelLog "NO POLICY: No tags found" }
        }
    }

    # Run verification if needed
    if ($Policy.ShouldVerify) {
        $Installed = Test-SoftwareInstalled
        if ($Installed) {
            $Healthy = Test-SoftwareHealthy
            if (-not $Healthy) {
                # Remediation logic here
            }
        }
    }

    Write-LevelLog "Check completed" -Level "SUCCESS"
}}
if ($RunningFromLauncher) { $InvokeParams.NoExit = $true }
Invoke-LevelScript @InvokeParams
```

## Install Modes

The `$InstallMode` configuration controls how `🙏Install` is handled:

| Mode | Behavior |
|------|----------|
| `"Reinstall"` | Always uninstall first, then install. Use for software that needs config updates (DNSFilter, RMM agents, etc.) |
| `"Install"` | Only install if not present. Use for simple software that doesn't need config refresh |

Example use cases:
- **DNSFilter**: `$InstallMode = "Reinstall"` - needs reinstall to pick up new site key
- **Unchecky**: `$InstallMode = "Install"` - just needs to be present, no config

### Step 3: Add Tags in Level.io

Add the appropriate emoji tag to the device:
- `🙏newsoftware` - Install
- `🚫newsoftware` - Remove
- `📌newsoftware` - Pin (lock state)
- `🔄newsoftware` - Reinstall
- `✅newsoftware` - Verify installed (status)
- `❌newsoftware` - Skip (hands off)

## Verification Flow (✅ Has)

When `✅SOFTWARE` is detected and `ShouldVerify = $true`:

1. **Check Installation** - Is the software actually installed?
2. **Check Services** - Are required services running?
3. **Remediation** - If services stopped, attempt restart (try twice over 30 seconds)
4. **Report** - Log status and exit with appropriate code

Each script contains its own verification logic. The library resolves WHAT to do; the script knows HOW to do it.

## Library Functions

| Function | Purpose |
|----------|---------|
| `Get-EmojiMap` | Returns hashtable of all emoji-to-action mappings (single source of truth) |
| `Get-SoftwarePolicy` | Parses device tags, resolves priority, returns policy object |
| `Invoke-SoftwarePolicyCheck` | Runs policy check and outputs formatted results |

## Platform/Category Tags

These tags are used for filtering, not software policy:

| Emoji | Meaning |
|-------|---------|
| 🪟 | Windows |
| 🐧 | Linux |
| 🚨 | Alert/Critical |
| 🌀 | AdelaideMRI (client) |
| 🛰️ | Satellite/remote site |
| 🔧 | Fix/Repair script |
| 🔄 | Maintenance script |

## Emoji Corruption Handling

See [EMOJI-HANDLING.md](EMOJI-HANDLING.md) for how COOLForge handles Level.io emoji corruption and how to add new emoji patterns.
