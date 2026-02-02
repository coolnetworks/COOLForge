# ScreenConnect Policy

Software policy enforcement for ConnectWise ScreenConnect (Control) remote access agent.

## Naming Convention

ScreenConnect uses a **split naming** model — this is the only script where tag names differ from field names:

| Aspect | Name | Example |
|--------|------|---------|
| **Tags** | `SC` (short) | `SC`, `SC`, `SC`, `SC`, `SC` |
| **Fields** | `screenconnect` (full) | `policy_screenconnect`, `policy_screenconnect_instance_id`, etc. |

This is handled by passing both `-SoftwareName "screenconnect"` and `-TagName "sc"` to `Initialize-SoftwarePolicyInfrastructure`. The function:
1. Creates tags using `TagName` (uppercased) → `SC`, `SC`, etc.
2. Creates the policy field using `SoftwareName` → `policy_screenconnect`
3. Auto-deletes the stale `policy_sc` field if it exists from older code

## Flow

```mermaid
flowchart TD
    A[Level.io Triggers Launcher] --> B[Load Variables]
    B --> C[Download & Verify Library]
    C --> D[Invoke-ScriptLauncher]
    D --> E[Initialize-LevelScript]

    E --> F{Global Tags?}
    F -->|"Has cross"| Z1[EXIT: Excluded]
    F -->|"No checkmark"| Z2[EXIT: Not Verified]
    F -->|"Both check+cross"| Z3[EXIT: Globally Pinned]
    F -->|"Checkmark only"| G

    G[Initialize-SoftwarePolicyInfrastructure] --> G1[Create SC Tags]
    G1 --> G2[Create policy_screenconnect Field]
    G2 --> G3{TagName != SoftwareName?}
    G3 -->|Yes| G4[Find & Delete policy_sc]
    G3 -->|No| G5
    G4 --> G5[Create SC-Specific Fields]

    G5 --> H[Get-SoftwarePolicy]

    H --> I{Resolved Action}
    I -->|Pin| J1[No-op]
    I -->|Install| J2[Install ScreenConnect]
    I -->|Remove| J3[Remove ScreenConnect]
    I -->|Reinstall| J4[Remove + Install]
    I -->|No Policy| J5[Verify State]

    J2 --> K[Build MSI URL from Instance]
    K --> K1[Download MSI]
    K1 --> K2[Install via msiexec]
    K2 --> L

    J3 --> M[Find Uninstall String]
    M --> M1[Run Uninstaller]
    M1 --> L

    J4 --> M
    J5 --> L

    L[Update Tags] --> N{Success?}
    N -->|Yes| N1["Remove action tag<br/>Set/Remove HAS tag"]
    N -->|No| N2[Log Error]
    N1 --> O[Exit 0]
    N2 --> P[Exit 1]
    J1 --> O

    style G fill:#1a1a2e,stroke:#e94560,color:#fff
    style G4 fill:#e94560,stroke:#fff,color:#fff
    style J2 fill:#22c55e,stroke:#fff,color:#fff
    style J3 fill:#f97316,stroke:#fff,color:#fff
```

### Infrastructure Bootstrap Detail

```mermaid
flowchart LR
    subgraph "Initialize-SoftwarePolicyInfrastructure"
        direction TB
        S1["SoftwareName = screenconnect<br/>TagName = sc"] --> S2

        subgraph "Step 1: Tags (using TagName)"
            S2["Create SC"] --> S3["Create SC"]
            S3 --> S4["Create SC"]
            S4 --> S5["Create SC"]
            S5 --> S6["Create SC"]
        end

        S6 --> S7

        subgraph "Step 2: System Tags"
            S7["Create checkmark"] --> S8["Create cross"]
            S8 --> S9["Create DEBUG tags"]
        end

        S9 --> S10

        subgraph "Step 3: Fields (using SoftwareName)"
            S10["Create policy_screenconnect"]
        end

        S10 --> S11

        subgraph "Step 4: Stale Cleanup"
            S11{"policy_sc exists?"} -->|Yes| S12["DELETE policy_sc"]
            S11 -->|No| S13[Skip]
        end
    end

    style S12 fill:#e94560,stroke:#fff,color:#fff
    style S10 fill:#22c55e,stroke:#fff,color:#fff
```

## Overview

Manages ScreenConnect agent installation and removal based on tag and custom field policies. Uses the 5-tag model (Install, Remove, Pin, Reinstall, Has) with `SC` as the tag suffix, while all custom fields use the full `screenconnect` name.

## Policy Field

`policy_screenconnect` — Set to `install`, `remove`, `pin`, or leave as default for tag-based control.

> **Note:** Older versions of this script incorrectly created a `policy_sc` field. The current version auto-detects and removes this stale field on first run.

## Additional Fields

| Field | Description |
|-------|-------------|
| `policy_screenconnect_instance_id` | ScreenConnect instance ID (GUID). Used for whitelisting and to derive the service display name: `ScreenConnect Client (<id>)` |
| `policy_screenconnect_api_user` | API username for device URL lookup |
| `policy_screenconnect_api_password` | API password |
| `policy_screenconnect_device_url` | Device-specific ScreenConnect URL (auto-populated) |
| `policy_screenconnect_baseurl` | Base URL for ScreenConnect server |

## Tags

| Tag | Action | Persists |
|-----|--------|----------|
| `SC` (Install) | Install ScreenConnect if missing | No — removed after action |
| `SC` (Remove) | Remove ScreenConnect if present | No — removed after action |
| `SC` (Pin) | Lock current state — no changes | Yes — admin intent |
| `SC` (Reinstall) | Remove then reinstall | No — removed after action |
| `SC` (Has) | Status: currently installed | Yes — set/cleared by script |

## Script Variables

```
$SoftwareName  = "screenconnect"   # Used for field names
$TagName       = "sc"              # Used for tag names (short form)
$ScriptVersion = "2026.01.31.01"   # Bumped for launcher cache invalidation
```

## Related Scripts

- [Extract and Set ScreenConnect Device URL](../scripts/ScreenConnect-Device-URL.md)
- [Force Remove Non-MSP ScreenConnect](../scripts/Force-Remove-Non-MSP-ScreenConnect.md)

## Related

- [Policy System](README.md)
- [Tag System](TAGS.md)
- [Policy Fields Reference](../POLICY-FIELDS.md)
