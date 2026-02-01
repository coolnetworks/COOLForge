# MeshCentral Policy

Software policy enforcement for MeshCentral remote management agent.

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

    G[Initialize-SoftwarePolicyInfrastructure] --> H[Get-SoftwarePolicy]

    H --> I{Resolved Action}
    I -->|Pin| J1[No-op]
    I -->|Install| J2[Install MeshCentral]
    I -->|Remove| J3[Remove MeshCentral]
    I -->|Reinstall| J4[Remove + Install]
    I -->|No Policy| J5[Verify State]

    J2 --> K[Download meshagent.exe]
    K --> K1[Unblock-File]
    K1 --> K2{PE Header = MZ?}
    K2 -->|No| K3[ERROR: Invalid binary]
    K2 -->|Yes| K4["Start-Process -fullinstall"]
    K4 --> L

    J3 --> M[Find Mesh Agent Service]
    M --> M1[Stop & Remove]
    M1 --> L

    J4 --> M
    J5 --> L

    L[Update Tags] --> N{Success?}
    N -->|Yes| N1["Remove action tag<br/>Set/Remove HAS tag"]
    N -->|No| N2[Log Error]
    N1 --> O[Exit 0]
    N2 --> P[Exit 1]
    J1 --> O
    K3 --> P

    style K2 fill:#1a1a2e,stroke:#e94560,color:#fff
    style K3 fill:#e94560,stroke:#fff,color:#fff
    style J2 fill:#22c55e,stroke:#fff,color:#fff
    style J3 fill:#f97316,stroke:#fff,color:#fff
```

### Installation Detail

```mermaid
flowchart LR
    subgraph "Install-MeshCentral"
        direction TB
        I1[Get download URL from policy field] --> I2[Resolve binaries folder]
        I2 --> I3["Download to<br/>scratch/binaries/meshagent.exe"]
        I3 --> I4[Unblock-File for MOTW]
        I4 --> I5{Read first 2 bytes}
        I5 -->|"MZ header"| I6["Start-Process meshagent.exe<br/>-ArgumentList '-fullinstall'<br/>-Wait -PassThru"]
        I5 -->|"Not MZ"| I7["ERROR: Not a valid PE<br/>(wrong file downloaded?)"]
        I6 --> I8{Exit code 0?}
        I8 -->|Yes| I9[Install Success]
        I8 -->|No| I10[Install Failed]
    end

    style I7 fill:#e94560,stroke:#fff,color:#fff
    style I9 fill:#22c55e,stroke:#fff,color:#fff
```

## Overview

Manages MeshCentral agent installation and removal based on tag and custom field policies. The agent installer is downloaded as an `.exe` from the MeshCentral server and run with `-fullinstall`.

## Policy Field

`policy_meshcentral` — Set to `install`, `remove`, `pin`, or leave as default for tag-based control.

## Additional Fields

| Field | Description |
|-------|-------------|
| `policy_meshcentral_server_url` | MeshCentral server URL |
| `policy_meshcentral_download_url` | Windows agent download URL (must point to `.exe`) |
| `policy_meshcentral_linux_install` | Linux installation command |
| `policy_meshcentral_mac_download_url` | macOS agent download URL |

## Tags

| Tag | Action | Persists |
|-----|--------|----------|
| `MESHCENTRAL` (Install) | Install MeshCentral if missing | No — removed after action |
| `MESHCENTRAL` (Remove) | Remove MeshCentral if present | No — removed after action |
| `MESHCENTRAL` (Pin) | Lock current state — no changes | Yes — admin intent |
| `MESHCENTRAL` (Reinstall) | Remove then reinstall | No — removed after action |
| `MESHCENTRAL` (Has) | Status: currently installed | Yes — set/cleared by script |

## Installation Notes

- **Installer format:** `.exe` only (not `.msh`). The download URL in `policy_meshcentral_download_url` must point to an executable.
- **PE validation:** Before running, the script reads the first 2 bytes and verifies the `MZ` header. If the file isn't a valid PE, the install is aborted with an error.
- **Unblock-File:** Applied after download to remove Mark of the Web, preventing "operation not supported" errors when running as SYSTEM via Level.io.
- **Binaries folder:** Installer is saved to `scratch/binaries/meshagent.exe` via `Get-BinariesFolder`, shared across runs.
- **Install method:** `Start-Process -FilePath meshagent.exe -ArgumentList "-fullinstall" -Wait -PassThru`

## Platforms

- Windows (PowerShell launcher)
- Linux (Bash launcher)
- macOS (Bash launcher)

## Related

- [Policy System](README.md)
- [Tag System](TAGS.md)
- [Policy Fields Reference](../POLICY-FIELDS.md)
