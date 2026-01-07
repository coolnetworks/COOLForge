# Backup-LevelAutomationsAndScripts.ps1

Exports all automations and scripts from Level.io via GraphQL API.

## What It Exports

- **Tags** - All tags with their styles
- **Custom Fields** - All custom field definitions
- **Scripts** - All scripts with full content, organized by folder structure
- **Automations** - All automations with triggers, actions, conditions, and variables

## Requirements

- PowerShell 5.1+
- Level.io account with appropriate permissions
- JWT authentication token

## Usage

```powershell
# Run with cached token (if available)
.\Backup-LevelAutomationsAndScripts.ps1

# Run with specific output directory
.\Backup-LevelAutomationsAndScripts.ps1 -OutputDir "C:\Backups\Level"

# Run with token directly
.\Backup-LevelAutomationsAndScripts.ps1 -Token "eyJ..."
```

## Getting Your JWT Token

1. Log into **app.level.io** in your browser
2. Open DevTools (F12) > **Network** tab
3. Click anything in Level.io to trigger a request
4. Click any **graphql** request in the list
5. Go to **Headers** > **Request Headers** > **Authorization**
6. Copy the value (starts with `eyJ...`)

The token is cached to `jwt-token-cache.txt` in the output directory for subsequent runs.

## Output Structure

```
level-export/
├── tags.json                    # All tags
├── custom-fields.json           # All custom fields
├── full-export.json             # Combined export file
├── jwt-token-cache.txt          # Cached JWT token
├── scripts/
│   ├── FolderName/
│   │   └── ScriptName.ps1       # Scripts organized by folder
│   └── ...
└── automations/
    ├── AutomationName.json      # Individual automation JSON
    └── ...
```

## Script Output Format

Scripts are saved with metadata headers:

```powershell
<#
Script: My Script Name
ID: Z2lkOi8v...
Shell: POWERSHELL
Timeout: 300 seconds
RunAs: SYSTEM

Description:
  Script description here
#>

# Actual script content follows...
```

## Rate Limiting

The script includes random delays (3-12 seconds) between API requests to avoid rate limiting.

## Troubleshooting

**"GraphQL Error: Not authenticated"**
- Your JWT token has expired. Get a fresh token from DevTools.

**"Token doesn't look like a JWT"**
- Make sure you copied the full token starting with `eyJ`
- Don't include "Bearer " prefix

**Slow export**
- The script intentionally uses delays between requests
- Large organizations with many automations will take longer
