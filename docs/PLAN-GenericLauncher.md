# Generic Launcher Plan

**Status:** Waiting on Level.io to implement `{{level_script_name}}` variable (approved feature request)

---

## Overview

Replace multiple script-specific launchers with a single generic launcher that dynamically downloads and executes scripts based on the Level.io script name.

---

## How It Works

1. Level.io passes `{{level_script_name}}` - the name of the script as defined in Level.io
2. Generic launcher receives this variable (text substitution happens at deployment time)
3. Launcher downloads `{{level_script_name}}.ps1` from GitHub repo
4. Launcher executes the downloaded script

---

## Benefits

- Single launcher to maintain instead of N copies
- Updates to launcher logic only need to happen once
- Reduces deployment complexity and drift between launchers
- Adding new scripts = add `.ps1` to repo + create entry in Level.io

---

## Implementation Tasks

### Prerequisites
- [ ] Level.io implements `{{level_script_name}}` system variable
- [ ] Confirm exact variable name and behavior

### Development
- [ ] Create generic launcher script using existing launcher logic
- [ ] Decide on naming convention (recommend: `Verb-Noun` PascalCase to match PowerShell conventions)
- [ ] Determine if validation/allowlist is needed or trust Level's input
- [ ] Test with pilot scripts

### Migration
- [ ] Deploy generic launcher alongside existing launchers
- [ ] Test with subset of scripts
- [ ] Document any edge cases discovered
- [ ] Retire individual launchers once proven stable

---

## Technical Details

### Launcher Concept

```powershell
# Generic launcher receives script name from Level.io
$ScriptName = "{{level_script_name}}"

# Existing launcher logic downloads from GitHub
# Downloads: scripts/$ScriptName.ps1
# Executes the script
```

### Level.io Variable Substitution

Level.io performs text substitution at deployment time. The placeholder `{{level_script_name}}` is replaced with the actual value before the script reaches the endpoint.

Example: If Level.io script is named `Install-ChromeEnterprise`, the endpoint receives:
```powershell
$ScriptName = "Install-ChromeEnterprise"
```

---

## Naming Convention Decision

**Recommendation:** Use PowerShell `Verb-Noun` PascalCase format
- Level.io script name: `Install-ChromeEnterprise`
- GitHub file: `scripts/Install-ChromeEnterprise.ps1`

This keeps consistency with PowerShell conventions and makes scripts self-documenting.

---

## Open Questions

1. Exact name of the Level.io variable (`{{level_script_name}}` assumed)
2. Whether to implement allowlist validation or trust Level's input
3. Error handling if script doesn't exist in repo

---

## Related Files

- Current launchers: `launchers/` folder
- Scripts: `scripts/` folder
- Variables reference: `docs/VARIABLES.md`
