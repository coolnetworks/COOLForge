<#
.SYNOPSIS
    Creates the standard COOLForge script folder structure.

.DESCRIPTION
    This script creates the recommended folder organization for COOLForge scripts
    and automations. Run this when setting up a new COOLForge repository or when
    adding new categories.

.PARAMETER BasePath
    The base path where to create the folder structure. Defaults to the repository root.

.EXAMPLE
    .\New-ScriptFolderStructure.ps1
    Creates folders in the default location (repository scripts/ folder)

.EXAMPLE
    .\New-ScriptFolderStructure.ps1 -BasePath "C:\MyScripts"
    Creates folders in a custom location

.NOTES
    Version: 2025.12.30.01
#>

param(
    [string]$BasePath = (Split-Path -Parent $PSScriptRoot)
)

# Define the folder categories and their purposes
$FolderStructure = @{
    "scripts" = @{
        "Deploy"    = "Install software, deploy configurations, provision resources"
        "Remove"    = "Uninstall software, cleanup, remove configurations"
        "Update"    = "Patch, upgrade existing software and components"
        "Fix"       = "Repair broken things, remediation scripts"
        "Configure" = "Change settings without installing new software"
        "Check"     = "Read-only audits, compliance checks, health monitoring"
        "Secure"    = "Hardening, security policies, lockdown scripts"
        "Maintain"  = "Scheduled maintenance, cleanup tasks, optimization"
        "Provision" = "New device/user setup, onboarding workflows"
        "Report"    = "Generate reports, inventory, documentation"
        "Utility"   = "Miscellaneous tools and helper scripts"
    }
    "automations" = @{
        "Deploy"    = "Automated deployment workflows"
        "Remove"    = "Automated removal and cleanup workflows"
        "Update"    = "Automated patching and upgrade workflows"
        "Fix"       = "Automated remediation workflows"
        "Configure" = "Automated configuration workflows"
        "Check"     = "Automated monitoring and compliance workflows"
        "Secure"    = "Automated security hardening workflows"
        "Maintain"  = "Automated maintenance workflows"
        "Provision" = "Automated provisioning workflows"
        "Report"    = "Automated reporting workflows"
        "Utility"   = "Miscellaneous automation workflows"
    }
}

Write-Host "Creating COOLForge folder structure in: $BasePath" -ForegroundColor Cyan
Write-Host ""

foreach ($rootFolder in $FolderStructure.Keys) {
    $rootPath = Join-Path $BasePath $rootFolder

    if (-not (Test-Path $rootPath)) {
        New-Item -Path $rootPath -ItemType Directory -Force | Out-Null
        Write-Host "Created: $rootFolder\" -ForegroundColor Green
    } else {
        Write-Host "Exists:  $rootFolder\" -ForegroundColor Yellow
    }

    foreach ($subFolder in $FolderStructure[$rootFolder].Keys) {
        $subPath = Join-Path $rootPath $subFolder
        $description = $FolderStructure[$rootFolder][$subFolder]

        if (-not (Test-Path $subPath)) {
            New-Item -Path $subPath -ItemType Directory -Force | Out-Null
            Write-Host "  Created: $subFolder\ - $description" -ForegroundColor Green
        } else {
            Write-Host "  Exists:  $subFolder\" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

Write-Host "Folder structure complete!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Folder Categories:" -ForegroundColor White
Write-Host "  Deploy    - Install software, deploy configs" -ForegroundColor Gray
Write-Host "  Remove    - Uninstall, cleanup" -ForegroundColor Gray
Write-Host "  Update    - Patch, upgrade software" -ForegroundColor Gray
Write-Host "  Fix       - Repair broken things" -ForegroundColor Gray
Write-Host "  Configure - Change settings" -ForegroundColor Gray
Write-Host "  Check     - Audits, compliance, monitoring" -ForegroundColor Gray
Write-Host "  Secure    - Hardening, security policies" -ForegroundColor Gray
Write-Host "  Maintain  - Scheduled maintenance" -ForegroundColor Gray
Write-Host "  Provision - New device/user setup" -ForegroundColor Gray
Write-Host "  Report    - Generate reports, inventory" -ForegroundColor Gray
Write-Host "  Utility   - Misc tools and helpers" -ForegroundColor Gray
