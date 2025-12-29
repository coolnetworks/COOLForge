<#
.SYNOPSIS
    DEPRECATED - This module has moved to the modules/ folder.

.DESCRIPTION
    COOLForge-Common.psm1 has been relocated to:
    https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1

    This stub will automatically download and load the module from the new location.

    Please update your custom field value for 'ps_module_library_source' to:
    https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1

.NOTES
    This redirect stub will be removed in a future release.
#>

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Yellow
Write-Host " NOTICE: COOLForge-Common.psm1 has moved to the modules/ folder" -ForegroundColor Yellow
Write-Host "========================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host " Please update your Level.io custom field 'ps_module_library_source' to:" -ForegroundColor Cyan
Write-Host " https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1" -ForegroundColor White
Write-Host ""
Write-Host " Loading module from new location..." -ForegroundColor Gray
Write-Host ""

# Determine the new module URL based on how this stub was loaded
$NewModuleUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/main/modules/COOLForge-Common.psm1"

# If we're running from a versioned URL, try to match it
if ($MyInvocation.MyCommand.Path -match 'COOLForge/(v[\d\.]+)/') {
    $Version = $Matches[1]
    $NewModuleUrl = "https://raw.githubusercontent.com/coolnetworks/COOLForge/$Version/modules/COOLForge-Common.psm1"
}

try {
    # Download the actual module
    $ModuleContent = (Invoke-WebRequest -Uri $NewModuleUrl -UseBasicParsing -ErrorAction Stop).Content

    # Load it as a dynamic module
    New-Module -Name "COOLForge-Common" -ScriptBlock ([scriptblock]::Create($ModuleContent)) | Import-Module -Force -Global

    Write-Host "[OK] Module loaded successfully from new location." -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "[ERROR] Failed to load module from new location: $_" -ForegroundColor Red
    Write-Host "Please manually update your configuration." -ForegroundColor Yellow
    throw
}
