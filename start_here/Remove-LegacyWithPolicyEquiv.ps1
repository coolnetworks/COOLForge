Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) "modules\COOLForge-Common.psm1") -Force -DisableNameChecking

$ConfigPath = Join-Path $PSScriptRoot ".COOLForge_Lib-setup.json"
$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$ApiKey = if ($Config.CoolForge_ApiKeyEncrypted) {
    Unprotect-ApiKey -EncryptedText $Config.CoolForge_ApiKeyEncrypted
} elseif ($Config.ApiKeyEncrypted) {
    Unprotect-ApiKey -EncryptedText $Config.ApiKeyEncrypted
} else { $null }

Initialize-LevelApi -ApiKey $ApiKey | Out-Null

# Load definitions
$DefsPath = Join-Path (Split-Path $PSScriptRoot -Parent) "definitions\custom-fields.json"
$Defs = Get-Content $DefsPath -Raw | ConvertFrom-Json

# Build list of defined field names and their legacy names
$DefinedNames = @()
$LegacyToNew = @{}
foreach ($group in $Defs.fields.PSObject.Properties.Name) {
    foreach ($f in $Defs.fields.$group) {
        $DefinedNames += $f.name
        if ($f.legacyNames) {
            foreach ($legacy in $f.legacyNames) {
                $LegacyToNew[$legacy] = $f.name
            }
        }
    }
}

# Get Level.io fields
$Result = Get-LevelCustomFields
$Fields = if ($Result -isnot [array] -and $Result.data) { $Result.data } else { $Result }

Write-Host ""
Write-Host "Checking for legacy fields with policy equivalents..." -ForegroundColor Cyan
Write-Host ""

$ToDelete = @()
foreach ($f in $Fields) {
    $name = $f.name

    # Check if this is a legacy name that maps to a defined field
    if ($LegacyToNew.ContainsKey($name)) {
        $newName = $LegacyToNew[$name]
        # Check if the new field exists in Level.io
        $newExists = $Fields | Where-Object { $_.name -eq $newName }
        if ($newExists) {
            Write-Host "  [!] $name -> superseded by $newName" -ForegroundColor Yellow
            $ToDelete += $f
        } else {
            Write-Host "  [?] $name -> new field $newName not yet created" -ForegroundColor DarkGray
        }
    }
    # Check if not in definitions at all (and not a known non-coolforge field)
    elseif ($DefinedNames -notcontains $name) {
        $nonCoolforge = @("Managed", "ssid", "ssid_password", "users_admins", "users_admins_pass",
                          "users", "users_pass", "standards_bypass", "Cipp TenantID", "quiet hours", "AgreedRebootTIme")
        if ($nonCoolforge -notcontains $name) {
            Write-Host "  [?] $name -> not in definitions (orphan?)" -ForegroundColor DarkYellow
        }
    }
}

if ($ToDelete.Count -eq 0) {
    Write-Host "  No legacy fields to remove." -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "Delete $($ToDelete.Count) legacy field(s)? (y/N): " -NoNewline -ForegroundColor Yellow
$confirm = Read-Host
if ($confirm -ne 'y') {
    Write-Host "Cancelled." -ForegroundColor DarkGray
    exit 0
}

Write-Host ""
foreach ($f in $ToDelete) {
    Write-Host "  Deleting $($f.name)..." -NoNewline
    $del = Remove-LevelCustomField -FieldId $f.id -FieldName $f.name
    if ($del) { Write-Host " OK" -ForegroundColor Green }
    else { Write-Host " FAILED" -ForegroundColor Red }
    Start-Sleep -Milliseconds 300
}
Write-Host ""
Write-Host "Done!" -ForegroundColor Green
