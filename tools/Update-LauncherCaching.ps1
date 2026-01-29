# Update-LauncherCaching.ps1
# Updates launchers to use smart caching: normal URL first, retry with cache-bust on hash mismatch

param(
    [string]$LaunchersPath = "E:\COOLForge\launchers",
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

# Old pattern (always cache-bust)
$OldPattern = @'
# STEP 4: Download library if needed (always use cache-busting)
if ($NeedsUpdate) {
    $LibFetchUrl = "$LibraryUrl`?t=$CacheBuster"
    if ($DebugScripts) { Write-Host "[DEBUG] Library URL: $LibFetchUrl" }

    try {
        $RemoteContent = (Invoke-WebRequest -Uri $LibFetchUrl -UseBasicParsing -TimeoutSec 10).Content
        # Strip UTF-8 BOM if present (shows as ? when downloaded via Invoke-WebRequest)
        if ($RemoteContent.StartsWith([char]0xFEFF) -or $RemoteContent.StartsWith('?')) {
            $RemoteContent = $RemoteContent.Substring(1)
        }
        $RemoteVersion = Get-ModuleVersion -Content $RemoteContent
        $RemoteHash = Get-StringMD5 -Content $RemoteContent

        if ($DebugScripts) { Write-Host "[DEBUG] Remote library hash: $RemoteHash" }

        # Verify downloaded content matches expected hash
        if ($ExpectedLibraryHash -and $RemoteHash -ne $ExpectedLibraryHash) {
            Write-Host "[!] WARNING: Downloaded library hash doesn't match MD5SUMS!"
            Write-Host "[!] Expected: $ExpectedLibraryHash"
            Write-Host "[!] Got: $RemoteHash"
        }

        # Save with proper UTF-8 BOM for emoji handling
        [System.IO.File]::WriteAllText($LibraryPath, $RemoteContent, [System.Text.UTF8Encoding]::new($true))
        Write-Host "[+] Library updated to v$RemoteVersion"
    } catch {
        if (!(Test-Path $LibraryPath)) {
            Write-Host "[Alert] Cannot download library: $_"
            exit 1
        }
        Write-Host "[!] Using cached library v$LocalVersion"
    }
}
'@

# New pattern (smart caching - normal first, cache-bust on mismatch)
$NewPattern = @'
# STEP 4: Download library if needed
# Strategy: Try normal URL first (CDN cached), retry with cache-bust if hash mismatch
if ($NeedsUpdate) {
    $LibFetchUrl = if ($DebugScripts) { "$LibraryUrl`?t=$CacheBuster" } else { $LibraryUrl }
    if ($DebugScripts) { Write-Host "[DEBUG] Library URL: $LibFetchUrl" }

    try {
        $RemoteContent = (Invoke-WebRequest -Uri $LibFetchUrl -UseBasicParsing -TimeoutSec 10).Content
        # Strip UTF-8 BOM if present (shows as ? when downloaded via Invoke-WebRequest)
        if ($RemoteContent.StartsWith([char]0xFEFF) -or $RemoteContent.StartsWith('?')) {
            $RemoteContent = $RemoteContent.Substring(1)
        }
        $RemoteVersion = Get-ModuleVersion -Content $RemoteContent
        $RemoteHash = Get-StringMD5 -Content $RemoteContent

        if ($DebugScripts) { Write-Host "[DEBUG] Remote library hash: $RemoteHash" }

        # If hash mismatch and not already cache-busting, retry with cache-bust
        if ($ExpectedLibraryHash -and $RemoteHash -ne $ExpectedLibraryHash -and -not $DebugScripts) {
            Write-Host "[*] Hash mismatch - retrying with cache-bust..."
            $LibFetchUrl = "$LibraryUrl`?t=$CacheBuster"
            $RemoteContent = (Invoke-WebRequest -Uri $LibFetchUrl -UseBasicParsing -TimeoutSec 10).Content
            if ($RemoteContent.StartsWith([char]0xFEFF) -or $RemoteContent.StartsWith('?')) {
                $RemoteContent = $RemoteContent.Substring(1)
            }
            $RemoteVersion = Get-ModuleVersion -Content $RemoteContent
            $RemoteHash = Get-StringMD5 -Content $RemoteContent
        }

        # Final hash check
        if ($ExpectedLibraryHash -and $RemoteHash -ne $ExpectedLibraryHash) {
            Write-Host "[!] WARNING: Library hash still doesn't match after cache-bust"
            Write-Host "[!] Expected: $ExpectedLibraryHash"
            Write-Host "[!] Got: $RemoteHash"
        }

        # Save with proper UTF-8 BOM for emoji handling
        [System.IO.File]::WriteAllText($LibraryPath, $RemoteContent, [System.Text.UTF8Encoding]::new($true))
        Write-Host "[+] Library updated to v$RemoteVersion"
    } catch {
        if (!(Test-Path $LibraryPath)) {
            Write-Host "[Alert] Cannot download library: $_"
            exit 1
        }
        Write-Host "[!] Using cached library v$LocalVersion"
    }
}
'@

# Find all launcher files
$Launchers = Get-ChildItem -Path $LaunchersPath -Recurse -Filter "*.ps1"
Write-Host "Found $($Launchers.Count) launcher files"

$Updated = 0
$Skipped = 0
$AlreadyDone = 0
$Failed = 0

foreach ($Launcher in $Launchers) {
    Write-Host "`nProcessing: $($Launcher.Name)" -NoNewline

    try {
        $Content = Get-Content -Path $Launcher.FullName -Raw -Encoding UTF8

        # Check if already updated
        if ($Content -match 'Strategy: Try normal URL first') {
            Write-Host " - Already updated" -ForegroundColor Green
            $AlreadyDone++
            continue
        }

        # Check if has old pattern
        if ($Content -notmatch 'STEP 4: Download library if needed \(always use cache-busting\)') {
            Write-Host " - Different pattern, skipping" -ForegroundColor Yellow
            $Skipped++
            continue
        }

        # Replace using .Replace() method - NOT -replace operator!
        # The -replace operator treats $_ as regex backreference which corrupts files
        $NewContent = $Content.Replace($OldPattern, $NewPattern)

        if ($NewContent -eq $Content) {
            Write-Host " - No changes made" -ForegroundColor Yellow
            $Skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host " - Would update" -ForegroundColor Cyan
            $Updated++
            continue
        }

        # Write with proper UTF-8 BOM
        [System.IO.File]::WriteAllText($Launcher.FullName, $NewContent, [System.Text.UTF8Encoding]::new($true))
        Write-Host " - Updated" -ForegroundColor Green
        $Updated++
    }
    catch {
        Write-Host " - FAILED: $_" -ForegroundColor Red
        $Failed++
    }
}

Write-Host "`n=========================================="
Write-Host "Summary:"
Write-Host "  Updated: $Updated"
Write-Host "  Already done: $AlreadyDone"
Write-Host "  Skipped: $Skipped"
Write-Host "  Failed: $Failed"

if ($WhatIf) {
    Write-Host "`nRun without -WhatIf to apply changes."
}
