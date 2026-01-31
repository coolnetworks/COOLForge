<#
.SYNOPSIS
    Updates all launcher scripts from the template.
#>

$templateContent = Get-Content "$PSScriptRoot\..\templates\Launcher_Template.ps1" -Raw

# Extract everything after the first $ScriptToRun line
if ($templateContent -match '(?s)^.*?\r?\n(\$ScriptToRun = [^\r\n]+)\r?\n(.*)$') {
    $templateScriptToRun = $Matches[1]
    $templateBody = $Matches[2]
} else {
    Write-Host "Could not parse template" -ForegroundColor Red
    exit 1
}

$launchers = Get-ChildItem "$PSScriptRoot\..\launchers\*.ps1" | Where-Object {
    $_.Name -notlike "*debug.ps1" -and $_.Name -notlike "*unchecky.ps1"
}

$updated = 0

foreach ($launcher in $launchers) {
    $content = Get-Content $launcher.FullName -Raw

    # Extract the ScriptToRun line from this launcher
    if ($content -match '(?m)^\$ScriptToRun = [^\r\n]+') {
        $scriptToRunLine = $Matches[0]

        # Rebuild: header + ScriptToRun + template body
        $header = @"
# ============================================================
# SCRIPT TO RUN - PRE-CONFIGURED
# ============================================================
"@
        $newContent = $header + "`r`n" + $scriptToRunLine + "`r`n" + $templateBody

        Set-Content -Path $launcher.FullName -Value $newContent -Encoding UTF8 -NoNewline
        Write-Host "Updated: $($launcher.Name)" -ForegroundColor Green
        $updated++
    } else {
        Write-Host "Skipped (no ScriptToRun): $($launcher.Name)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Updated $updated launchers" -ForegroundColor Cyan
