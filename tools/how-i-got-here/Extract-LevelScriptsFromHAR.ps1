# Extract-LevelScriptsFromHAR.ps1
# Extracts all scripts directly from a HAR file (no API calls needed)

param(
    [string]$HarFilePath = "e:\allscriptsapp.level.io.har",
    [string]$OutputDir = "E:\DLScripts"
)

$ErrorActionPreference = "Stop"

function Get-SafeFileName {
    param([string]$Name)
    $invalid = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalid)
    return ($Name -replace $re, '_').Trim()
}

Write-Host "=== Level.io Script Extractor (HAR-based) ===" -ForegroundColor Cyan
Write-Host ""

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
Write-Host "Output directory: $OutputDir" -ForegroundColor Gray

# Load HAR file
Write-Host "Loading HAR file: $HarFilePath" -ForegroundColor Gray
$har = Get-Content $HarFilePath -Raw | ConvertFrom-Json

Write-Host "Extracting scripts from HAR responses..." -ForegroundColor Cyan
Write-Host ""

$extracted = 0
$failed = 0

# Track extracted scripts to avoid duplicates
$extractedIds = @{}

# Helper function to save a script
function Save-Script {
    param(
        [hashtable]$Script,
        [string]$OutputDir
    )

    $scriptName = $Script.name
    $command = $Script.command
    $shell = $Script.shell
    $description = $Script.description
    $timeout = $Script.timeout
    $runAs = $Script.runAs

    # Build folder path from ancestry
    $folderPath = ""
    if ($Script.groupAncestry -and $Script.groupAncestry.Count -gt 0) {
        $pathParts = @()
        # Ancestry is leaf to root, so reverse
        $reversed = $Script.groupAncestry | Sort-Object { [array]::IndexOf($Script.groupAncestry, $_) } -Descending
        foreach ($ancestor in $reversed) {
            $safeName = Get-SafeFileName -Name $ancestor.name
            if ($safeName) { $pathParts += $safeName }
        }
        $folderPath = $pathParts -join "\"
    }
    elseif ($Script.group) {
        $folderPath = Get-SafeFileName -Name $Script.group.name
    }

    $fullFolderPath = if ($folderPath) { Join-Path $OutputDir $folderPath } else { $OutputDir }
    if (-not (Test-Path $fullFolderPath)) {
        New-Item -ItemType Directory -Path $fullFolderPath -Force | Out-Null
    }

    # Determine file extension
    $ext = switch ($shell) {
        "POWERSHELL" { ".ps1" }
        "CMD" { ".cmd" }
        "BASH" { ".sh" }
        default { ".txt" }
    }

    $safeScriptName = Get-SafeFileName -Name $scriptName
    $filePath = Join-Path $fullFolderPath "$safeScriptName$ext"

    Write-Host "Extracting: $scriptName" -ForegroundColor White
    Write-Host "  -> $filePath" -ForegroundColor Gray

    # Add metadata as comments at the top
    $header = @()
    if ($shell -eq "POWERSHELL") {
        $header += "<#"
        $header += "Script: $scriptName"
        $header += "Shell: $shell"
        if ($timeout) { $header += "Timeout: $timeout seconds" }
        if ($runAs) { $header += "RunAs: $runAs" }
        if ($description) {
            $header += ""
            $header += "Description:"
            $description -split "`n" | ForEach-Object { $header += "  $_" }
        }
        $header += "#>"
        $header += ""
    }
    elseif ($shell -eq "BASH") {
        $header += "#!/bin/bash"
        $header += "# Script: $scriptName"
        $header += "# Shell: $shell"
        if ($timeout) { $header += "# Timeout: $timeout seconds" }
        if ($runAs) { $header += "# RunAs: $runAs" }
        if ($description) {
            $header += "#"
            $header += "# Description:"
            $description -split "`n" | ForEach-Object { $header += "#   $_" }
        }
        $header += ""
    }
    else {
        $header += "REM Script: $scriptName"
        $header += "REM Shell: $shell"
        if ($timeout) { $header += "REM Timeout: $timeout seconds" }
        if ($runAs) { $header += "REM RunAs: $runAs" }
        $header += ""
    }

    $fullContent = ($header -join "`r`n") + $command

    # Save with UTF-8 encoding
    [System.IO.File]::WriteAllText($filePath, $fullContent, [System.Text.UTF8Encoding]::new($false))

    Write-Host "  OK" -ForegroundColor Green
    return $true
}

# Process each GraphQL response
foreach ($entry in $har.log.entries) {
    if ($entry.request.url -match 'api.level.io/graphql' -and $entry.response.content.text) {
        $responseText = $entry.response.content.text

        # Decode if base64 encoded
        $decoded = $responseText
        if ($entry.response.content.encoding -eq "base64") {
            try {
                $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($responseText))
            } catch {
                continue
            }
        }

        # Parse JSON
        try {
            $respJson = $decoded | ConvertFrom-Json
        } catch {
            continue
        }

        # Check scriptSearch.nodes
        if ($respJson.data.scriptSearch.nodes) {
            foreach ($node in $respJson.data.scriptSearch.nodes) {
                if ($node.command -and -not $extractedIds.ContainsKey($node.id)) {
                    try {
                        $scriptData = @{
                            name = $node.name
                            shell = $node.shell
                            command = $node.command
                            description = $node.description
                            timeout = $node.timeout
                            runAs = $node.runAs
                            group = $node.group
                            groupAncestry = $node.groupAncestry
                        }
                        if (Save-Script -Script $scriptData -OutputDir $OutputDir) {
                            $extracted++
                            $extractedIds[$node.id] = $true
                        }
                    } catch {
                        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
                        $failed++
                    }
                }
            }
        }

        # Check scriptSearch.edges
        if ($respJson.data.scriptSearch.edges) {
            foreach ($edge in $respJson.data.scriptSearch.edges) {
                $node = $edge.node
                if ($node.command -and -not $extractedIds.ContainsKey($node.id)) {
                    try {
                        $scriptData = @{
                            name = $node.name
                            shell = $node.shell
                            command = $node.command
                            description = $node.description
                            timeout = $node.timeout
                            runAs = $node.runAs
                            group = $node.group
                            groupAncestry = $node.groupAncestry
                        }
                        if (Save-Script -Script $scriptData -OutputDir $OutputDir) {
                            $extracted++
                            $extractedIds[$node.id] = $true
                        }
                    } catch {
                        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
                        $failed++
                    }
                }
            }
        }

        # Check if this is a ScriptPage response with command (single script view)
        if ($respJson.data.script.command -and -not $extractedIds.ContainsKey($respJson.data.script.id)) {
            $s = $respJson.data.script
            try {
                $scriptData = @{
                    name = $s.name
                    shell = $s.shell
                    command = $s.command
                    description = $s.description
                    timeout = $s.timeout
                    runAs = $s.runAs
                    group = $s.group
                    groupAncestry = $s.groupAncestry
                }
                if (Save-Script -Script $scriptData -OutputDir $OutputDir) {
                    $extracted++
                    $extractedIds[$s.id] = $true
                }
            } catch {
                Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
                $failed++
            }
        }
    }
}

Write-Host ""
Write-Host "=== Complete ===" -ForegroundColor Cyan
Write-Host "Extracted: $extracted scripts" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Gray" })
Write-Host "Output: $OutputDir" -ForegroundColor Gray
