# Extract-LevelAutomationsFromHAR.ps1
# Extracts automation definitions from HAR files captured during Level.io import

param(
    [string]$HarFilePath,
    [string]$OutputDir = "E:\DLScripts\automations"
)

$ErrorActionPreference = "Stop"

function Get-SafeFileName {
    param([string]$Name)
    $invalid = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalid)
    return ($Name -replace $re, '_').Trim()
}

Write-Host "=== Level.io Automation Extractor (HAR-based) ===" -ForegroundColor Cyan
Write-Host ""

if (-not $HarFilePath) {
    Write-Host "Usage: .\Extract-LevelAutomationsFromHAR.ps1 -HarFilePath <path-to-har>" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To capture a HAR file:" -ForegroundColor Gray
    Write-Host "  1. Open Chrome DevTools (F12)" -ForegroundColor Gray
    Write-Host "  2. Go to Network tab" -ForegroundColor Gray
    Write-Host "  3. Visit your Level.io import URL" -ForegroundColor Gray
    Write-Host "  4. Right-click in Network list -> Save all as HAR" -ForegroundColor Gray
    exit 1
}

if (-not (Test-Path $HarFilePath)) {
    Write-Host "ERROR: HAR file not found: $HarFilePath" -ForegroundColor Red
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
Write-Host "Output directory: $OutputDir" -ForegroundColor Gray

# Load HAR file
Write-Host "Loading HAR file: $HarFilePath" -ForegroundColor Gray
$har = Get-Content $HarFilePath -Raw | ConvertFrom-Json

Write-Host "Searching for automation data in GraphQL responses..." -ForegroundColor Cyan
Write-Host ""

$automationsFound = 0
$scriptsFound = 0

# Track what we find
$allAutomations = @()
$allScripts = @()
$queryTypes = @{}

foreach ($entry in $har.log.entries) {
    # Check GraphQL requests
    if ($entry.request.url -match 'api.level.io/graphql') {

        # Log the operation name from request
        if ($entry.request.postData.text) {
            try {
                $reqJson = $entry.request.postData.text | ConvertFrom-Json
                $opName = $reqJson.operationName
                if ($opName) {
                    if (-not $queryTypes.ContainsKey($opName)) {
                        $queryTypes[$opName] = 0
                    }
                    $queryTypes[$opName]++
                }
            } catch {}
        }

        # Process response
        if ($entry.response.content.text) {
            $responseText = $entry.response.content.text

            # Decode if base64 encoded
            if ($entry.response.content.encoding -eq "base64") {
                try {
                    $responseText = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($responseText))
                } catch {
                    continue
                }
            }

            # Parse JSON
            try {
                $respJson = $responseText | ConvertFrom-Json
            } catch {
                continue
            }

            # Look for import/automation-related data
            # Check various possible paths where automation data might be

            # AllowedImport query
            if ($respJson.data.allowedImport) {
                $import = $respJson.data.allowedImport
                Write-Host "Found AllowedImport data!" -ForegroundColor Green
                Write-Host "  Name: $($import.name)" -ForegroundColor White

                $allAutomations += @{
                    source = "allowedImport"
                    data = $import
                }
                $automationsFound++
            }

            # Automation query
            if ($respJson.data.automation) {
                $auto = $respJson.data.automation
                Write-Host "Found Automation: $($auto.name)" -ForegroundColor Green

                $allAutomations += @{
                    source = "automation"
                    data = $auto
                }
                $automationsFound++
            }

            # AutomationSearch
            if ($respJson.data.automationSearch.nodes) {
                foreach ($node in $respJson.data.automationSearch.nodes) {
                    Write-Host "Found Automation (search): $($node.name)" -ForegroundColor Green
                    $allAutomations += @{
                        source = "automationSearch"
                        data = $node
                    }
                    $automationsFound++
                }
            }

            # ImportPreview or similar
            if ($respJson.data.importPreview) {
                $preview = $respJson.data.importPreview
                Write-Host "Found ImportPreview data!" -ForegroundColor Green

                $allAutomations += @{
                    source = "importPreview"
                    data = $preview
                }
                $automationsFound++
            }

            # Scripts embedded in automation
            if ($respJson.data.allowedImport.scripts) {
                foreach ($script in $respJson.data.allowedImport.scripts) {
                    Write-Host "  Script: $($script.name)" -ForegroundColor Cyan
                    $allScripts += $script
                    $scriptsFound++
                }
            }

            # Workflow data
            if ($respJson.data.workflow) {
                Write-Host "Found Workflow: $($respJson.data.workflow.name)" -ForegroundColor Green
                $allAutomations += @{
                    source = "workflow"
                    data = $respJson.data.workflow
                }
                $automationsFound++
            }
        }
    }
}

Write-Host ""
Write-Host "=== GraphQL Operations Found ===" -ForegroundColor Cyan
foreach ($op in $queryTypes.Keys | Sort-Object) {
    Write-Host "  $op : $($queryTypes[$op]) calls" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "Automations found: $automationsFound" -ForegroundColor $(if ($automationsFound -gt 0) { "Green" } else { "Yellow" })
Write-Host "Scripts found: $scriptsFound" -ForegroundColor $(if ($scriptsFound -gt 0) { "Green" } else { "Yellow" })

# Save raw extracted data
if ($allAutomations.Count -gt 0 -or $allScripts.Count -gt 0) {
    $outputFile = Join-Path $OutputDir "extracted_data.json"

    $exportData = @{
        extractedAt = (Get-Date).ToString("o")
        harFile = $HarFilePath
        automations = $allAutomations
        scripts = $allScripts
        queryTypes = $queryTypes
    }

    $exportData | ConvertTo-Json -Depth 20 | Out-File $outputFile -Encoding UTF8
    Write-Host ""
    Write-Host "Raw data saved to: $outputFile" -ForegroundColor Green
}

# If nothing found, dump all response structures for analysis
if ($automationsFound -eq 0) {
    Write-Host ""
    Write-Host "No automation data found. Dumping response structures for analysis..." -ForegroundColor Yellow

    $analysisFile = Join-Path $OutputDir "response_analysis.txt"
    $analysis = @()

    foreach ($entry in $har.log.entries) {
        if ($entry.request.url -match 'api.level.io/graphql' -and $entry.response.content.text) {
            $responseText = $entry.response.content.text

            if ($entry.response.content.encoding -eq "base64") {
                try {
                    $responseText = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($responseText))
                } catch { continue }
            }

            try {
                $respJson = $responseText | ConvertFrom-Json

                # Get operation name from request
                $opName = "unknown"
                if ($entry.request.postData.text) {
                    try {
                        $reqJson = $entry.request.postData.text | ConvertFrom-Json
                        $opName = $reqJson.operationName
                    } catch {}
                }

                # Get top-level keys in data
                $dataKeys = @()
                if ($respJson.data) {
                    $respJson.data.PSObject.Properties | ForEach-Object {
                        $dataKeys += $_.Name
                    }
                }

                $analysis += "Operation: $opName"
                $analysis += "  Data keys: $($dataKeys -join ', ')"
                $analysis += ""
            } catch {}
        }
    }

    $analysis | Out-File $analysisFile -Encoding UTF8
    Write-Host "Response analysis saved to: $analysisFile" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Done." -ForegroundColor Cyan
