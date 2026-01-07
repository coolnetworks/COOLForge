# Download-LevelScripts.ps1
# Downloads all scripts from Level.io to local files
# Preserves folder structure, uses natural delays to avoid rate limiting

param(
    [string]$HarFilePath = "e:\allscriptsapp.level.io.har",

    [string]$OutputDir = "E:\DLScripts",

    [int]$MinDelaySeconds = 10,
    [int]$MaxDelaySeconds = 50,

    [string]$AuthToken = ""
)

$ErrorActionPreference = "Stop"

function Get-RandomDelay {
    return Get-Random -Minimum $MinDelaySeconds -Maximum $MaxDelaySeconds
}

function Get-SafeFileName {
    param([string]$Name)
    $invalid = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalid)
    return ($Name -replace $re, '_')
}

function Invoke-LevelGraphQL {
    param(
        [string]$Query,
        [hashtable]$Variables,
        [string]$OperationName,
        [hashtable]$Headers
    )

    $body = @{
        query = $Query
        variables = $Variables
        operationName = $OperationName
    } | ConvertTo-Json -Compress -Depth 10

    $response = Invoke-RestMethod -Uri "https://api.level.io/graphql" `
        -Method POST `
        -Headers $Headers `
        -Body $body `
        -ContentType "application/json"

    return $response
}

Write-Host "=== Level.io Script Downloader ===" -ForegroundColor Cyan
Write-Host ""

# Load HAR file
Write-Host "Loading HAR file: $HarFilePath" -ForegroundColor Gray
$har = Get-Content $HarFilePath -Raw | ConvertFrom-Json

# Extract headers from a successful GraphQL POST request
Write-Host "Extracting authentication headers..." -ForegroundColor Gray
$headers = @{
    "Content-Type" = "application/json"
    "Origin" = "https://app.level.io"
    "Referer" = "https://app.level.io/"
}

# Look for Authorization header in any request
foreach ($entry in $har.log.entries) {
    if ($entry.request.url -match 'api.level.io') {
        foreach ($h in $entry.request.headers) {
            if ($h.name -ieq 'authorization' -and $h.value) {
                $headers["Authorization"] = $h.value
                Write-Host "  Found Authorization header" -ForegroundColor Green
                break
            }
            if ($h.name -ieq 'cookie' -and $h.value) {
                $headers["Cookie"] = $h.value
                Write-Host "  Found Cookie header" -ForegroundColor Green
            }
        }
    }
    if ($headers.ContainsKey("Authorization")) { break }
}

# If no auth found in headers, use provided token or prompt
if (-not $headers.ContainsKey("Authorization") -and -not $headers.ContainsKey("Cookie")) {
    if ($AuthToken) {
        $headers["Authorization"] = $AuthToken
        Write-Host "  Using provided auth token" -ForegroundColor Green
    }
    else {
        Write-Host ""
        Write-Host "  No auth headers found in HAR file." -ForegroundColor Yellow
        Write-Host "  Level.io uses Clerk for authentication." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  To get a token:" -ForegroundColor Cyan
        Write-Host "  1. Open Level.io in browser with DevTools (F12)" -ForegroundColor White
        Write-Host "  2. Go to Application tab -> Local Storage -> https://app.level.io" -ForegroundColor White
        Write-Host "  3. Find a key starting with '__clerk_db_jwt' and copy its value" -ForegroundColor White
        Write-Host "  4. Run: .\Download-LevelScripts.ps1 -AuthToken 'Bearer YOUR_TOKEN'" -ForegroundColor White
        Write-Host ""
        Write-Host "  Or find it in Network tab:" -ForegroundColor Cyan
        Write-Host "  1. Reload Level.io with Network tab open" -ForegroundColor White
        Write-Host "  2. Filter by 'graphql'" -ForegroundColor White
        Write-Host "  3. Click a request -> Headers -> Request Headers" -ForegroundColor White
        Write-Host "  4. Copy the Authorization header value" -ForegroundColor White
        Write-Host ""
        exit 1
    }
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
Write-Host "Output directory: $OutputDir" -ForegroundColor Gray
Write-Host ""

# GraphQL Queries - exact format from Level.io
$ScriptsSearchQuery = @"
query ScriptsSearch(`$searchTerm: String, `$groupId: ID, `$newOnly: Boolean, `$first: Int, `$last: Int, `$before: String, `$after: String, `$sortBy: ScriptSortByEnum, `$sortDirection: SortDirectionEnum) {
  scriptSearch(
    searchTerm: `$searchTerm
    groupId: `$groupId
    newOnly: `$newOnly
    first: `$first
    last: `$last
    before: `$before
    after: `$after
    sortBy: `$sortBy
    sortDirection: `$sortDirection
  ) {
    edges {
      node {
        id
        ...ScriptListItem
        __typename
      }
      __typename
    }
    totalCount
    pageInfo {
      startCursor
      endCursor
      hasNextPage
      hasPreviousPage
      __typename
    }
    __typename
  }
}

fragment ScriptListItem on Script {
  id
  description
  createdAt
  ...ScriptCommon
  ...ScriptBreadcrumbs
  __typename
}

fragment ScriptCommon on Script {
  id
  name
  shell
  __typename
}

fragment ScriptBreadcrumbs on Script {
  id
  ...ScriptCommon
  group {
    id
    name
    __typename
  }
  groupAncestry {
    id
    parentId
    name
    __typename
  }
  __typename
}
"@

$ScriptPageQuery = @"
query ScriptPage(`$scriptId: ID!) {
  script(scriptId: `$scriptId) {
    ...ScriptPage
    __typename
  }
}

fragment ScriptPage on Script {
  id
  description
  createdAt
  updatedAt
  command
  timeout
  runAs
  allowedImport {
    id
    __typename
  }
  ...ScriptCommon
  ...ScriptBreadcrumbs
  variableDefinitions {
    id
    ...VariableDefinitionListItem
    __typename
  }
  __typename
}

fragment ScriptCommon on Script {
  id
  name
  shell
  __typename
}

fragment ScriptBreadcrumbs on Script {
  id
  ...ScriptCommon
  group {
    id
    name
    __typename
  }
  groupAncestry {
    id
    parentId
    name
    __typename
  }
  __typename
}

fragment VariableDefinitionListItem on VariableDefinition {
  id
  ...VariableDefinitionCommon
  defaultValue
  __typename
}

fragment VariableDefinitionCommon on VariableDefinition {
  id
  name
  reference
  __typename
}
"@

# Step 1: Get list of all scripts
Write-Host "Fetching script list from Level.io..." -ForegroundColor Cyan
$allScripts = @()
$hasNextPage = $true
$cursor = $null
$pageNum = 0

while ($hasNextPage) {
    $pageNum++
    Write-Host "  Fetching page $pageNum..." -ForegroundColor Gray

    $variables = @{
        first = 50
        sortBy = "NAME"
        sortDirection = "ASC"
    }
    if ($cursor) {
        $variables["after"] = $cursor
    }

    try {
        $result = Invoke-LevelGraphQL -Query $ScriptsSearchQuery -Variables $variables -OperationName "ScriptsSearch" -Headers $headers

        if ($result.data.scriptSearch.edges) {
            foreach ($edge in $result.data.scriptSearch.edges) {
                $allScripts += $edge.node
            }
        }

        $hasNextPage = $result.data.scriptSearch.pageInfo.hasNextPage
        $cursor = $result.data.scriptSearch.pageInfo.endCursor

        if ($hasNextPage) {
            $delay = Get-RandomDelay
            Write-Host "    Found $($result.data.scriptSearch.edges.Count) scripts, waiting ${delay}s..." -ForegroundColor Gray
            Start-Sleep -Seconds $delay
        }
    }
    catch {
        Write-Host "  ERROR fetching scripts: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  You may need to provide a valid Authorization token" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  To get a token:" -ForegroundColor Yellow
        Write-Host "  1. Open Level.io in browser with DevTools Network tab" -ForegroundColor Yellow
        Write-Host "  2. Look for GraphQL requests with Authorization header" -ForegroundColor Yellow
        Write-Host "  3. Copy the Bearer token value" -ForegroundColor Yellow
        exit 1
    }
}

Write-Host ""
Write-Host "Found $($allScripts.Count) scripts total" -ForegroundColor Green
Write-Host ""

# Step 2: Download each script
$downloaded = 0
$failed = 0

foreach ($script in $allScripts) {
    $scriptName = $script.name
    $scriptId = $script.id
    $shell = $script.shell

    # Build folder path from ancestry
    $folderPath = ""
    if ($script.groupAncestry) {
        # Ancestry is ordered from leaf to root, so reverse it
        $ancestry = $script.groupAncestry | Sort-Object {
            $idx = [array]::IndexOf($script.groupAncestry, $_)
            -$idx
        }
        $pathParts = @()
        foreach ($ancestor in $ancestry) {
            $safeName = Get-SafeFileName -Name $ancestor.name
            $pathParts += $safeName
        }
        $folderPath = $pathParts -join "\"
    }
    elseif ($script.group) {
        $folderPath = Get-SafeFileName -Name $script.group.name
    }

    $fullFolderPath = Join-Path $OutputDir $folderPath
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

    Write-Host "Downloading: $scriptName" -ForegroundColor White
    Write-Host "  -> $filePath" -ForegroundColor Gray

    try {
        $result = Invoke-LevelGraphQL -Query $ScriptPageQuery -Variables @{ scriptId = $scriptId } -OperationName "ScriptPage" -Headers $headers

        if ($result.data.script.command) {
            $content = $result.data.script.command

            # Add metadata as comments at the top
            $description = $result.data.script.description
            $timeout = $result.data.script.timeout
            $runAs = $result.data.script.runAs

            $header = @()
            if ($shell -eq "POWERSHELL") {
                $header += "<#"
                $header += "Script: $scriptName"
                $header += "Shell: $shell"
                $header += "Timeout: $timeout seconds"
                $header += "RunAs: $runAs"
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
                $header += "# Timeout: $timeout seconds"
                $header += "# RunAs: $runAs"
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
                $header += "REM Timeout: $timeout seconds"
                $header += "REM RunAs: $runAs"
                $header += ""
            }

            $fullContent = ($header -join "`r`n") + $content

            # Save with UTF-8 encoding
            [System.IO.File]::WriteAllText($filePath, $fullContent, [System.Text.UTF8Encoding]::new($false))

            $downloaded++
            Write-Host "  OK" -ForegroundColor Green
        }
        else {
            Write-Host "  SKIP (no content)" -ForegroundColor Yellow
            $failed++
        }
    }
    catch {
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }

    # Random delay between scripts
    $delay = Get-RandomDelay
    Write-Host "  Waiting ${delay}s..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $delay
}

Write-Host ""
Write-Host "=== Complete ===" -ForegroundColor Cyan
Write-Host "Downloaded: $downloaded" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Gray" })
Write-Host "Output: $OutputDir" -ForegroundColor Gray
