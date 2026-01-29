# Export-LevelAutomations.ps1
# Exports all automations and scripts from Level.io via GraphQL API

param(
    [string]$Token,
    [string]$OutputDir = "E:\DLScripts\level-export"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Token cache file
$tokenCacheFile = Join-Path $OutputDir "jwt-token-cache.txt"

# Try to load cached token if not provided
if (-not $Token) {
    if (Test-Path $tokenCacheFile) {
        $cachedToken = Get-Content $tokenCacheFile -Raw
        if ($cachedToken -match '^eyJ') {
            Write-Host "Using cached JWT token from: $tokenCacheFile" -ForegroundColor Gray
            $Token = $cachedToken.Trim()
        }
    }
}

# If still no token, prompt for it
if (-not $Token) {
    Write-Host "To get your JWT token:" -ForegroundColor Yellow
    Write-Host "  1. Log into app.level.io in your browser"
    Write-Host "  2. Open DevTools (F12) > Network tab"
    Write-Host "  3. Click anything in Level.io to trigger a request"
    Write-Host "  4. Click any 'graphql' request in the list"
    Write-Host "  5. Go to Headers > Request Headers > Authorization"
    Write-Host "  6. Copy the value (starts with 'eyJ...')"
    Write-Host ""
    $Token = Read-Host "Enter your Level.io JWT token"

    if (-not $Token) {
        Write-Host "ERROR: JWT token is required" -ForegroundColor Red
        exit 1
    }
}

# Validate token format
if ($Token -notmatch '^eyJ') {
    Write-Host "WARNING: Token doesn't look like a JWT (should start with 'eyJ')" -ForegroundColor Yellow
    $continue = Read-Host "Continue anyway? (y/n)"
    if ($continue -ne 'y') { exit 1 }
}

# Cache the token for next time
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
$Token | Out-File $tokenCacheFile -Encoding UTF8 -NoNewline
Write-Host "Token cached to: $tokenCacheFile" -ForegroundColor Gray

# Use script-scoped token so it can be refreshed
$script:CurrentToken = $Token

function Request-NewToken {
    Write-Host ""
    Write-Host "TOKEN EXPIRED or INVALID" -ForegroundColor Red
    Write-Host "To get a new JWT token:" -ForegroundColor Yellow
    Write-Host "  1. Log into app.level.io in your browser"
    Write-Host "  2. Open DevTools (F12) > Network tab"
    Write-Host "  3. Click anything in Level.io to trigger a request"
    Write-Host "  4. Click any 'graphql' request in the list"
    Write-Host "  5. Go to Headers > Request Headers > Authorization"
    Write-Host "  6. Copy the value (starts with 'eyJ...')"
    Write-Host ""
    $newToken = Read-Host "Enter new JWT token (or 'q' to quit)"

    if ($newToken -eq 'q' -or [string]::IsNullOrWhiteSpace($newToken)) {
        Write-Host "Exiting..." -ForegroundColor Yellow
        exit 1
    }

    $script:CurrentToken = $newToken.Trim()

    # Cache the new token
    $script:CurrentToken | Out-File $tokenCacheFile -Encoding UTF8 -NoNewline
    Write-Host "New token cached." -ForegroundColor Green

    return $script:CurrentToken
}

function Invoke-LevelGraphQL {
    param(
        [string]$OperationName,
        [string]$Query,
        [hashtable]$Variables = @{},
        [int]$MaxRetries = 3
    )

    $body = @{
        operationName = $OperationName
        query = $Query
        variables = $Variables
    } | ConvertTo-Json -Depth 10 -Compress

    for ($retry = 0; $retry -lt $MaxRetries; $retry++) {
        $headers = @{
            "Authorization" = $script:CurrentToken
            "Content-Type" = "application/json"
            "Origin" = "https://app.level.io"
            "Referer" = "https://app.level.io/"
        }

        try {
            $response = Invoke-WebRequest -Uri "https://api.level.io/graphql" -Method POST -Headers $headers -Body $body -UseBasicParsing -TimeoutSec 60
            $json = $response.Content | ConvertFrom-Json

            if ($json.errors) {
                $errorMsg = $json.errors[0].message
                # Check for auth-related errors
                if ($errorMsg -match 'unauthorized|unauthenticated|expired|invalid token|jwt|auth' -or $json.errors[0].extensions.code -eq 'UNAUTHENTICATED') {
                    Write-Host "    Auth error: $errorMsg" -ForegroundColor Red
                    Request-NewToken
                    continue  # Retry with new token
                }
                throw "GraphQL Error: $errorMsg"
            }

            return $json.data
        } catch {
            $errText = $_.Exception.Message
            # Check for 401/403 HTTP errors
            if ($errText -match '401|403|Unauthorized|Forbidden') {
                Write-Host "    HTTP Auth error: $errText" -ForegroundColor Red
                Request-NewToken
                continue  # Retry with new token
            }

            if ($retry -lt $MaxRetries - 1) {
                Write-Host "    Retry $($retry + 1) of $MaxRetries..." -ForegroundColor Yellow
                Start-Sleep -Seconds (2 * ($retry + 1))
            } else {
                throw
            }
        }
    }
}

Write-Host "=== Level.io Exporter ===" -ForegroundColor Cyan
Write-Host ""

# Test connection
Write-Host "Testing connection..." -ForegroundColor Gray
$org = Invoke-LevelGraphQL -OperationName "OrganizationDetails" -Query "query OrganizationDetails { organization { id name } }"
Write-Host "Connected to: $($org.organization.name)" -ForegroundColor Green
Write-Host ""

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Export Tags
Write-Host "=== Exporting Tags ===" -ForegroundColor Cyan

$tagsQuery = @"
query TagsSearch {
  tagSearch {
    nodes {
      id
      name
      userStyle
    }
  }
}
"@

$tagsResult = Invoke-LevelGraphQL -OperationName "TagsSearch" -Query $tagsQuery
$allTags = $tagsResult.tagSearch.nodes
Write-Host "  Found $($allTags.Count) tags" -ForegroundColor Green

# Save tags
$tagsPath = Join-Path $OutputDir "tags.json"
$allTags | ConvertTo-Json -Depth 10 | Out-File $tagsPath -Encoding UTF8
Write-Host "  Saved to: $tagsPath" -ForegroundColor Gray

# Add delay before next section
$delay = Get-Random -Minimum 3 -Maximum 12
Write-Host "    Waiting $delay seconds..." -ForegroundColor DarkGray
Start-Sleep -Seconds $delay

# Export Custom Fields
Write-Host ""
Write-Host "=== Exporting Custom Fields ===" -ForegroundColor Cyan

$customFieldsQuery = @"
query CustomFields {
  customFields {
    id
    name
  }
}
"@

$cfResult = Invoke-LevelGraphQL -OperationName "CustomFields" -Query $customFieldsQuery
$allCustomFields = $cfResult.customFields
Write-Host "  Found $($allCustomFields.Count) custom fields" -ForegroundColor Green

# Save custom fields
$cfPath = Join-Path $OutputDir "custom-fields.json"
$allCustomFields | ConvertTo-Json -Depth 10 | Out-File $cfPath -Encoding UTF8
Write-Host "  Saved to: $cfPath" -ForegroundColor Gray

# Add delay before next section
$delay = Get-Random -Minimum 3 -Maximum 12
Write-Host "    Waiting $delay seconds..." -ForegroundColor DarkGray
Start-Sleep -Seconds $delay

# Export Scripts
Write-Host "=== Exporting Scripts ===" -ForegroundColor Cyan

$scriptQuery = @"
query ScriptsSearch(`$first: Int, `$after: String) {
  scriptSearch(first: `$first, after: `$after) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      id
      name
      description
      shell
      command
      timeout
      runAs
      group {
        id
        name
      }
      groupAncestry {
        id
        name
      }
    }
  }
}
"@

$allScripts = @()
$hasNext = $true
$cursor = $null
$page = 1

while ($hasNext) {
    Write-Host "  Fetching scripts page $page..." -ForegroundColor Gray

    $vars = @{ first = 50 }
    if ($cursor) { $vars.after = $cursor }

    $result = Invoke-LevelGraphQL -OperationName "ScriptsSearch" -Query $scriptQuery -Variables $vars

    $allScripts += $result.scriptSearch.nodes
    $hasNext = $result.scriptSearch.pageInfo.hasNextPage
    $cursor = $result.scriptSearch.pageInfo.endCursor
    $page++

    if ($hasNext) {
        $delay = Get-Random -Minimum 3 -Maximum 12
        Write-Host "    Waiting $delay seconds..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $delay
    }
}

Write-Host "  Found $($allScripts.Count) scripts" -ForegroundColor Green

# Save scripts
$scriptsDir = Join-Path $OutputDir "scripts"
if (-not (Test-Path $scriptsDir)) {
    New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null
}

foreach ($script in $allScripts) {
    # Build path from group ancestry
    $pathParts = @()
    if ($script.groupAncestry) {
        $reversed = $script.groupAncestry | Sort-Object { [array]::IndexOf($script.groupAncestry, $_) } -Descending
        foreach ($g in $reversed) {
            $safeName = $g.name -replace '[\\/:*?"<>|]', '_'
            $pathParts += $safeName
        }
    }

    $folderPath = if ($pathParts.Count -gt 0) {
        Join-Path $scriptsDir ($pathParts -join '\')
    } else {
        $scriptsDir
    }

    if (-not (Test-Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    }

    # Determine extension
    $ext = switch ($script.shell) {
        "POWERSHELL" { ".ps1" }
        "CMD" { ".cmd" }
        "BASH" { ".sh" }
        default { ".txt" }
    }

    $safeName = $script.name -replace '[\\/:*?"<>|]', '_'
    $filePath = Join-Path $folderPath "$safeName$ext"

    # Build file content with metadata header
    $header = @()
    if ($script.shell -eq "POWERSHELL") {
        $header += "<#"
        $header += "Script: $($script.name)"
        $header += "ID: $($script.id)"
        $header += "Shell: $($script.shell)"
        if ($script.timeout) { $header += "Timeout: $($script.timeout) seconds" }
        if ($script.runAs) { $header += "RunAs: $($script.runAs)" }
        if ($script.description) {
            $header += ""
            $header += "Description:"
            $script.description -split "`n" | ForEach-Object { $header += "  $_" }
        }
        $header += "#>"
        $header += ""
    }

    $content = ($header -join "`r`n") + $script.command
    [System.IO.File]::WriteAllText($filePath, $content, [System.Text.UTF8Encoding]::new($false))
}

Write-Host "  Saved to: $scriptsDir" -ForegroundColor Gray

# Export Automations
Write-Host ""
Write-Host "=== Exporting Automations ===" -ForegroundColor Cyan

# Fetch automations with pagination on the automations within each group
$automationsInGroupQuery = @"
query AutomationsInGroup(`$groupId: ID!, `$first: Int, `$after: String) {
  group(groupId: `$groupId) {
    ... on AutomationGroup {
      id
      name
      automations(first: `$first, after: `$after) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          id
          name
          enabled
        }
      }
    }
  }
}
"@

# First, get all automation groups
$groupsQuery = @"
query GroupsList {
  groups(type: AUTOMATION_GROUP) {
    nodes {
      id
      ... on AutomationGroup {
        name
        parentId
      }
    }
  }
}
"@

Write-Host "  Fetching automation groups..." -ForegroundColor Gray
$groupsResult = Invoke-LevelGraphQL -OperationName "GroupsList" -Query $groupsQuery
$allGroups = $groupsResult.groups.nodes
Write-Host "  Found $($allGroups.Count) groups" -ForegroundColor Gray

$allAutomationIds = @()
$groupNum = 0

foreach ($group in $allGroups) {
    $groupNum++
    Write-Host "  [$groupNum/$($allGroups.Count)] Fetching automations in: $($group.name)" -ForegroundColor Gray

    $hasNextPage = $true
    $cursor = $null
    $groupAutomationCount = 0

    while ($hasNextPage) {
        try {
            $vars = @{ groupId = $group.id; first = 100 }
            if ($cursor) { $vars.after = $cursor }

            $groupResult = Invoke-LevelGraphQL -OperationName "AutomationsInGroup" -Query $automationsInGroupQuery -Variables $vars

            if ($groupResult.group.automations -and $groupResult.group.automations.nodes) {
                foreach ($a in $groupResult.group.automations.nodes) {
                    # Check if already added (avoid duplicates)
                    if (-not ($allAutomationIds | Where-Object { $_.id -eq $a.id })) {
                        $allAutomationIds += @{
                            id = $a.id
                            name = $a.name
                            enabled = $a.enabled
                            groupName = $group.name
                        }
                        $groupAutomationCount++
                    }
                }

                $hasNextPage = $groupResult.group.automations.pageInfo.hasNextPage
                $cursor = $groupResult.group.automations.pageInfo.endCursor
            } else {
                $hasNextPage = $false
            }
        } catch {
            Write-Host "    Error fetching group: $($_.Exception.Message)" -ForegroundColor Red
            $hasNextPage = $false
        }

        if ($hasNextPage) {
            Start-Sleep -Milliseconds 500
        }
    }

    if ($groupAutomationCount -gt 0) {
        Write-Host "    Found $groupAutomationCount automations" -ForegroundColor DarkGray
    }

    # Small delay between group fetches
    if ($groupNum -lt $allGroups.Count) {
        $delay = Get-Random -Minimum 1 -Maximum 2
        Start-Sleep -Seconds $delay
    }
}

# Also fetch ungrouped/unassigned automations
Write-Host "  Fetching ungrouped automations..." -ForegroundColor Gray

$ungroupedQuery = @"
query UngroupedAutomations(`$first: Int, `$after: String) {
  automations(first: `$first, after: `$after, filter: { ungrouped: true }) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      id
      name
      enabled
    }
  }
}
"@

$hasNextPage = $true
$cursor = $null
$ungroupedCount = 0

while ($hasNextPage) {
    try {
        $vars = @{ first = 100 }
        if ($cursor) { $vars.after = $cursor }

        $ungroupedResult = Invoke-LevelGraphQL -OperationName "UngroupedAutomations" -Query $ungroupedQuery -Variables $vars

        if ($ungroupedResult.automations -and $ungroupedResult.automations.nodes) {
            foreach ($a in $ungroupedResult.automations.nodes) {
                if (-not ($allAutomationIds | Where-Object { $_.id -eq $a.id })) {
                    $allAutomationIds += @{
                        id = $a.id
                        name = $a.name
                        enabled = $a.enabled
                        groupName = "Ungrouped"
                    }
                    $ungroupedCount++
                }
            }

            $hasNextPage = $ungroupedResult.automations.pageInfo.hasNextPage
            $cursor = $ungroupedResult.automations.pageInfo.endCursor
        } else {
            $hasNextPage = $false
        }
    } catch {
        Write-Host "    Note: Could not fetch ungrouped automations (may not be supported): $($_.Exception.Message)" -ForegroundColor DarkGray
        $hasNextPage = $false
    }

    if ($hasNextPage) {
        Start-Sleep -Milliseconds 500
    }
}

if ($ungroupedCount -gt 0) {
    Write-Host "    Found $ungroupedCount ungrouped automations" -ForegroundColor DarkGray
}

Write-Host "  Found $($allAutomationIds.Count) automations total" -ForegroundColor Green

# Fetch full details for each automation
$automationDetailQuery = @"
query AutomationPage(`$automationId: ID!) {
  automation(automationId: `$automationId) {
    id
    name
    enabled
    archivedAt
    isScriptRun
    group {
      id
      name
    }
    groupAncestry {
      id
      name
    }
    triggers {
      id
      name
      nickname
      enabled
      triggerable {
        __typename
        ... on ScheduleTrigger {
          schedule {
            entries {
              __typename
              ... on DailyScheduleEntry { hour minute }
              ... on WeeklyScheduleEntry { hour minute weekday }
              ... on HourlyScheduleEntry { interval }
              ... on MonthlyScheduleEntry { instance hour minute weekday selectedWeekday }
              ... on OneTimeScheduleEntry { runAt }
            }
          }
        }
        ... on WebhookTrigger {
          url
          apiKey
          requiresAuth
        }
        ... on TagAppliedTrigger {
          tag { id name }
        }
        ... on TagRemovedTrigger {
          tag { id name }
        }
        ... on DeviceEntersGroupTrigger {
          groups { id name }
        }
        ... on DeviceLeavesGroupTrigger {
          groups { id name }
        }
        ... on DeviceMonitorTrigger {
          deviceMonitor {
            id
            name
            deviceMonitorPolicy { id name }
          }
        }
        ... on CustomFieldChangedTrigger {
          customField { id name }
        }
        ... on RunAutomationTrigger {
          originatingAutomation { id name }
        }
      }
      conditions {
        id
        strategy
        valueComparison
        ... on ValueCondition {
          values { value }
        }
        ... on TagCondition {
          values { id name }
        }
        ... on GroupCondition {
          values { id name }
        }
        ... on CustomFieldCondition {
          customField { id name }
          values { value }
        }
        ... on VariableCondition {
          variableDefinition { id name }
          values { value }
        }
      }
    }
    actions {
      id
      name
      enabled
      onFailure
      retries
      conditions {
        id
        strategy
        valueComparison
        ... on ValueCondition {
          values { value }
        }
        ... on TagCondition {
          values { id name }
        }
        ... on GroupCondition {
          values { id name }
        }
        ... on CustomFieldCondition {
          customField { id name }
          values { value }
        }
        ... on VariableCondition {
          variableDefinition { id name }
          values { value }
        }
        ... on StepStatusCondition {
          action { id name }
          values { value }
        }
      }
      actionable {
        __typename
        ... on RunScriptAction {
          script { id name }
        }
        ... on ShellAction {
          shell
          command
          timeout
          runAs
        }
        ... on InstallWingetPackagesAction {
          packages
        }
        ... on UninstallWingetPackagesAction {
          packages
        }
        ... on UpgradeWingetPackagesAction {
          packages
          excludedPackages
        }
        ... on HttpRequestAction {
          url
          httpMethod
          body
          headers
          contentType
        }
        ... on ApplyTagsAction {
          tags { id name }
        }
        ... on RemoveTagsAction {
          tags { id name }
        }
        ... on AssignToGroupAction {
          group { id name }
        }
        ... on RunAutomationAction {
          targetAutomation { id name }
        }
        ... on DownloadFileAction {
          destinationPath
          filename
          repositoryFile { id filename }
        }
        ... on DownloadFileFromURLAction {
          destinationPath
          filename
          url
        }
        ... on CreateAlertAction {
          name
          description
          severity
        }
        ... on SendEmailAction {
          subject
          emailBody: body
          emails
        }
        ... on SetCustomFieldAction {
          customField { id name }
        }
        ... on DelayAction {
          duration
        }
        ... on RestartAction {
          askForApproval
        }
        ... on ManageServiceAction {
          serviceName
          state
          boot
        }
        ... on StartProcessAction {
          path
          arguments
          timeout
        }
        ... on StopProcessAction {
          processName
        }
      }
    }
    variableDefinitions {
      id
      name
      defaultValue
    }
  }
}
"@

$automationsDir = Join-Path $OutputDir "automations"
if (-not (Test-Path $automationsDir)) {
    New-Item -ItemType Directory -Path $automationsDir -Force | Out-Null
}

$allAutomations = @()
$i = 0

foreach ($auto in $allAutomationIds) {
    $i++
    $pct = [math]::Round(($i / $allAutomationIds.Count) * 100)
    Write-Host "  [$i/$($allAutomationIds.Count)] ($pct%) Fetching: $($auto.name)" -ForegroundColor Gray

    try {
        $detail = Invoke-LevelGraphQL -OperationName "AutomationPage" -Query $automationDetailQuery -Variables @{ automationId = $auto.id }
        $allAutomations += $detail.automation

        # Save individual JSON
        $safeName = $auto.name -replace '[\\/:*?"<>|]', '_'
        $jsonPath = Join-Path $automationsDir "$safeName.json"
        $detail.automation | ConvertTo-Json -Depth 20 | Out-File $jsonPath -Encoding UTF8
        Write-Host "    Saved: $safeName.json" -ForegroundColor DarkGray
    } catch {
        Write-Host "    ERROR on automation $($auto.id): $($_.Exception.Message)" -ForegroundColor Red
        # Continue with next automation instead of stopping
    }

    # Rate limiting - reduced delay (1-3 seconds)
    if ($i -lt $allAutomationIds.Count) {
        $delay = Get-Random -Minimum 1 -Maximum 3
        Start-Sleep -Seconds $delay
    }
}

# Save combined export
$exportData = @{
    exportedAt = (Get-Date).ToString("o")
    organization = $org.organization.name
    tags = $allTags
    customFields = $allCustomFields
    scripts = $allScripts
    automations = $allAutomations
}

$exportPath = Join-Path $OutputDir "full-export.json"
$exportData | ConvertTo-Json -Depth 30 | Out-File $exportPath -Encoding UTF8

Write-Host ""
Write-Host "=== Export Complete ===" -ForegroundColor Green
Write-Host "Tags: $($allTags.Count)" -ForegroundColor White
Write-Host "Custom Fields: $($allCustomFields.Count)" -ForegroundColor White
Write-Host "Scripts: $($allScripts.Count)" -ForegroundColor White
Write-Host "Automations: $($allAutomations.Count)" -ForegroundColor White
Write-Host "Output: $OutputDir" -ForegroundColor White
