<#
.SYNOPSIS
    Test script for ScreenConnect API integration with Level.io
.DESCRIPTION
    Tests both local ScreenConnect detection and server API connectivity.
    Run this script to validate your ScreenConnect setup before deploying
    the policy check script.

    Tests include:
    1. Configuration validation
    2. Local ScreenConnect detection (our instance vs rogues)
    3. Server API connectivity
    4. Machine search on server
    5. GUID comparison (local vs server)
    6. Session Groups enumeration
    7. DEBUG group testing

.NOTES
    Version: 2026.01.01.02

    Required Level.io Custom Fields:
    - cf_screenconnect_baseurl       : https://your-server.com
    - cf_screenconnect_instance_id   : Your instance ID (e.g., 983fa4f3c185dd21)
    - cf_screenconnect_api_user      : API username
    - cf_screenconnect_api_password  : API password

    Optional:
    - level_group_path               : Level.io group path for session group matching

    ScreenConnect Server Setup:
    1. Create API user with View Sessions permission only
    2. Create "DEBUG" session group with filter: CustomProperty1 LIKE '%DEBUG%'

.EXAMPLE
    # Run with parameters (for testing without Level.io)
    .\Test-ScreenConnectAPI.ps1 -BaseUrl "https://support.cool.net.au" -InstanceId "983fa4f3c185dd21" -ApiUser "level-api" -ApiPassword "secret"

.EXAMPLE
    # Run via Level.io (uses custom fields)
    .\Test-ScreenConnectAPI.ps1
#>

param(
    [string]$BaseUrl = "{{cf_screenconnect_baseurl}}",
    [string]$InstanceId = "{{cf_screenconnect_instance_id}}",
    [string]$ApiUser = "{{cf_screenconnect_api_user}}",
    [string]$ApiPassword = "{{cf_screenconnect_api_password}}",
    [string]$LevelGroupPath = "{{level_group_path}}",
    [string]$SessionGroup = "All Machines"
)

$ErrorActionPreference = 'Stop'

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )

    $status = if ($Passed) { "[PASS]" } else { "[FAIL]" }
    $color = if ($Passed) { "Green" } else { "Red" }

    Write-Host "$status " -ForegroundColor $color -NoNewline
    Write-Host $TestName
    if ($Details) {
        Write-Host "       $Details" -ForegroundColor Gray
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

# ============================================================
# TEST 1: CONFIGURATION CHECK
# ============================================================

Write-Section "TEST 1: Configuration"

$configValid = $true

# Check BaseUrl
if ($BaseUrl -match '^\{\{') {
    Write-TestResult "BaseUrl configured" $false "Still contains template variable"
    $configValid = $false
} elseif ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    Write-TestResult "BaseUrl configured" $false "Empty or null"
    $configValid = $false
} else {
    Write-TestResult "BaseUrl configured" $true $BaseUrl
}

# Check InstanceId
if ($InstanceId -match '^\{\{') {
    Write-TestResult "InstanceId configured" $false "Still contains template variable"
    $configValid = $false
} elseif ([string]::IsNullOrWhiteSpace($InstanceId)) {
    Write-TestResult "InstanceId configured" $false "Empty or null"
    $configValid = $false
} else {
    Write-TestResult "InstanceId configured" $true $InstanceId
}

# Check ApiUser
if ($ApiUser -match '^\{\{') {
    Write-TestResult "ApiUser configured" $false "Still contains template variable"
    $configValid = $false
} elseif ([string]::IsNullOrWhiteSpace($ApiUser)) {
    Write-TestResult "ApiUser configured" $false "Empty or null"
    $configValid = $false
} else {
    Write-TestResult "ApiUser configured" $true $ApiUser
}

# Check ApiPassword
if ($ApiPassword -match '^\{\{') {
    Write-TestResult "ApiPassword configured" $false "Still contains template variable"
    $configValid = $false
} elseif ([string]::IsNullOrWhiteSpace($ApiPassword)) {
    Write-TestResult "ApiPassword configured" $false "Empty or null"
    $configValid = $false
} else {
    Write-TestResult "ApiPassword configured" $true "(len=$($ApiPassword.Length))"
}

if (-not $configValid) {
    Write-Host ""
    Write-Host "Configuration incomplete. Please set the custom fields in Level.io or pass parameters directly:" -ForegroundColor Yellow
    Write-Host '  .\Test-ScreenConnectAPI.ps1 -BaseUrl "https://..." -InstanceId "..." -ApiUser "..." -ApiPassword "..."' -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# ============================================================
# TEST 2: LOCAL SCREENCONNECT DETECTION
# ============================================================

Write-Section "TEST 2: Local ScreenConnect Detection"

$localServices = @()
$ourInstance = $null
$rogueInstances = @()

try {
    $services = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like "*ScreenConnect Client*" }

    if ($services) {
        Write-TestResult "ScreenConnect services found" $true "Found $($services.Count) service(s)"

        foreach ($svc in $services) {
            $svcName = $svc.PSChildName
            $props = Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Services\$svcName" -ErrorAction SilentlyContinue
            $imagePath = $props.ImagePath

            # Extract GUID from ImagePath
            $guid = $null
            if ($imagePath -match '&s=([^&]+)') {
                $guid = $Matches[1]
            }

            # Extract host from ImagePath
            $scHost = $null
            if ($imagePath -match '&h=([^&]+)') {
                $scHost = $Matches[1]
            }

            $svcInfo = @{
                ServiceName = $svcName
                ImagePath = $imagePath
                GUID = $guid
                SCHost = $scHost
                IsOurs = $svcName -like "*$InstanceId*"
            }
            $localServices += $svcInfo

            if ($svcInfo.IsOurs) {
                $ourInstance = $svcInfo
                Write-TestResult "OUR instance found" $true $svcName
                Write-Host "       GUID: $guid" -ForegroundColor Gray
                Write-Host "       Host: $scHost" -ForegroundColor Gray
            } else {
                $rogueInstances += $svcInfo
                Write-TestResult "ROGUE instance detected" $false $svcName
            }
        }
    } else {
        Write-TestResult "ScreenConnect services found" $false "No ScreenConnect Client services in registry"
    }
} catch {
    Write-TestResult "Registry query" $false $_.Exception.Message
}

# Check service status if our instance exists
if ($ourInstance) {
    try {
        $svcStatus = Get-Service | Where-Object { $_.DisplayName -like "*$InstanceId*" } | Select-Object -First 1
        if ($svcStatus) {
            $running = $svcStatus.Status -eq 'Running'
            Write-TestResult "Service running" $running "Status: $($svcStatus.Status)"
        } else {
            Write-TestResult "Service status" $false "Could not query service"
        }
    } catch {
        Write-TestResult "Service status" $false $_.Exception.Message
    }
}

# ============================================================
# TEST 3: SERVER API CONNECTIVITY
# ============================================================

Write-Section "TEST 3: Server API Connectivity"

$encodedCredentials = [System.Convert]::ToBase64String(
    [System.Text.Encoding]::ASCII.GetBytes("${ApiUser}:${ApiPassword}")
)

$Headers = @{
    'authorization' = "Basic $encodedCredentials"
    'content-type' = "application/json; charset=utf-8"
    'origin' = $BaseUrl
}

# Create a session object to handle cookies across requests
$Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

# Test 3a: Basic server reachability and anti-forgery token extraction
Write-Host "3a. Fetching front page and extracting anti-forgery token..." -ForegroundColor Gray
$antiForgeryToken = $null
try {
    $FrontPage = Invoke-WebRequest -Uri $BaseUrl -Headers $Headers -WebSession $Session -UseBasicParsing -TimeoutSec 30
    Write-TestResult "Server reachable" $true $BaseUrl

    # Check login result from headers
    $loginResult = $FrontPage.Headers['X-Login-Result']
    if ($loginResult -and $loginResult -ne 'Success') {
        Write-Host "       X-Login-Result: $loginResult" -ForegroundColor Yellow
    }

    # Verify we got a session cookie (authentication worked)
    $setCookieHeader = $FrontPage.Headers['Set-Cookie']
    if ($setCookieHeader -and $setCookieHeader -like '*.ASPXAUTH=*') {
        Write-TestResult "Authentication" $true "Session cookie received"
    } elseif ($loginResult) {
        Write-TestResult "Authentication" $false "Login failed: $loginResult"
    }

    # Extract anti-forgery token from the page
    $Regex = [Regex]'(?<=antiForgeryToken":")(.*)(?=","isUserAdministrator)'
    $Match = $Regex.Match($FrontPage.Content)
    if ($Match.Success) {
        $antiForgeryToken = $Match.Value.ToString()
        $Headers['x-anti-forgery-token'] = $antiForgeryToken
        Write-TestResult "Anti-forgery token extracted" $true "Token: $($antiForgeryToken.Substring(0, [Math]::Min(20, $antiForgeryToken.Length)))..."
    } else {
        Write-TestResult "Anti-forgery token extracted" $false "Token not found in page"
        Write-Host "       The API may still work without this token on some versions" -ForegroundColor Yellow
    }
} catch {
    Write-TestResult "Server reachable" $false $_.Exception.Message
}

# Test 3b: Test GetHello endpoint (simplest API call)
Write-Host ""
Write-Host "3b. Testing GetHello endpoint..." -ForegroundColor Gray
$ApiUrl = "$BaseUrl/Services/PageService.ashx/GetHello"
$Body = "[]"
Write-Host "       URL: $ApiUrl" -ForegroundColor Gray

$HelloResponse = $null
try {
    # Use Invoke-WebRequest with session for cookie handling, then parse JSON
    $HelloResult = Invoke-WebRequest -Uri $ApiUrl -Method Post -Headers $Headers -Body $Body -WebSession $Session -UseBasicParsing -TimeoutSec 30
    $HelloResponse = $HelloResult.Content | ConvertFrom-Json
    Write-TestResult "GetHello" $true "Response: $HelloResponse"
} catch {
    $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
    Write-TestResult "GetHello" $false "$statusCode - $($_.Exception.Message)"

    # Try to read error response body
    if ($_.Exception.Response) {
        try {
            $errorStream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorStream)
            $errorBody = $reader.ReadToEnd()
            if ($errorBody) {
                Write-Host "       Error body: $($errorBody.Substring(0, [Math]::Min(200, $errorBody.Length)))" -ForegroundColor DarkYellow
            }
        } catch { }
    }

    if ($statusCode -eq 500 -and -not $antiForgeryToken) {
        Write-Host "       Anti-forgery token was not found - this is likely the cause" -ForegroundColor Yellow
    }
}

# Test 3c: Try GetLiveData endpoint (the CORRECT endpoint for sessions)
Write-Host ""
Write-Host "3c. Testing GetLiveData endpoint..." -ForegroundColor Gray

$sessionGroupsToTry = @("All Machines", "All Sessions")
$TestResponse = $null
$LiveDataSessions = $null

foreach ($groupName in $sessionGroupsToTry) {
    $ApiUrl = "$BaseUrl/Services/PageService.ashx/GetLiveData"

    # Body format from ConnectWiseControlAPI module (Get-CWCSession.ps1):
    # Array with: 1) Object containing HostSessionInfo + ActionCenterInfo, 2) The number 0
    $BodyObject = @(
        @{
            HostSessionInfo = @{
                sessionType = 2  # Access
                sessionGroupPathParts = @($groupName)
                filter = ""
                findSessionID = $null
                sessionLimit = 10
            }
            ActionCenterInfo = @{}
        },
        0
    )
    $Body = ConvertTo-Json $BodyObject -Depth 5

    Write-Host "       Trying group: '$groupName'" -ForegroundColor Gray
    Write-Host "       URL: $ApiUrl" -ForegroundColor Gray

    try {
        # Use Invoke-WebRequest with session for cookie handling
        $LiveDataResult = Invoke-WebRequest -Uri $ApiUrl -Method Post -Headers $Headers -Body $Body -WebSession $Session -UseBasicParsing -TimeoutSec 30
        $LiveDataResponse = $LiveDataResult.Content | ConvertFrom-Json

        # Extract sessions from ResponseInfoMap.HostSessionInfo.Sessions
        if ($LiveDataResponse.ResponseInfoMap -and $LiveDataResponse.ResponseInfoMap.HostSessionInfo) {
            $LiveDataSessions = $LiveDataResponse.ResponseInfoMap.HostSessionInfo.Sessions
            $TestResponse = $LiveDataSessions
            Write-TestResult "GetLiveData ('$groupName')" $true "Returned $($LiveDataSessions.Count) session(s)"

            if ($LiveDataSessions.Count -gt 0) {
                Write-Host "       Sample sessions:" -ForegroundColor Gray
                $LiveDataSessions | Select-Object -First 3 | ForEach-Object {
                    Write-Host "         - $($_.Name) ($($_.GuestMachineName))" -ForegroundColor Gray
                }
            }
            $SessionGroup = $groupName
            break
        } else {
            Write-TestResult "GetLiveData ('$groupName')" $false "Unexpected response format"
        }
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
        Write-TestResult "GetLiveData ('$groupName')" $false "$statusCode - $($_.Exception.Message)"

        # Try to read error response body
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                if ($errorBody) {
                    Write-Host "       Error body: $($errorBody.Substring(0, [Math]::Min(200, $errorBody.Length)))" -ForegroundColor DarkYellow
                }
            } catch { }
        }
    }
}

if (-not $TestResponse) {
    Write-Host ""
    Write-Host "       TROUBLESHOOTING:" -ForegroundColor Yellow
    Write-Host "       Ensure the API user has ViewSessionGroup permission" -ForegroundColor Yellow
    Write-Host "       Check Administration -> Security -> Roles" -ForegroundColor Yellow
}

# ============================================================
# TEST 4: SEARCH FOR THIS MACHINE
# ============================================================

Write-Section "TEST 4: Search for This Machine on Server"

$hostname = $env:COMPUTERNAME
$SearchResponse = $null

# Use GetLiveData with filter (same format as Get-CWCSession)
$ApiUrl = "$BaseUrl/Services/PageService.ashx/GetLiveData"
$BodyObject = @(
    @{
        HostSessionInfo = @{
            sessionType = 2  # Access
            sessionGroupPathParts = @($SessionGroup)
            filter = "GuestMachineName = '$hostname'"
            findSessionID = $null
            sessionLimit = 10
        }
        ActionCenterInfo = @{}
    },
    0
)
$Body = ConvertTo-Json $BodyObject -Depth 5

Write-Host "       URL: $ApiUrl" -ForegroundColor Gray
Write-Host "       Filter: GuestMachineName = '$hostname'" -ForegroundColor Gray

try {
    # Use Invoke-WebRequest with session for cookie handling
    $SearchResult = Invoke-WebRequest -Uri $ApiUrl -Method Post -Headers $Headers -Body $Body -WebSession $Session -UseBasicParsing -TimeoutSec 30
    $SearchLiveData = $SearchResult.Content | ConvertFrom-Json

    if ($SearchLiveData.ResponseInfoMap -and $SearchLiveData.ResponseInfoMap.HostSessionInfo) {
        $SearchResponse = $SearchLiveData.ResponseInfoMap.HostSessionInfo.Sessions

        if ($SearchResponse -and $SearchResponse.Count -gt 0) {
            Write-TestResult "Machine found on server" $true "Found $($SearchResponse.Count) matching session(s)"

            foreach ($session in $SearchResponse) {
                Write-Host ""
                Write-Host "       Session: $($session.Name)" -ForegroundColor Cyan
                Write-Host "       SessionID: $($session.SessionID)" -ForegroundColor Gray
                Write-Host "       GuestMachineName: $($session.GuestMachineName)" -ForegroundColor Gray
                Write-Host "       GuestOperatingSystemName: $($session.GuestOperatingSystemName)" -ForegroundColor Gray
                Write-Host "       GuestLoggedOnUserName: $($session.GuestLoggedOnUserName)" -ForegroundColor Gray
            }
        } else {
            Write-TestResult "Machine found on server" $false "No sessions matching '$hostname'"
            Write-Host "       This machine may not be registered with ScreenConnect" -ForegroundColor Yellow
        }
    } else {
        Write-TestResult "Machine found on server" $false "Unexpected response format"
    }
} catch {
    $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
    Write-TestResult "Search query" $false "$statusCode - $($_.Exception.Message)"
}

# ============================================================
# TEST 5: GUID COMPARISON
# ============================================================

Write-Section "TEST 5: GUID Comparison (Local vs Server)"

if ($ourInstance -and $ourInstance.GUID) {
    $localGuid = $ourInstance.GUID
    Write-Host "Local GUID: $localGuid" -ForegroundColor Gray

    if ($SearchResponse -and $SearchResponse.Count -gt 0) {
        $serverGuid = $SearchResponse[0].SessionID
        Write-Host "Server SessionID: $serverGuid" -ForegroundColor Gray

        $guidMatch = $localGuid -eq $serverGuid
        Write-TestResult "GUID match" $guidMatch $(if ($guidMatch) { "Local and server GUIDs match" } else { "MISMATCH - may need reinstall" })
    } else {
        Write-TestResult "GUID match" $false "No server session to compare"
    }
} else {
    Write-TestResult "GUID comparison" $false "No local GUID found"
}

# ============================================================
# TEST 6: SESSION GROUPS (from LiveData response)
# ============================================================

Write-Section "TEST 6: Session Groups"

# Session groups are typically available in the LiveData response
# For now, we'll just note that we retrieved sessions successfully
if ($TestResponse -and $TestResponse.Count -gt 0) {
    Write-TestResult "Sessions retrieved" $true "Got $($TestResponse.Count) session(s) from '$SessionGroup'"
} else {
    Write-TestResult "Sessions retrieved" $false "No sessions retrieved from API"
}

# ============================================================
# TEST 7: DEBUG SESSION GROUP
# ============================================================

Write-Section "TEST 7: DEBUG Session Group"

$debugGroupExists = $false
$debugGroupSessions = $null

# Check if DEBUG group exists
if ($AllSessionGroups) {
    $debugGroup = $AllSessionGroups | Where-Object { $_.Name -eq "DEBUG" }
    if ($debugGroup) {
        $debugGroupExists = $true
        Write-TestResult "DEBUG group exists" $true "Filter: $($debugGroup.SessionFilter)"

        # Query sessions in DEBUG group using GetLiveData
        try {
            $BodyObject = @(
                @{
                    HostSessionInfo = @{
                        sessionType = 2
                        sessionGroupPathParts = @("DEBUG")
                        filter = ""
                        findSessionID = $null
                        sessionLimit = 100
                    }
                    ActionCenterInfo = @{}
                },
                0
            )
            $Body = ConvertTo-Json $BodyObject -Depth 5
            $DebugResult = Invoke-WebRequest -Uri "$BaseUrl/Services/PageService.ashx/GetLiveData" `
                -Method Post -Headers $Headers -Body $Body -WebSession $Session -UseBasicParsing -TimeoutSec 30
            $DebugResponse = $DebugResult.Content | ConvertFrom-Json

            if ($DebugResponse.ResponseInfoMap -and $DebugResponse.ResponseInfoMap.HostSessionInfo) {
                $debugGroupSessions = $DebugResponse.ResponseInfoMap.HostSessionInfo.Sessions
            }

            if ($debugGroupSessions -and $debugGroupSessions.Count -gt 0) {
                Write-TestResult "DEBUG group has sessions" $true "Found $($debugGroupSessions.Count) session(s)"
                Write-Host ""
                Write-Host "       Sessions in DEBUG group:" -ForegroundColor Gray
                foreach ($session in $debugGroupSessions) {
                    Write-Host "         - $($session.GuestMachineName) ($($session.Name))" -ForegroundColor Gray
                }
            } else {
                Write-TestResult "DEBUG group has sessions" $false "No sessions in DEBUG group yet"
                Write-Host "       To add a machine to DEBUG group:" -ForegroundColor Yellow
                Write-Host "       1. Install ScreenConnect with company name containing 'DEBUG'" -ForegroundColor Yellow
                Write-Host "       2. Or modify the DEBUG group filter to match your test machines" -ForegroundColor Yellow
            }
        } catch {
            Write-TestResult "Query DEBUG group" $false $_.Exception.Message
        }
    } else {
        Write-TestResult "DEBUG group exists" $false "Not found"
        Write-Host ""
        Write-Host "       To create DEBUG session group in ScreenConnect:" -ForegroundColor Yellow
        Write-Host "       1. Go to Administration -> Session Groups" -ForegroundColor Yellow
        Write-Host "       2. Add new group named 'DEBUG'" -ForegroundColor Yellow
        Write-Host "       3. Set Session Type: Access" -ForegroundColor Yellow
        Write-Host "       4. Set Filter: CustomProperty1 LIKE '%DEBUG%'" -ForegroundColor Yellow
    }
}

# ============================================================
# TEST 8: LEVEL.IO GROUP PATH MAPPING
# ============================================================

Write-Section "TEST 8: Level.io Group Path Mapping"

if ($LevelGroupPath -match '^\{\{' -or [string]::IsNullOrWhiteSpace($LevelGroupPath)) {
    Write-TestResult "Level Group Path" $false "Not configured (template variable or empty)"
    Write-Host "       This is optional - used for automatic session group mapping" -ForegroundColor Gray
} else {
    Write-TestResult "Level Group Path" $true $LevelGroupPath

    # Transform to ScreenConnect format (spaces around slashes removed)
    $scGroupName = ($LevelGroupPath -replace "\s*/\s*", "/").Trim()
    $scCompanyFilter = ($LevelGroupPath -replace "\s*/\s*", " ").Trim()

    Write-Host "       Proposed ScreenConnect mapping:" -ForegroundColor Gray
    Write-Host "         Group Name: $scGroupName" -ForegroundColor Cyan
    Write-Host "         Filter: CustomProperty1 = '$scCompanyFilter'" -ForegroundColor Cyan

    # Check if matching group exists
    if ($AllSessionGroups) {
        $matchingGroup = $AllSessionGroups | Where-Object { $_.Name -eq $scGroupName -or $_.Name -eq $LevelGroupPath }
        if ($matchingGroup) {
            Write-TestResult "Matching session group exists" $true $matchingGroup.Name
        } else {
            Write-TestResult "Matching session group exists" $false "Would need to create: $scGroupName"
        }
    }
}

# ============================================================
# TEST 9: SESSION CUSTOM PROPERTIES
# ============================================================

Write-Section "TEST 9: Session Custom Properties"

if ($SearchResponse -and $SearchResponse.Count -gt 0) {
    $session = $SearchResponse[0]
    Write-Host "       Custom Properties for this machine ($($session.GuestMachineName)):" -ForegroundColor Gray

    for ($i = 1; $i -le 8; $i++) {
        $propName = "CustomProperty$i"
        $propValue = $session.$propName
        if ($propValue) {
            Write-Host "         CustomProperty$i : $propValue" -ForegroundColor Cyan
        } else {
            Write-Host "         CustomProperty$i : (empty)" -ForegroundColor DarkGray
        }
    }

    # Check if any custom property matches Level.io group path
    if (-not ($LevelGroupPath -match '^\{\{') -and -not [string]::IsNullOrWhiteSpace($LevelGroupPath)) {
        $scCompanyFilter = ($LevelGroupPath -replace "\s*/\s*", " ").Trim()
        $matchFound = $false
        for ($i = 1; $i -le 8; $i++) {
            $propValue = $session."CustomProperty$i"
            if ($propValue -and $propValue -like "*$scCompanyFilter*") {
                Write-TestResult "CustomProperty$i matches Level path" $true $propValue
                $matchFound = $true
            }
        }
        if (-not $matchFound) {
            Write-TestResult "Custom property matches Level path" $false "No property contains '$scCompanyFilter'"
            Write-Host "       The ScreenConnect client may have been installed with different company name" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "       (No session found to check custom properties)" -ForegroundColor Gray
}

# ============================================================
# SUMMARY
# ============================================================

Write-Section "SUMMARY"

$summary = [ordered]@{
    "Configuration" = $configValid
    "Local Instance Found" = ($null -ne $ourInstance)
    "Rogue Instances" = $rogueInstances.Count
    "Server API Working" = ($null -ne $TestResponse)
    "Machine on Server" = ($SearchResponse -and $SearchResponse.Count -gt 0)
    "Session Groups API" = ($null -ne $AllSessionGroups)
    "DEBUG Group Exists" = $debugGroupExists
}

foreach ($item in $summary.GetEnumerator()) {
    $value = $item.Value
    if ($item.Key -eq "Rogue Instances") {
        $passed = $value -eq 0
        Write-TestResult $item.Key $passed "$value found"
    } else {
        Write-TestResult $item.Key $value
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NEXT STEPS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if (-not $configValid) {
    Write-Host "1. Configure Level.io custom fields or pass parameters" -ForegroundColor Yellow
}
if (-not $debugGroupExists) {
    Write-Host "1. Create DEBUG session group in ScreenConnect" -ForegroundColor Yellow
}
if ($null -eq $ourInstance) {
    Write-Host "2. Install ScreenConnect client on this machine" -ForegroundColor Yellow
}
if (-not ($SearchResponse -and $SearchResponse.Count -gt 0)) {
    Write-Host "3. Register this machine with ScreenConnect server" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Test complete." -ForegroundColor Cyan

# Return structured result for automation
return @{
    ConfigValid = $configValid
    LocalInstance = $ourInstance
    RogueInstances = $rogueInstances
    ServerSessions = $SearchResponse
    ApiWorking = ($null -ne $TestResponse)
    SessionGroups = $AllSessionGroups
    DebugGroupExists = $debugGroupExists
    DebugGroupSessions = $debugGroupSessions
}
