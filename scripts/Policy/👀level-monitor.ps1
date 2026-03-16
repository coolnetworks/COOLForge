<#
.SYNOPSIS
    Level.io service monitoring and health check policy with automated reporting.

.DESCRIPTION
    Implements automated Level.io service monitoring with daily health checks and n8n webhook reporting.
    Installs scheduled task for continuous monitoring and provides full diagnostics when needed.

    POLICY FLOW:
    1. Check global control tags (device must have checkmark to be managed)
    2. Check monitoring-specific override tags (highest priority)
    3. Fall back to custom field policy (policy_level_monitor)
    4. Execute resolved action (install/remove monitoring, run diagnostics)

    GLOBAL CONTROL TAGS (standalone):
    - U+2705 = Device is managed (required to process)
    - U+274C = Device is excluded from management
    - Both = Device is globally pinned (no changes)

    MONITORING-SPECIFIC OVERRIDE TAGS (with "lm" suffix):
    - U+1F64F lm = Install monitoring if missing (transient)
    - U+1F6AB lm = Remove monitoring if present (transient)
    - U+1F4CC lm = Pin - no monitoring changes allowed (persistent)
    - U+1F504 lm = Run full diagnostics now (transient)
    - U+2705 lm  = Status: monitoring is active (set by script)

    CUSTOM FIELD POLICY (inherited Group->Device):
    - policy_level_monitor = "install" | "remove" | "pin" | "diagnostics" | ""

.NOTES
    Version:          2026.03.17.01
    Target Platform:  Level.io RMM (via Script Launcher)
    Exit Codes:       0 = Success | 1 = Alert (Failure)

    Level.io Variables Used (passed from Script Launcher):
    - $MspScratchFolder   : MSP-defined scratch folder for persistent storage
    - $DeviceHostname     : Device hostname from Level.io
    - $DeviceTags         : Comma-separated list of device tags
    - $LevelGroupPath     : Device group path in Level.io

    Custom Fields:
    - $policy_level_monitor          : Policy action (install/remove/pin/diagnostics)
    - $policy_level_monitor_webhook  : n8n webhook URL for status reporting
    - $policy_level_monitor_interval : Check interval in hours (default: 12)

    MONITORING FEATURES:
    - Daily Level.io service health checks
    - n8n webhook reporting every 12 hours
    - Full diagnostics on service failures
    - Scheduled task management
    - Log rotation and cleanup

    Copyright (c) COOLNETWORKS
    https://github.com/coolnetworks/COOLForge

.LINK
    https://github.com/coolnetworks/COOLForge
#>

# ============================================================
# SCRIPT INITIALIZATION
# ============================================================

$ErrorActionPreference = "Continue"
$ScriptVersion = "2026.03.17.01"
$ScriptName = "Level Monitor Policy"

# Level.io variables (passed from Script Launcher)
$Hostname = if ($DeviceHostname) { $DeviceHostname } else { $env:COMPUTERNAME }
$Tags = if ($DeviceTags) { $DeviceTags } else { "" }
$GroupPath = if ($LevelGroupPath) { $LevelGroupPath } else { "Unknown" }

# Policy custom fields
$PolicyAction = $policy_level_monitor
$WebhookUrl = $policy_level_monitor_webhook  
$CheckInterval = $policy_level_monitor_interval

# Defaults
if ([string]::IsNullOrWhiteSpace($CheckInterval) -or $CheckInterval -like "{{*}}") { $CheckInterval = "12" }
if ([string]::IsNullOrWhiteSpace($WebhookUrl) -or $WebhookUrl -like "{{*}}") { $WebhookUrl = "" }

# Paths
$MonitorDir = "C:\ProgramData\COOLNETWORKS\level-monitor"
$LogFile = Join-Path $MonitorDir "level-monitor.log"
$ConfigFile = Join-Path $MonitorDir "config.json"
$TaskName = "COOLNETWORKS Level Monitor"

# ============================================================
# LOGGING FUNCTIONS
# ============================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console
    Write-Host $logEntry
    
    # Write to log file
    try {
        if (-not (Test-Path (Split-Path $LogFile -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path $LogFile -Parent) -Force | Out-Null
        }
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        # Fail silently if we can't write to log
    }
}

function Write-LogSection {
    param([string]$Title)
    $separator = "=" * 60
    Write-Log $separator
    Write-Log "  $Title"
    Write-Log $separator
}

# ============================================================
# POLICY TAG PROCESSING
# ============================================================

function Get-PolicyAction {
    param([string]$Tags, [string]$DefaultPolicy)
    
    # Convert tags to array
    $tagArray = if ($Tags) { $Tags.Split(',').Trim() } else { @() }
    
    # Check global control tags first
    $hasManaged = $tagArray -contains "✅"      # U+2705
    $hasExcluded = $tagArray -contains "❌"     # U+274C
    
    if ($hasExcluded -and $hasManaged) {
        Write-Log "Device is globally pinned (both ✅ and ❌ tags present)" "WARN"
        return "pin"
    }
    elseif ($hasExcluded) {
        Write-Log "Device is excluded from management (❌ tag present)" "WARN"
        return "skip"
    }
    elseif (-not $hasManaged) {
        Write-Log "Device is not managed (✅ tag missing)" "WARN"  
        return "skip"
    }
    
    # Check monitoring-specific override tags (with "lm" suffix)
    $installTag = $tagArray | Where-Object { $_ -like "🙏*lm*" }     # U+1F64F
    $removeTag = $tagArray | Where-Object { $_ -like "🚫*lm*" }      # U+1F6AB  
    $pinTag = $tagArray | Where-Object { $_ -like "📌*lm*" }         # U+1F4CC
    $diagnosticsTag = $tagArray | Where-Object { $_ -like "🔄*lm*" } # U+1F504
    
    if ($pinTag) { return "pin" }
    if ($removeTag) { return "remove" }
    if ($installTag) { return "install" }
    if ($diagnosticsTag) { return "diagnostics" }
    
    # Fall back to custom field policy
    if (![string]::IsNullOrWhiteSpace($DefaultPolicy) -and $DefaultPolicy -notlike "{{*}}") {
        return $DefaultPolicy.ToLower()
    }
    
    # Default action
    return "install"
}

# ============================================================
# LEVEL.IO SERVICE FUNCTIONS  
# ============================================================

function Find-LevelAgent {
    $commonPaths = @(
        "${env:ProgramFiles}\Level\level.exe",
        "${env:ProgramFiles(x86)}\Level\level.exe", 
        "C:\ProgramData\Level\level.exe"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    # Search via service
    try {
        $service = Get-Service -Name "Level" -ErrorAction SilentlyContinue
        if ($service -and $service.Path) {
            $exePath = $service.Path.Trim('"')
            if (Test-Path $exePath) {
                return $exePath
            }
        }
    } catch {
        # Service not found
    }
    
    return $null
}

function Test-LevelService {
    try {
        $service = Get-Service -Name "Level" -ErrorAction SilentlyContinue
        if (-not $service) {
            return @{ Status = "NotFound"; Details = "Level service not found" }
        }
        
        $status = $service.Status
        $startType = $service.StartType
        
        return @{
            Status = $status
            StartType = $startType
            Details = "Service status: $status, StartType: $startType"
        }
    } catch {
        return @{ Status = "Error"; Details = "Failed to query service: $($_.Exception.Message)" }
    }
}

function Test-LevelConnectivity {
    $levelAgent = Find-LevelAgent
    if (-not $levelAgent) {
        return @{ Status = "Failed"; Details = "Level agent not found" }
    }
    
    try {
        $result = & $levelAgent --check 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -eq 0) {
            return @{ Status = "OK"; Details = "Level connectivity check passed"; Output = $result }
        } else {
            return @{ Status = "Failed"; Details = "Level connectivity check failed (exit $exitCode)"; Output = $result }
        }
    } catch {
        return @{ Status = "Error"; Details = "Failed to run level --check: $($_.Exception.Message)" }
    }
}

# ============================================================
# N8N WEBHOOK REPORTING
# ============================================================

function Send-StatusReport {
    param(
        [string]$WebhookUrl,
        [hashtable]$StatusData,
        [string]$ReportType = "health_check"
    )
    
    if ([string]::IsNullOrWhiteSpace($WebhookUrl)) {
        Write-Log "No webhook URL configured, skipping report" "WARN"
        return $false
    }
    
    try {
        # Build report payload
        $payload = @{
            timestamp = (Get-Date).ToString("o")
            hostname = $Hostname
            group_path = $GroupPath
            report_type = $ReportType
            script_version = $ScriptVersion
            status = $StatusData
        } | ConvertTo-Json -Depth 10
        
        Write-Log "Sending $ReportType report to n8n webhook..."
        
        # Send webhook request
        $response = Invoke-RestMethod -Uri $WebhookUrl -Method POST -Body $payload -ContentType "application/json" -TimeoutSec 30
        
        Write-Log "Webhook report sent successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-Log "Failed to send webhook report: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ============================================================
# SCHEDULED TASK MANAGEMENT
# ============================================================

function Install-MonitoringTask {
    try {
        Write-Log "Installing Level monitoring scheduled task..."
        
        # Create monitoring directory
        if (-not (Test-Path $MonitorDir)) {
            New-Item -ItemType Directory -Path $MonitorDir -Force | Out-Null
        }
        
        # Create config file
        $config = @{
            webhook_url = $WebhookUrl
            check_interval_hours = [int]$CheckInterval
            last_check = $null
            installed = (Get-Date).ToString("o")
            version = $ScriptVersion
        } | ConvertTo-Json
        
        Set-Content -Path $ConfigFile -Value $config -Force
        
        # Create monitoring script
        $monitorScript = @"
# Level Monitor Daily Check
`$ErrorActionPreference = "SilentlyContinue"
`$ConfigPath = "$ConfigFile"
`$LogPath = "$LogFile"

# Load config
try {
    `$config = Get-Content `$ConfigPath | ConvertFrom-Json
} catch {
    exit 1
}

# Quick health check
function Test-LevelHealth {
    `$service = Get-Service -Name "Level" -ErrorAction SilentlyContinue
    `$agent = @("$([string]::Join('", "', @(
        "`${env:ProgramFiles}\Level\level.exe",
        "`${env:ProgramFiles(x86)}\Level\level.exe", 
        "C:\ProgramData\Level\level.exe"
    )))") | Where-Object { Test-Path `$_ } | Select-Object -First 1
    
    `$status = @{
        service_found = `$service -ne `$null
        service_status = if (`$service) { `$service.Status } else { "NotFound" }
        agent_found = `$agent -ne `$null
        agent_path = `$agent
        check_time = (Get-Date).ToString("o")
    }
    
    # Quick connectivity test if agent found
    if (`$agent) {
        try {
            `$checkResult = & `$agent --check 2>`$null
            `$status.connectivity = if (`$LASTEXITCODE -eq 0) { "OK" } else { "Failed" }
        } catch {
            `$status.connectivity = "Error"
        }
    }
    
    return `$status
}

# Run check and report
`$healthStatus = Test-LevelHealth
`$needsAlert = `$healthStatus.service_status -ne "Running" -or `$healthStatus.connectivity -ne "OK"

# Send report if webhook configured
if (`$config.webhook_url) {
    `$payload = @{
        timestamp = (Get-Date).ToString("o")
        hostname = "$Hostname"
        group_path = "$GroupPath" 
        report_type = if (`$needsAlert) { "health_alert" } else { "health_check" }
        script_version = "$ScriptVersion"
        status = `$healthStatus
    } | ConvertTo-Json -Depth 10
    
    try {
        Invoke-RestMethod -Uri `$config.webhook_url -Method POST -Body `$payload -ContentType "application/json" -TimeoutSec 30 | Out-Null
    } catch {
        # Log error but don't fail
        Add-Content -Path `$LogPath -Value "[`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Webhook failed: `$(`$_.Exception.Message)" -ErrorAction SilentlyContinue
    }
}

# Update last check time
`$config.last_check = (Get-Date).ToString("o")
`$config | ConvertTo-Json | Set-Content -Path `$ConfigPath -Force

exit 0
"@
        
        $scriptPath = Join-Path $MonitorDir "monitor-task.ps1"
        Set-Content -Path $scriptPath -Value $monitorScript -Force
        
        # Create scheduled task
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -Daily -At "08:00" -RandomDelay (New-TimeSpan -Minutes 30)
        $trigger2 = New-ScheduledTaskTrigger -Daily -At "20:00" -RandomDelay (New-TimeSpan -Minutes 30)
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Remove existing task if present
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        } catch {
            # Task didn't exist
        }
        
        # Register new task
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($trigger, $trigger2) -Settings $settings -Principal $principal -Description "COOLNETWORKS Level.io service monitoring" | Out-Null
        
        Write-Log "Level monitoring task installed successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-Log "Failed to install monitoring task: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-MonitoringTask {
    try {
        Write-Log "Removing Level monitoring scheduled task..."
        
        # Unregister task
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        
        # Remove monitoring directory
        if (Test-Path $MonitorDir) {
            Remove-Item -Path $MonitorDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "Level monitoring task removed successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-Log "Failed to remove monitoring task: $($_.Exception.Message)" "ERROR" 
        return $false
    }
}

# ============================================================
# MAIN POLICY LOGIC
# ============================================================

Write-LogSection "$ScriptName v$ScriptVersion - $Hostname"
Write-Log "Device: $Hostname | Group: $GroupPath"
Write-Log "Tags: $Tags"
Write-Log "Policy: $PolicyAction | Webhook: $([string]::IsNullOrWhiteSpace($WebhookUrl) -eq $false)"

# Determine action
$action = Get-PolicyAction -Tags $Tags -DefaultPolicy $PolicyAction

Write-Log "Resolved action: $action"

# Execute action
switch ($action) {
    "skip" {
        Write-Log "Skipping Level monitoring (device not managed or excluded)"
        exit 0
    }
    
    "pin" {
        Write-Log "Level monitoring is pinned (no changes allowed)"
        exit 0
    }
    
    "install" {
        Write-Log "Installing/updating Level monitoring..."
        
        $success = Install-MonitoringTask
        if ($success) {
            # Run initial health check and report
            $serviceStatus = Test-LevelService
            $connectivityStatus = Test-LevelConnectivity
            
            $statusData = @{
                monitoring_installed = $true
                service = $serviceStatus
                connectivity = $connectivityStatus
                installation_time = (Get-Date).ToString("o")
            }
            
            Send-StatusReport -WebhookUrl $WebhookUrl -StatusData $statusData -ReportType "monitoring_installed"
            
            Write-Log "Level monitoring installed successfully" "SUCCESS"
            exit 0
        } else {
            Write-Log "Failed to install Level monitoring" "ERROR"
            exit 1
        }
    }
    
    "remove" {
        Write-Log "Removing Level monitoring..."
        
        $success = Remove-MonitoringTask
        if ($success) {
            Write-Log "Level monitoring removed successfully" "SUCCESS"
            exit 0
        } else {
            Write-Log "Failed to remove Level monitoring" "ERROR"
            exit 1
        }
    }
    
    "diagnostics" {
        Write-Log "Running full Level diagnostics..."
        Write-LogSection "FULL LEVEL.IO DIAGNOSTICS"
        
        # Run comprehensive diagnostics (based on original level-debug.ps1)
        $serviceStatus = Test-LevelService
        $connectivityStatus = Test-LevelConnectivity
        $agentPath = Find-LevelAgent
        
        Write-Log "Service Status: $($serviceStatus.Details)"
        Write-Log "Agent Path: $($agentPath ?? 'Not Found')"
        Write-Log "Connectivity: $($connectivityStatus.Details)"
        
        # Collect additional diagnostics
        $diagnostics = @{
            service = $serviceStatus
            connectivity = $connectivityStatus
            agent_path = $agentPath
            system_info = @{
                hostname = $Hostname
                group_path = $GroupPath
                os_version = [System.Environment]::OSVersion.ToString()
                powershell_version = $PSVersionTable.PSVersion.ToString()
            }
            diagnostic_time = (Get-Date).ToString("o")
        }
        
        # Check for common issues
        if ($serviceStatus.Status -ne "Running") {
            Write-Log "WARNING: Level service is not running!" "WARN"
            $diagnostics.issues = @("Service not running")
        }
        
        if ($connectivityStatus.Status -ne "OK") {
            Write-Log "WARNING: Level connectivity check failed!" "WARN"
            if (-not $diagnostics.issues) { $diagnostics.issues = @() }
            $diagnostics.issues += "Connectivity failed"
        }
        
        if (-not $agentPath) {
            Write-Log "ERROR: Level agent not found!" "ERROR"
            if (-not $diagnostics.issues) { $diagnostics.issues = @() }
            $diagnostics.issues += "Agent not found"
        }
        
        # Send diagnostic report
        Send-StatusReport -WebhookUrl $WebhookUrl -StatusData $diagnostics -ReportType "full_diagnostics"
        
        Write-Log "Full diagnostics completed"
        exit 0
    }
    
    default {
        Write-Log "Unknown action: $action" "ERROR"
        exit 1
    }
}