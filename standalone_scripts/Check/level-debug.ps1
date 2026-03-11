# level-debug.ps1 - Level Agent Diagnostics (per Level.io published method)
# Logs everything to ./logs/<HOSTNAME>.log
# If agent is missing/broken, falls back to fresh install
# Run via: level-debug.cmd (auto-elevates to admin)
#
# Reference: https://docs.level.io/en/articles/10697896-offline-troubleshooting

$ErrorActionPreference = "Continue"
$hostname = $env:COMPUTERNAME
# Use $PSScriptRoot (reliable even under UAC elevation), fallback to invocation path, fallback to working dir
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot }
             elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
             else { Get-Location | Select-Object -ExpandProperty Path }

# If running from removable media (USB), copy scripts to permanent location
$permanentDir = "C:\ProgramData\COOLNETWORKS\tools\level-debug"
$myPath = if ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } elseif ($PSCommandPath) { $PSCommandPath } else { $null }
if ($myPath) {
    $myDrive = (Get-Item $myPath).PSDrive
    $driveInfo = Get-Volume -DriveLetter $myDrive.Name -ErrorAction SilentlyContinue
    if ($driveInfo -and $driveInfo.DriveType -eq 'Removable') {
        Write-Host "Running from USB - updating permanent copy at $permanentDir..."
        if (-not (Test-Path $permanentDir)) {
            New-Item -ItemType Directory -Path $permanentDir -Force | Out-Null
        }
        if (-not (Test-Path "$permanentDir\logs")) {
            New-Item -ItemType Directory -Path "$permanentDir\logs" -Force | Out-Null
        }
        Copy-Item $myPath -Destination "$permanentDir\level-debug.ps1" -Force
        $cmdPath = Join-Path $scriptDir "level-debug.cmd"
        if (Test-Path $cmdPath) {
            Copy-Item $cmdPath -Destination "$permanentDir\level-debug.cmd" -Force
        }
        Write-Host "Permanent copy updated."
    }
}

$logDir = Join-Path $scriptDir "logs"
$logFile = Join-Path $logDir "$hostname.log"

# Create logs directory
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

function Log {
    param([string]$msg)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line
    Add-Content -Path $logFile -Value $line
}

function LogSection {
    param([string]$title)
    $separator = "=" * 60
    Log $separator
    Log $title
    Log $separator
}

function RunAndLog {
    param([string]$description, [scriptblock]$command)
    Log ">>> $description"
    try {
        $output = & $command 2>&1 | Out-String
        Add-Content -Path $logFile -Value $output
        Write-Host $output
        return $output
    } catch {
        $err = $_.Exception.Message
        Log "ERROR: $err"
        return $null
    }
}

# Find Level agent executable
function Find-LevelAgent {
    $paths = @(
        "C:\Program Files\Level\level-windows-amd64.exe",
        "C:\Program Files\Level\level.exe",
        "C:\Program Files (x86)\Level\level-windows-amd64.exe",
        "C:\Program Files (x86)\Level\level.exe"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { return $p }
    }
    $found = Get-ChildItem -Path "C:\Program Files*" -Depth 2 -Filter "level*.exe" -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match "^level" } |
             Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

# ============================================================
LogSection "LEVEL AGENT DIAGNOSTICS - $hostname - $(Get-Date)"
LogSection "Reference: https://docs.level.io/en/articles/10697896-offline-troubleshooting"

# --- Step 1: Locate agent ---
LogSection "STEP 1: LOCATE LEVEL AGENT"
$agentExe = Find-LevelAgent
if ($agentExe) {
    Log "Found agent: $agentExe"
    RunAndLog "Agent file details" { Get-Item $agentExe | Format-List Name,FullName,Length,LastWriteTime }
} else {
    Log "WARNING: Level agent executable NOT FOUND"
}

# --- Step 2: Service status ---
LogSection "STEP 2: CHECK SERVICE STATUS"
RunAndLog "Level service status" { Get-Service -Name 'Level' -ErrorAction SilentlyContinue | Format-List * }
RunAndLog "Level services (wildcard)" { Get-Service | Where-Object { $_.Name -like '*level*' -or $_.DisplayName -like '*level*' } | Format-List Name,DisplayName,Status,StartType }
RunAndLog "Level processes" { Get-Process | Where-Object { $_.Name -like '*level*' } | Format-Table Name,Id,CPU,WorkingSet64,StartTime -AutoSize }

# --- Step 3: AV/EDR interference check (Level Step 1) ---
LogSection "STEP 3: CHECK AV/EDR INTERFERENCE (Level Docs Step 1)"
Log "Checking if AV/EDR may be blocking Level agent..."
RunAndLog "Windows Defender exclusions" { Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExclusionPath }
RunAndLog "Windows Defender threat detections (recent)" { Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.Resources -like '*level*' } | Format-List }
RunAndLog "Windows Defender threat history" { Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.Resources -like '*level*' } | Format-List }
# Check if Level paths are excluded
$levelDir = "C:\Program Files\Level"
$mpPrefs = Get-MpPreference -ErrorAction SilentlyContinue
if ($mpPrefs) {
    $excluded = $mpPrefs.ExclusionPath | Where-Object { $_ -like "*Level*" }
    if ($excluded) {
        Log "[OK] Level directory is in Defender exclusions: $excluded"
    } else {
        Log "[WARN] Level directory is NOT in Defender exclusions - may cause interference"
        Log "   Recommended: Add-MpPreference -ExclusionPath 'C:\Program Files\Level'"
    }
}

# --- Step 4: Firewall/network check (Level Step 2) ---
LogSection "STEP 4: CHECK FIREWALL AND NETWORK (Level Docs Step 2)"
Log "Testing connectivity to Level required endpoints..."

# Level required URLs per docs
$endpoints = @(
    @{ Host = "agents.level.io";    Port = 443;  Purpose = "Agent communication" },
    @{ Host = "online.level.io";    Port = 443;  Purpose = "Connectivity status checks" },
    @{ Host = "builds.level.io";    Port = 443;  Purpose = "Agent updates" },
    @{ Host = "downloads.level.io"; Port = 443;  Purpose = "Agent installation" },
    @{ Host = "realtime.ably.io";   Port = 443;  Purpose = "Real-time WebSocket" },
    @{ Host = "prd-level-storage.s3.wasabisys.com"; Port = 443; Purpose = "File storage repository" },
    @{ Host = "logs.logdna.com";    Port = 443;  Purpose = "Log aggregation" },
    @{ Host = "global.turn.twilio.com"; Port = 3478; Purpose = "TURN relay" },
    @{ Host = "global.turn.twilio.com"; Port = 5349; Purpose = "TURN TLS fallback" },
    @{ Host = "global.stun.twilio.com"; Port = 3478; Purpose = "STUN" }
)

foreach ($ep in $endpoints) {
    $epHost = $ep.Host
    $epPort = $ep.Port
    $epPurpose = $ep.Purpose
    Log "Testing: ${epHost}:${epPort} ($epPurpose)"
    try {
        $result = Test-NetConnection -ComputerName $epHost -Port $epPort -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        if ($result.TcpTestSucceeded) {
            Log "  [OK] ${epHost}:${epPort}"
        } else {
            Log "  [FAIL] ${epHost}:${epPort} - TCP connect failed"
        }
        $detail = $result | Format-List | Out-String
        Add-Content -Path $logFile -Value $detail
    } catch {
        Log "  [FAIL] ${epHost}:${epPort} - ERROR: $($_.Exception.Message)"
    }
}

# Check DNS resolution
Log ""
Log "DNS resolution checks:"
foreach ($ep in $endpoints) {
    try {
        $dns = Resolve-DnsName $ep.Host -ErrorAction SilentlyContinue
        $ips = ($dns | Where-Object { $_.QueryType -eq 'A' -or $_.QueryType -eq 'AAAA' } | ForEach-Object { $_.IPAddress }) -join ", "
        Log "  $($ep.Host) -> $ips"
    } catch {
        Log "  $($ep.Host) -> [FAIL] DNS FAILED"
    }
}

# Check Windows Firewall rules for Level
RunAndLog "Windows Firewall rules for Level" { Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*level*' -or $_.Name -like '*level*' } | Format-Table Name,DisplayName,Direction,Action,Enabled -AutoSize }

# --- Step 5: Run --check diagnostic (Level Step 3) ---
LogSection "STEP 5: RUN --check DIAGNOSTIC (Level Docs Step 3)"
if ($agentExe) {
    Log "Running Level agent --check command (this is Level's official diagnostic)..."
    RunAndLog "level --check (PRE-RESTART)" { & $agentExe --check }
} else {
    Log "SKIPPED - no agent executable found"
}

# --- Step 6: Collect agent logs ---
LogSection "STEP 6: COLLECT AGENT LOGS"
$levelLogPaths = @(
    "C:\Program Files\Level\logs",
    "C:\Program Files\Level\log",
    "C:\ProgramData\Level\logs",
    "C:\ProgramData\Level\log",
    "$env:LOCALAPPDATA\Level\logs"
)
$foundLogs = $false
foreach ($lp in $levelLogPaths) {
    if (Test-Path $lp) {
        Log "Found Level logs at: $lp"
        $foundLogs = $true
        RunAndLog "Level log files" { Get-ChildItem $lp -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 10 | Format-Table Name,Length,LastWriteTime -AutoSize }
        # Grab last 100 lines of most recent log
        $recentLog = Get-ChildItem $lp -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($recentLog) {
            Log "--- Last 100 lines of $($recentLog.Name) ---"
            $logContent = Get-Content $recentLog.FullName -Tail 100 -ErrorAction SilentlyContinue | Out-String
            Add-Content -Path $logFile -Value $logContent
            Write-Host $logContent
        }
    }
}
if (-not $foundLogs) {
    Log "No Level log directories found at standard paths"
}

# Event viewer logs
RunAndLog "Recent Level events (Application)" { Get-WinEvent -LogName Application -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like '*level*' -or $_.ProviderName -like '*level*' } | Format-Table TimeCreated,Id,LevelDisplayName,Message -Wrap }
RunAndLog "Recent Level events (System)" { Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like '*level*' -or $_.ProviderName -like '*level*' } | Format-Table TimeCreated,Id,LevelDisplayName,Message -Wrap }

# --- Step 7: Restart service ---
LogSection "STEP 7: RESTART LEVEL SERVICE"
RunAndLog "Stop Level service" { net stop level }
Start-Sleep -Seconds 3
RunAndLog "Start Level service" { net start level }
Start-Sleep -Seconds 10
RunAndLog "Service status after restart" { Get-Service -Name 'Level' -ErrorAction SilentlyContinue | Format-List Name,Status,StartType }
RunAndLog "Level processes after restart" { Get-Process | Where-Object { $_.Name -like '*level*' } | Format-Table Name,Id,CPU,WorkingSet64,StartTime -AutoSize }

# --- Step 8: Post-restart --check ---
LogSection "STEP 8: POST-RESTART --check DIAGNOSTIC"
Log "Waiting 30 seconds for agent to reconnect..."
Start-Sleep -Seconds 30
if ($agentExe) {
    RunAndLog "level --check (POST-RESTART)" { & $agentExe --check }
} else {
    Log "SKIPPED - no agent executable found"
}

# --- Step 9: Assessment ---
LogSection "STEP 9: ASSESSMENT"
$svc = Get-Service -Name 'Level' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Log "[OK] Level service is RUNNING"
    Log "Review --check output and logs above for connectivity issues"
} elseif (-not $agentExe) {
    Log "[FAIL] Level agent NOT INSTALLED - running installer"
    LogSection "STEP 10: FRESH INSTALL"
    Log "Downloading and installing Level agent..."
    try {
        $installArgs = "LEVEL_API_KEY=WrN1ihw2bXmuvCKBmqGvUBt4:20883"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "level.msi"
        Log "Downloading level.msi to $tempFile..."
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://downloads.level.io/level.msi" -OutFile $tempFile
        $ProgressPreference = 'Continue'
        Log "Download complete. Installing..."
        $proc = Start-Process msiexec.exe -Wait -ArgumentList "/i `"$tempFile`" $installArgs" -PassThru
        Log "Installer exit code: $($proc.ExitCode)"
        Start-Sleep -Seconds 10
        RunAndLog "Post-install service check" { Get-Service -Name 'Level' -ErrorAction SilentlyContinue | Format-List * }
        # Run --check after install
        $newExe = Find-LevelAgent
        if ($newExe) {
            RunAndLog "Post-install --check" { & $newExe --check }
        }
    } catch {
        Log "ERROR during install: $($_.Exception.Message)"
    }
} else {
    Log "[WARN] Level agent found but service NOT RUNNING after restart - reinstalling"
    LogSection "STEP 10: REINSTALL"
    try {
        $installArgs = "LEVEL_API_KEY=WrN1ihw2bXmuvCKBmqGvUBt4:20883"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "level.msi"
        Log "Downloading level.msi to $tempFile..."
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://downloads.level.io/level.msi" -OutFile $tempFile
        $ProgressPreference = 'Continue'
        Log "Download complete. Reinstalling..."
        $proc = Start-Process msiexec.exe -Wait -ArgumentList "/i `"$tempFile`" $installArgs /qn" -PassThru
        Log "Installer exit code: $($proc.ExitCode)"
        Start-Sleep -Seconds 10
        RunAndLog "Post-reinstall service check" { Get-Service -Name 'Level' -ErrorAction SilentlyContinue | Format-List * }
        $newExe = Find-LevelAgent
        if ($newExe) {
            RunAndLog "Post-reinstall --check" { & $newExe --check }
        }
    } catch {
        Log "ERROR during reinstall: $($_.Exception.Message)"
    }
}

# --- Collect support bundle (BEFORE email so we can attach it) ---
LogSection "STEP 11: BUILD LEVEL SUPPORT BUNDLE"
$bundleDir = Join-Path $logDir "$hostname-level-support"
$bundleZip = Join-Path $logDir "$hostname-level-support.zip"
try {
    if (Test-Path $bundleDir) { Remove-Item $bundleDir -Recurse -Force }
    New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null

    # Copy diagnostic log
    Copy-Item $logFile -Destination (Join-Path $bundleDir "diagnostic.log") -ErrorAction SilentlyContinue

    # Copy all Level agent logs
    $levelLogPaths2 = @(
        "C:\Program Files\Level\logs",
        "C:\Program Files\Level\log",
        "C:\ProgramData\Level\logs",
        "C:\ProgramData\Level\log"
    )
    $agentLogDir2 = Join-Path $bundleDir "agent-logs"
    New-Item -ItemType Directory -Path $agentLogDir2 -Force | Out-Null
    foreach ($lp in $levelLogPaths2) {
        if (Test-Path $lp) {
            Log "Collecting Level logs from $lp..."
            Get-ChildItem $lp -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item $_.FullName -Destination $agentLogDir2 -ErrorAction SilentlyContinue
            }
        }
    }

    # Collect Level agent config/state files
    $levelStateDir = Join-Path $bundleDir "agent-state"
    New-Item -ItemType Directory -Path $levelStateDir -Force | Out-Null
    $statePaths = @(
        "C:\Program Files\Level\level.conf",
        "C:\Program Files\Level\level.yaml",
        "C:\Program Files\Level\config.json",
        "C:\ProgramData\Level"
    )
    foreach ($sp in $statePaths) {
        if (Test-Path $sp) {
            if ((Get-Item $sp).PSIsContainer) {
                Get-ChildItem $sp -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in '.conf','.yaml','.json','.toml','.txt','.log' } |
                    ForEach-Object { Copy-Item $_.FullName -Destination $levelStateDir -ErrorAction SilentlyContinue }
            } else {
                Copy-Item $sp -Destination $levelStateDir -ErrorAction SilentlyContinue
            }
        }
    }

    # System info summary
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $sysInfo = "Hostname: $hostname`r`n"
    $sysInfo += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n"
    $sysInfo += "OS: $($osInfo.Caption) $($osInfo.Version)`r`n"
    $sysInfo += "Architecture: $env:PROCESSOR_ARCHITECTURE`r`n"
    $sysInfo += "Domain: $env:USERDOMAIN`r`n"
    $sysInfo += "Level Agent: $agentExe`r`n"
    $sysInfo += "Level Service: $((Get-Service -Name 'Level' -ErrorAction SilentlyContinue).Status)`r`n"
    $sysInfo | Out-File (Join-Path $bundleDir "system-info.txt") -Encoding UTF8

    # Export relevant Windows events
    Log "Exporting Windows event logs..."
    Get-WinEvent -LogName Application -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like '*level*' -or $_.ProviderName -like '*level*' } |
        Export-Csv (Join-Path $bundleDir "events-application.csv") -NoTypeInformation -ErrorAction SilentlyContinue
    Get-WinEvent -LogName System -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like '*level*' -or $_.ProviderName -like '*level*' } |
        Export-Csv (Join-Path $bundleDir "events-system.csv") -NoTypeInformation -ErrorAction SilentlyContinue

    # Zip it
    if (Test-Path $bundleZip) { Remove-Item $bundleZip -Force }
    Compress-Archive -Path "$bundleDir\*" -DestinationPath $bundleZip -Force
    Log "[OK] Support bundle created: $bundleZip"
    Log "   Send this zip to Level support if needed"

    # Clean up unzipped bundle dir
    Remove-Item $bundleDir -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    Log "[WARN] Support bundle creation failed: $($_.Exception.Message)"
}

# --- Email results + support bundle ---
LogSection "STEP 12: EMAIL LOG REPORT AND SUPPORT BUNDLE"
try {
    Log "Sending diagnostic report via email..."
    $dateStr = Get-Date -Format "yyyy-MM-dd"
    $subject = "$hostname - Debug logs $dateStr"
    $body = Get-Content $logFile -Raw -ErrorAction Stop
    $smtpServer = "123.136.49.11"
    $from = "level@adelaidemri.com"
    $to = "help@cool.net.au"

    # Copy log to temp file so Send-MailMessage doesn't lock the active log
    $tempLog = Join-Path $env:TEMP "$hostname-level-debug.log"
    Copy-Item $logFile -Destination $tempLog -Force -ErrorAction SilentlyContinue

    # Build attachment list - temp copy of log + support bundle if it exists
    $attachments = @($tempLog)
    $bundleZipPath = Join-Path $logDir "$hostname-level-support.zip"
    if (Test-Path $bundleZipPath) {
        $zipSize = (Get-Item $bundleZipPath).Length / 1MB
        if ($zipSize -lt 20) {
            $attachments += $bundleZipPath
            Log "Attaching support bundle ($([math]::Round($zipSize,1)) MB)"
        } else {
            Log "[WARN] Support bundle too large ($([math]::Round($zipSize,1)) MB) - skipping attachment"
            Log "   Bundle saved locally at: $bundleZipPath"
        }
    }

    try {
        Send-MailMessage -SmtpServer $smtpServer -Port 25 -From $from -To $to `
            -Subject $subject -Body $body -Attachments $attachments -ErrorAction Stop
        Log "[OK] Email sent to $to via $smtpServer - Subject: $subject"
    } catch {
        Log "[WARN] Primary SMTP ($smtpServer) failed: $($_.Exception.Message)"
        Log "Trying fallback SMTP 10.100.20.11..."
        Send-MailMessage -SmtpServer "10.100.20.11" -Port 25 -From $from -To $to `
            -Subject $subject -Body $body -Attachments $attachments -ErrorAction Stop
        Log "[OK] Email sent to $to via fallback 10.100.20.11 - Subject: $subject"
    }

    # Clean up temp log copy
    Remove-Item $tempLog -Force -ErrorAction SilentlyContinue
} catch {
    Log "[WARN] Email failed: $($_.Exception.Message)"
    Log "Log file still saved locally at: $logFile"
}

LogSection "DONE - Full log saved to $logFile"
