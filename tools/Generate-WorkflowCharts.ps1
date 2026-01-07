<#
.SYNOPSIS
    Generates ASCII workflow charts from Level.io automation JSON files.

.DESCRIPTION
    Reads automation JSON files from the backups folder and generates
    ASCII flowchart diagrams showing triggers, conditions, and actions.

.PARAMETER InputDir
    Directory containing automation JSON files. Defaults to backups/Level/automations.

.PARAMETER OutputDir
    Directory to save generated workflow charts. Defaults to workflows/.

.NOTES
    Version: 2025.01.07.02
#>

param(
    [string]$InputDir = ".\backups\Level\automations",
    [string]$OutputDir = ".\workflows"
)

$ErrorActionPreference = "Stop"

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

function Format-Conditions {
    param($Conditions)
    if (-not $Conditions -or $Conditions.Count -eq 0) { return "" }

    $parts = @()
    foreach ($cond in $Conditions) {
        $strategy = $cond.strategy
        $comparison = switch ($cond.valueComparison) {
            "EQUAL" { "=" }
            "NOT_EQUAL" { "!=" }
            "CONTAINS" { "contains" }
            "NOT_CONTAINS" { "!contains" }
            default { $cond.valueComparison }
        }
        $values = ($cond.values | ForEach-Object {
            if ($_.name) { $_.name } else { $_.value }
        }) -join ", "

        switch ($strategy) {
            "PLATFORM" { $parts += "Platform $comparison $values" }
            "TAG" { $parts += "Tag $comparison $values" }
            "TYPE" { $parts += "Type $comparison $values" }
            "VARIABLE" {
                $varName = $cond.variableDefinition.name
                $parts += "`$$varName $comparison `"$values`""
            }
            "STEP_STATUS" {
                $actionName = $cond.action.name
                $parts += "[$actionName] $comparison $values"
            }
            "OPERATING_SYSTEM" { $parts += "OS $comparison $values" }
            default { $parts += "$strategy $comparison $values" }
        }
    }
    return $parts -join " AND "
}

function Get-ActionDescription {
    param($Action)

    $actionable = $Action.actionable
    $typename = $actionable.__typename

    switch ($typename) {
        "ShellAction" {
            $shell = $actionable.shell
            $cmd = $actionable.command
            if ($cmd.Length -gt 40) { $cmd = $cmd.Substring(0, 37) + "..." }
            return "$shell`: $cmd"
        }
        "InstallWindowsUpdatesAction" { return "Install Windows Updates" }
        "UpgradeWingetPackagesAction" { return "Upgrade Winget Packages" }
        "InstallWingetPackagesAction" {
            $pkgs = $actionable.packages -join ", "
            if ($pkgs.Length -gt 40) { $pkgs = $pkgs.Substring(0, 37) + "..." }
            return "Install: $pkgs"
        }
        "ApplyTagsAction" {
            $tags = ($actionable.tags | ForEach-Object { $_.name }) -join ", "
            return "Apply Tags: $tags"
        }
        "RemoveTagsAction" {
            $tags = ($actionable.tags | ForEach-Object { $_.name }) -join ", "
            return "Remove Tags: $tags"
        }
        "CreateAlertAction" {
            return "ALERT [$($actionable.severity)]: $($actionable.name)"
        }
        "RunScriptAction" {
            return "Run Script: $($actionable.script.name)"
        }
        "RunAutomationAction" {
            return "Run Automation: $($actionable.automation.name)"
        }
        "DelayAction" {
            $mins = [math]::Round($actionable.duration / 60, 1)
            return "Delay $mins min"
        }
        "RestartAction" { return "Restart Device" }
        "SendMessageAction" { return "Send Message" }
        "ExitAutomationAction" { return "EXIT AUTOMATION" }
        default { return $typename -replace 'Action$', '' }
    }
}

function Get-TriggerDescription {
    param($Trigger)

    $triggerable = $Trigger.triggerable
    $typename = $triggerable.__typename

    switch ($typename) {
        "ScheduleTrigger" {
            $entries = $triggerable.schedule.entries
            $schedules = @()
            foreach ($entry in $entries) {
                $type = $entry.__typename
                switch ($type) {
                    "WeeklyScheduleEntry" {
                        $day = $entry.weekday.Substring(0,3)
                        $hour = $entry.hour
                        $min = $entry.minute
                        $schedules += "$day @ $($hour):$($min.ToString('00'))"
                    }
                    "DailyScheduleEntry" {
                        $hour = $entry.hour
                        $min = $entry.minute
                        $schedules += "Daily @ $($hour):$($min.ToString('00'))"
                    }
                    default { $schedules += $type }
                }
            }
            return "SCHEDULE: $($schedules -join ', ')"
        }
        "TagAppliedTrigger" {
            return "TAG APPLIED: $($triggerable.tag.name)"
        }
        "TagRemovedTrigger" {
            return "TAG REMOVED: $($triggerable.tag.name)"
        }
        "RunAutomationTrigger" {
            return "CALLED FROM: $($triggerable.originatingAutomation.name)"
        }
        "ManualTrigger" { return "MANUAL RUN" }
        "DeviceOnlineTrigger" { return "DEVICE ONLINE" }
        "DeviceOfflineTrigger" { return "DEVICE OFFLINE" }
        default { return $typename -replace 'Trigger$', '' }
    }
}

function New-Box {
    param(
        [string]$Text,
        [string]$Style = "action"  # action, condition, trigger, terminal
    )

    $maxWidth = 60
    $lines = @()

    # Word wrap
    $words = $Text -split '\s+'
    $currentLine = ""
    foreach ($word in $words) {
        if (($currentLine + " " + $word).Length -gt ($maxWidth - 4)) {
            if ($currentLine) { $lines += $currentLine.Trim() }
            $currentLine = $word
        } else {
            $currentLine += " $word"
        }
    }
    if ($currentLine) { $lines += $currentLine.Trim() }

    $width = ($lines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $width = [Math]::Max($width, 10)
    $boxWidth = $width + 4

    $result = @()

    switch ($Style) {
        "trigger" {
            $result += "  /" + ("=" * $boxWidth) + "\"
            foreach ($line in $lines) {
                $padded = $line.PadRight($width)
                $result += " ||  $padded  ||"
            }
            $result += "  \" + ("=" * $boxWidth) + "/"
        }
        "condition" {
            $result += "  /" + ("-" * $boxWidth) + "\"
            foreach ($line in $lines) {
                $padded = $line.PadRight($width)
                $result += " <   $padded   >"
            }
            $result += "  \" + ("-" * $boxWidth) + "/"
        }
        "terminal" {
            $result += "  (( " + $Text.PadRight($width) + " ))"
        }
        default {  # action
            $result += "  +" + ("-" * $boxWidth) + "+"
            foreach ($line in $lines) {
                $padded = $line.PadRight($width)
                $result += "  |  $padded  |"
            }
            $result += "  +" + ("-" * $boxWidth) + "+"
        }
    }

    return $result
}

function ConvertTo-AsciiChart {
    param($Automation)

    $name = $Automation.name
    $enabled = if ($Automation.enabled) { "ENABLED" } else { "DISABLED" }
    $group = if ($Automation.group) { $Automation.group.name } else { "Ungrouped" }

    $lines = @()
    $lines += "=" * 70
    $lines += "  $name"
    $lines += "  Group: $group | Status: $enabled"
    $lines += "=" * 70
    $lines += ""

    # Triggers
    foreach ($trigger in $Automation.triggers) {
        $desc = Get-TriggerDescription $trigger
        $lines += New-Box -Text $desc -Style "trigger"

        if ($trigger.conditions -and $trigger.conditions.Count -gt 0) {
            $lines += "         |"
            $lines += "         v"
            $condText = "IF: " + (Format-Conditions $trigger.conditions)
            $lines += New-Box -Text $condText -Style "condition"
        }

        $lines += "         |"
        $lines += "         v"
    }

    # Actions
    $actionIdx = 0
    foreach ($action in $Automation.actions) {
        $actionIdx++
        $desc = Get-ActionDescription $action
        $enabledMark = if (-not $action.enabled) { " [DISABLED]" } else { "" }
        $retryMark = if ($action.retries -gt 0) { " (retry:$($action.retries))" } else { "" }

        # Action conditions
        if ($action.conditions -and $action.conditions.Count -gt 0) {
            $condText = "IF: " + (Format-Conditions $action.conditions)
            $lines += New-Box -Text $condText -Style "condition"
            $lines += "    |Yes            |No"
            $lines += "    v               |(skip)"
        }

        $lines += New-Box -Text "$desc$enabledMark$retryMark" -Style "action"

        if ($action.onFailure -eq "STOP") {
            $lines += "    |               |Fail"
            $lines += "    v               +---> (( STOP ))"
        } else {
            $lines += "         |"
            $lines += "         v"
        }
    }

    $lines += "  (( DONE ))"
    $lines += ""
    $lines += ""
    $lines += "-" * 70
    $lines += "LEGEND"
    $lines += "-" * 70
    $lines += ""
    $lines += "  /==========\"
    $lines += " ||  TEXT   ||   TRIGGER - Event that starts the automation"
    $lines += "  \==========/"
    $lines += ""
    $lines += "  /----------\"
    $lines += " <   TEXT    >   CONDITION - Decision point (IF statement)"
    $lines += "  \----------/"
    $lines += ""
    $lines += "  +----------+"
    $lines += "  |  TEXT    |   ACTION - Task to execute"
    $lines += "  +----------+"
    $lines += ""
    $lines += "  (( TEXT ))     TERMINAL - End state (DONE or STOP)"
    $lines += ""
    $lines += "  (retry:N)      Action will retry N times on failure"
    $lines += "  [DISABLED]     Action is disabled and will be skipped"
    $lines += ""
    $lines += "  Flow:"
    $lines += "    |            Normal flow downward"
    $lines += "    v"
    $lines += ""
    $lines += "    |Yes         Condition met - execute action"
    $lines += "    |No (skip)   Condition not met - skip action"
    $lines += ""
    $lines += "    |Fail        Action failed - stop automation"
    $lines += "    +---> (( STOP ))"
    $lines += ""

    return $lines -join "`n"
}

# Process all automation files
$automationFiles = Get-ChildItem -Path $InputDir -Filter "*.json" -ErrorAction SilentlyContinue

if (-not $automationFiles) {
    Write-Host "No automation files found in $InputDir" -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($automationFiles.Count) automation files" -ForegroundColor Cyan
Write-Host "Output directory: $OutputDir" -ForegroundColor Cyan
Write-Host ""

$generated = 0
foreach ($file in $automationFiles) {
    try {
        $automation = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json

        # Generate safe filename
        $safeName = $automation.name -replace '[\\/:*?"<>|]', '_'
        $safeName = $safeName -replace '\s+', '_'
        $outputFile = Join-Path $OutputDir "$safeName.txt"

        $chart = ConvertTo-AsciiChart $automation

        $chart | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "  Generated: $safeName.txt" -ForegroundColor Green
        $generated++
    }
    catch {
        Write-Host "  Failed: $($file.Name) - $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Generated $generated workflow charts in $OutputDir" -ForegroundColor Cyan
