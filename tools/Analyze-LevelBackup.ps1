<#
.SYNOPSIS
    Analyzes Level.io backup and generates a summary of all automations.
.PARAMETER BackupFolder
    Path to the Level.io backup folder (e.g., backups/level2)
.PARAMETER OutputFile
    Path for the output summary file
#>

param(
    [string]$BackupFolder = "E:\COOLForge\backups\level2",
    [string]$OutputFile = "E:\COOLForge\backups\level2\AUTOMATION_SUMMARY.txt"
)

$automationsDir = Join-Path $BackupFolder "automations"
$tagsFile = Join-Path $BackupFolder "tags.json"
$scriptsDir = Join-Path $BackupFolder "scripts"

# Load tags for ID to name mapping
$tagMap = @{}
if (Test-Path $tagsFile) {
    $tags = Get-Content $tagsFile -Raw | ConvertFrom-Json
    foreach ($tag in $tags) {
        $tagMap[$tag.id] = $tag.name
    }
}

# Get all automation JSON files
$automationFiles = Get-ChildItem -Path $automationsDir -Filter "*.json" | Sort-Object Name

$output = @()
$output += "=" * 80
$output += "LEVEL.IO AUTOMATION SUMMARY"
$output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$output += "Total Automations: $($automationFiles.Count)"
$output += "=" * 80
$output += ""

foreach ($file in $automationFiles) {
    try {
        $auto = Get-Content $file.FullName -Raw | ConvertFrom-Json

        $output += "-" * 80
        $output += "AUTOMATION: $($auto.name)"
        $output += "-" * 80

        # Status
        $status = if ($auto.enabled) { "ENABLED" } else { "DISABLED" }
        if ($auto.archivedAt) { $status = "ARCHIVED" }
        $output += "Status: $status"

        # Group
        if ($auto.group) {
            $groupPath = if ($auto.groupAncestry) {
                ($auto.groupAncestry | ForEach-Object { $_.name }) -join " > "
            } else {
                $auto.group.name
            }
            $output += "Group: $groupPath"
        } else {
            $output += "Group: (Ungrouped)"
        }
        $output += ""

        # Triggers
        $output += "TRIGGERS:"
        if ($auto.triggers -and $auto.triggers.Count -gt 0) {
            foreach ($trigger in $auto.triggers) {
                $triggerType = $trigger.triggerable.__typename -replace 'Trigger$', ''
                $triggerInfo = "  - $triggerType"
                if ($trigger.nickname) { $triggerInfo += " [$($trigger.nickname)]" }

                # Extract trigger details
                switch ($trigger.triggerable.__typename) {
                    "ScheduleTrigger" {
                        if ($trigger.triggerable.schedule -and $trigger.triggerable.schedule.entries) {
                            foreach ($entry in $trigger.triggerable.schedule.entries) {
                                switch ($entry.__typename) {
                                    "DailyScheduleEntry" { $triggerInfo += " (Daily @ $($entry.hour):$($entry.minute.ToString('00')))" }
                                    "WeeklyScheduleEntry" { $triggerInfo += " ($($entry.weekday) @ $($entry.hour):$($entry.minute.ToString('00')))" }
                                    "HourlyScheduleEntry" { $triggerInfo += " (Every $($entry.interval) hours)" }
                                    "MonthlyScheduleEntry" { $triggerInfo += " (Monthly)" }
                                }
                            }
                        }
                    }
                    "TagAppliedTrigger" {
                        if ($trigger.triggerable.tag) {
                            $triggerInfo += ": $($trigger.triggerable.tag.name)"
                        }
                    }
                    "TagRemovedTrigger" {
                        if ($trigger.triggerable.tag) {
                            $triggerInfo += ": $($trigger.triggerable.tag.name)"
                        }
                    }
                    "DeviceEntersGroupTrigger" {
                        if ($trigger.triggerable.groups) {
                            $groupNames = ($trigger.triggerable.groups | ForEach-Object { $_.name }) -join ", "
                            $triggerInfo += ": $groupNames"
                        }
                    }
                    "DeviceLeavesGroupTrigger" {
                        if ($trigger.triggerable.groups) {
                            $groupNames = ($trigger.triggerable.groups | ForEach-Object { $_.name }) -join ", "
                            $triggerInfo += ": $groupNames"
                        }
                    }
                    "DeviceMonitorTrigger" {
                        if ($trigger.triggerable.deviceMonitor) {
                            $triggerInfo += ": $($trigger.triggerable.deviceMonitor.name)"
                        }
                    }
                    "RunAutomationTrigger" {
                        if ($trigger.triggerable.originatingAutomation) {
                            $triggerInfo += ": from '$($trigger.triggerable.originatingAutomation.name)'"
                        }
                    }
                    "WebhookTrigger" {
                        $triggerInfo += " (Webhook)"
                    }
                }

                # Add trigger conditions
                if ($trigger.conditions -and $trigger.conditions.Count -gt 0) {
                    foreach ($cond in $trigger.conditions) {
                        $condStr = "      IF "
                        switch ($cond.__typename) {
                            "TagCondition" {
                                $tagNames = ($cond.values | ForEach-Object { $_.name }) -join ", "
                                $condStr += "Tags $($cond.valueComparison) [$tagNames]"
                            }
                            "GroupCondition" {
                                $groupNames = ($cond.values | ForEach-Object { $_.name }) -join ", "
                                $condStr += "Group $($cond.valueComparison) [$groupNames]"
                            }
                            "ValueCondition" {
                                $values = ($cond.values | ForEach-Object { $_.value }) -join ", "
                                $condStr += "$($cond.strategy) $($cond.valueComparison) [$values]"
                            }
                            "CustomFieldCondition" {
                                if ($cond.customField) {
                                    $values = ($cond.values | ForEach-Object { $_.value }) -join ", "
                                    $condStr += "CustomField '$($cond.customField.name)' $($cond.valueComparison) [$values]"
                                }
                            }
                            default {
                                $condStr += "$($cond.__typename)"
                            }
                        }
                        $triggerInfo += "`n$condStr"
                    }
                }

                $output += $triggerInfo
            }
        } else {
            $output += "  (none)"
        }
        $output += ""

        # Actions - collect scripts and tags
        $scriptsUsed = @()
        $tagsApplied = @()
        $tagsRemoved = @()
        $automationsRun = @()
        $packagesInstalled = @()
        $packagesUninstalled = @()
        $alertsCreated = @()
        $shellCommands = @()
        $otherActions = @()

        $output += "ACTIONS:"
        if ($auto.actions -and $auto.actions.Count -gt 0) {
            foreach ($action in $auto.actions) {
                $actionType = $action.actionable.__typename -replace 'Action$', ''
                $actionInfo = "  - $actionType"
                if ($action.name) { $actionInfo += ": $($action.name)" }

                $disabled = if (-not $action.enabled) { " [DISABLED]" } else { "" }
                $retry = if ($action.retries -gt 0) { " (retry:$($action.retries))" } else { "" }

                switch ($action.actionable.__typename) {
                    "RunScriptAction" {
                        if ($action.actionable.script) {
                            $scriptName = $action.actionable.script.name
                            $actionInfo = "  - RunScript: $scriptName$disabled$retry"
                            $scriptsUsed += $scriptName
                        }
                    }
                    "ShellAction" {
                        $shell = $action.actionable.shell
                        $cmd = $action.actionable.command
                        if ($cmd.Length -gt 60) { $cmd = $cmd.Substring(0, 60) + "..." }
                        $actionInfo = "  - Shell ($shell): $cmd$disabled$retry"
                        $shellCommands += "$shell command"
                    }
                    "ApplyTagsAction" {
                        if ($action.actionable.tags) {
                            $tagNames = ($action.actionable.tags | ForEach-Object { $_.name }) -join ", "
                            $actionInfo = "  - ApplyTags: $tagNames$disabled"
                            $tagsApplied += $action.actionable.tags | ForEach-Object { $_.name }
                        }
                    }
                    "RemoveTagsAction" {
                        if ($action.actionable.tags) {
                            $tagNames = ($action.actionable.tags | ForEach-Object { $_.name }) -join ", "
                            $actionInfo = "  - RemoveTags: $tagNames$disabled"
                            $tagsRemoved += $action.actionable.tags | ForEach-Object { $_.name }
                        }
                    }
                    "RunAutomationAction" {
                        if ($action.actionable.targetAutomation) {
                            $targetName = $action.actionable.targetAutomation.name
                            $actionInfo = "  - RunAutomation: $targetName$disabled"
                            $automationsRun += $targetName
                        }
                    }
                    "InstallWingetPackagesAction" {
                        if ($action.actionable.packages) {
                            $pkgs = $action.actionable.packages -join ", "
                            $actionInfo = "  - InstallWinget: $pkgs$disabled$retry"
                            $packagesInstalled += $action.actionable.packages
                        }
                    }
                    "UninstallWingetPackagesAction" {
                        if ($action.actionable.packages) {
                            $pkgs = $action.actionable.packages -join ", "
                            $actionInfo = "  - UninstallWinget: $pkgs$disabled"
                            $packagesUninstalled += $action.actionable.packages
                        }
                    }
                    "UpgradeWingetPackagesAction" {
                        $actionInfo = "  - UpgradeWinget$disabled$retry"
                    }
                    "CreateAlertAction" {
                        $alertName = $action.actionable.name
                        $severity = $action.actionable.severity
                        $actionInfo = "  - CreateAlert [$severity]: $alertName$disabled"
                        $alertsCreated += "$alertName ($severity)"
                    }
                    "RestartAction" {
                        $actionInfo = "  - Restart$disabled"
                    }
                    "DelayAction" {
                        $actionInfo = "  - Delay: $($action.actionable.duration) seconds$disabled"
                    }
                    "DownloadFileAction" {
                        if ($action.actionable.repositoryFile) {
                            $actionInfo = "  - DownloadFile: $($action.actionable.repositoryFile.filename) -> $($action.actionable.destinationPath)$disabled"
                        }
                    }
                    "DownloadFileFromURLAction" {
                        $actionInfo = "  - DownloadFromURL: $($action.actionable.url)$disabled"
                    }
                    "SetCustomFieldAction" {
                        if ($action.actionable.customField) {
                            $actionInfo = "  - SetCustomField: $($action.actionable.customField.name)$disabled"
                        }
                    }
                    "AssignToGroupAction" {
                        if ($action.actionable.group) {
                            $actionInfo = "  - AssignToGroup: $($action.actionable.group.name)$disabled"
                        }
                    }
                    "SendEmailAction" {
                        $actionInfo = "  - SendEmail: $($action.actionable.subject)$disabled"
                    }
                    default {
                        $actionInfo = "  - $actionType$disabled$retry"
                        $otherActions += $actionType
                    }
                }

                # Add action conditions
                if ($action.conditions -and $action.conditions.Count -gt 0) {
                    $condStrs = @()
                    foreach ($cond in $action.conditions) {
                        switch ($cond.__typename) {
                            "TagCondition" {
                                $tagNames = ($cond.values | ForEach-Object { $_.name }) -join ", "
                                $condStrs += "Tags $($cond.valueComparison) [$tagNames]"
                            }
                            "StepStatusCondition" {
                                $values = ($cond.values | ForEach-Object { $_.value }) -join ", "
                                $stepName = if ($cond.action) { $cond.action.name } else { "prev" }
                                $condStrs += "Step '$stepName' $($cond.valueComparison) [$values]"
                            }
                            "VariableCondition" {
                                $varName = if ($cond.variableDefinition) { $cond.variableDefinition.name } else { "var" }
                                $values = ($cond.values | ForEach-Object { $_.value }) -join ", "
                                $condStrs += "Var '$varName' $($cond.valueComparison) [$values]"
                            }
                            default {
                                $condStrs += "$($cond.__typename)"
                            }
                        }
                    }
                    if ($condStrs.Count -gt 0) {
                        $actionInfo += " [IF: $($condStrs -join ' AND ')]"
                    }
                }

                $output += $actionInfo
            }
        } else {
            $output += "  (none)"
        }
        $output += ""

        # Summary section
        $output += "SUMMARY:"
        if ($scriptsUsed.Count -gt 0) {
            $output += "  Scripts: $($scriptsUsed -join ', ')"
        }
        if ($tagsApplied.Count -gt 0) {
            $output += "  Tags Applied: $($tagsApplied -join ', ')"
        }
        if ($tagsRemoved.Count -gt 0) {
            $output += "  Tags Removed: $($tagsRemoved -join ', ')"
        }
        if ($automationsRun.Count -gt 0) {
            $output += "  Runs Automations: $($automationsRun -join ', ')"
        }
        if ($packagesInstalled.Count -gt 0) {
            $output += "  Installs: $($packagesInstalled -join ', ')"
        }
        if ($packagesUninstalled.Count -gt 0) {
            $output += "  Uninstalls: $($packagesUninstalled -join ', ')"
        }
        if ($alertsCreated.Count -gt 0) {
            $output += "  Alerts: $($alertsCreated -join ', ')"
        }

        $output += ""
        $output += ""

    } catch {
        $output += "ERROR processing $($file.Name): $_"
        $output += ""
    }
}

# Write output
$output -join "`n" | Out-File -FilePath $OutputFile -Encoding UTF8

Write-Host "Summary generated: $OutputFile" -ForegroundColor Green
Write-Host "Processed $($automationFiles.Count) automations" -ForegroundColor Cyan
