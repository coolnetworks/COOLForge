#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Configure Windows power settings for workstation use

.DESCRIPTION
    Sets power management to:
    - AC Power: Never sleep
    - Battery Power: Normal sleep timeouts
    - Screensaver: 15 minutes (all power modes)

.NOTES
    Requires Administrator privileges
    Run with: powershell -ExecutionPolicy Bypass -File Configure-WorkstationPower.ps1
#>

#Requires -RunAsAdministrator

Write-Host "Configuring Windows Power Settings for Workstation..." -ForegroundColor Cyan

# Get the active power scheme GUID
$activeScheme = (powercfg /getactivescheme).Split()[3]
Write-Host "Active Power Scheme: $activeScheme" -ForegroundColor Yellow

# Power settings GUIDs
$SLEEP_GUID = "238c9fa8-0aad-41ed-83f4-97be242c8f20"  # Sleep after
$HIBERNATE_GUID = "9d7815a6-7ee4-497e-8888-515a05f02364"  # Hibernate after
$MONITOR_TIMEOUT_GUID = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"  # Turn off display after

Write-Host "`nConfiguring AC Power Settings (Plugged In)..." -ForegroundColor Green

# AC Power: Never sleep
Write-Host "  - Setting sleep to: Never" -ForegroundColor White
powercfg /change standby-timeout-ac 0

# AC Power: Never hibernate
Write-Host "  - Setting hibernate to: Never" -ForegroundColor White
powercfg /change hibernate-timeout-ac 0

# AC Power: Monitor off after 1 hour
Write-Host "  - Setting monitor timeout to: 60 minutes (1 hour)" -ForegroundColor White
powercfg /change monitor-timeout-ac 60

Write-Host "`nConfiguring Battery Power Settings..." -ForegroundColor Green

# Battery: Sleep after 15 minutes
Write-Host "  - Setting sleep to: 15 minutes" -ForegroundColor White
powercfg /change standby-timeout-dc 15

# Battery: Hibernate after 30 minutes
Write-Host "  - Setting hibernate to: 30 minutes" -ForegroundColor White
powercfg /change hibernate-timeout-dc 30

# Battery: Monitor off after 10 minutes
Write-Host "  - Setting monitor timeout to: 10 minutes" -ForegroundColor White
powercfg /change monitor-timeout-dc 10

Write-Host "`nConfiguring Screensaver..." -ForegroundColor Green

# Set screensaver timeout to 15 minutes (900 seconds)
$screensaverTimeout = 900

# Registry path for screensaver settings
$regPath = "HKCU:\Control Panel\Desktop"

# Enable screensaver
Write-Host "  - Setting screensaver timeout to: 15 minutes" -ForegroundColor White
Set-ItemProperty -Path $regPath -Name "ScreenSaveTimeOut" -Value $screensaverTimeout -Type String

# Enable screensaver active
Set-ItemProperty -Path $regPath -Name "ScreenSaveActive" -Value "1" -Type String

# Optional: Set screensaver to blank screen
# Set-ItemProperty -Path $regPath -Name "SCRNSAVE.EXE" -Value "scrnsave.scr" -Type String

# Optional: Enable password protection on wake from screensaver
# Set-ItemProperty -Path $regPath -Name "ScreenSaverIsSecure" -Value "1" -Type String

Write-Host "`nCurrent Power Configuration:" -ForegroundColor Cyan
powercfg /query $activeScheme

Write-Host "`n=== Configuration Complete ===" -ForegroundColor Green
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "  AC Power:    Never sleep, monitor off after 60min" -ForegroundColor White
Write-Host "  Battery:     Sleep after 15min, hibernate after 30min" -ForegroundColor White
Write-Host "  Screensaver: Active after 15 minutes" -ForegroundColor White
Write-Host "`nNote: Log out and back in for screensaver changes to take full effect." -ForegroundColor Cyan
