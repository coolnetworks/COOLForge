# Regenerate all launchers from the template
# Keeps the custom header (lines 1-7) and replaces the rest with template content

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$templatePath = 'E:\COOLForge\templates\Launcher_Template.ps1'
$launchersPath = 'E:\COOLForge\launchers'

# Read template content starting from line 7 (after the header block)
$templateLines = Get-Content $templatePath -Encoding UTF8
$templateBody = $templateLines[6..($templateLines.Count-1)] -join "`r`n"

# Get all launcher files
$launchers = Get-ChildItem $launchersPath -Filter '*.ps1'

foreach ($launcher in $launchers) {
    # Read launcher header (first 7 lines)
    $launcherLines = Get-Content $launcher.FullName -Encoding UTF8
    $launcherHeader = $launcherLines[0..6] -join "`r`n"

    # Combine header with new template body
    $newContent = $launcherHeader + "`r`n" + $templateBody

    # Write back with UTF-8 BOM for proper emoji handling
    [System.IO.File]::WriteAllText($launcher.FullName, $newContent, [System.Text.UTF8Encoding]::new($true))
    Write-Host "Updated: $($launcher.Name)"
}
Write-Host "Done - updated $($launchers.Count) launchers"
