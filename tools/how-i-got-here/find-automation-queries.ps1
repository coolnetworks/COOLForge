# Check the scripts HAR for any automation-related queries
$harFiles = @(
    "E:\DLScripts\importautomation.level.io.har"
)

foreach ($harFile in $harFiles) {
    if (!(Test-Path $harFile)) { continue }

    Write-Host "=== Checking: $harFile ===" -ForegroundColor Cyan
    $har = Get-Content $harFile -Raw | ConvertFrom-Json

    foreach ($entry in $har.log.entries) {
        if ($entry.request.url -match 'api.level.io/graphql' -and $entry.request.postData.text) {
            $req = $entry.request.postData.text | ConvertFrom-Json
            $opName = $req.operationName

            # Skip ones we've already seen
            if ($opName -and $opName -notmatch 'OrganizationDetails|CurrentUserIP|SegmentIdentify|AlertCounts') {
                Write-Host ""
                Write-Host "Operation: $opName" -ForegroundColor Yellow

                # Show relevant query parts
                if ($req.query -match 'automation|Automation') {
                    Write-Host $req.query -ForegroundColor Gray
                }
            }
        }
    }
}
