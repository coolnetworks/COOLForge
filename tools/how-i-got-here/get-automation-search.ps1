$har = Get-Content 'E:\DLScripts\importautomation.level.io.har' -Raw | ConvertFrom-Json

foreach ($entry in $har.log.entries) {
    if ($entry.request.url -match 'api.level.io/graphql' -and $entry.request.postData.text) {
        $req = $entry.request.postData.text | ConvertFrom-Json
        if ($req.operationName -match 'Automation' -and $req.operationName -ne 'AutomationPage') {
            Write-Host "=== $($req.operationName) ===" -ForegroundColor Cyan
            Write-Host $req.query
            Write-Host ""
        }
    }
}
