$har = Get-Content 'E:\DLScripts\importautomation.level.io.har' -Raw | ConvertFrom-Json

foreach ($entry in $har.log.entries) {
    if ($entry.request.url -match 'api.level.io/graphql' -and $entry.request.postData.text) {
        $req = $entry.request.postData.text | ConvertFrom-Json
        if ($req.operationName -eq 'Import') {
            Write-Host '=== Import Mutation ===' -ForegroundColor Cyan
            Write-Host $req.query
            Write-Host ''
            Write-Host '=== Variables ===' -ForegroundColor Cyan
            $req.variables | ConvertTo-Json -Depth 10
            Write-Host ''

            if ($entry.response.content.text) {
                $resp = $entry.response.content.text
                if ($entry.response.content.encoding -eq 'base64') {
                    $resp = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($resp))
                }
                Write-Host '=== Response ===' -ForegroundColor Cyan
                $respJson = $resp | ConvertFrom-Json
                $respJson | ConvertTo-Json -Depth 10
            }
        }
    }
}
