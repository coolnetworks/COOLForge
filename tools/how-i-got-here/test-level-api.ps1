$token = "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImFsbGVuQGNvb2wubmV0LmF1IiwiZXhwIjoxNzY3MDcyMzUzfQ.sREVct73T1-69pJ2h1SWdjiPSM7niw8IleyzP1eGSnY"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$body = @{
    operationName = "OrganizationDetails"
    variables = @{}
    query = "query OrganizationDetails { organization { id name __typename } }"
} | ConvertTo-Json -Compress

# Try different auth formats
$authFormats = @(
    @{ Name = "Bearer"; Value = "Bearer $token" },
    @{ Name = "No prefix"; Value = $token },
    @{ Name = "Token prefix"; Value = "Token $token" }
)

foreach ($format in $authFormats) {
    Write-Host "=== Trying: $($format.Name) ===" -ForegroundColor Cyan

    $headers = @{
        "Authorization" = $format.Value
        "Content-Type" = "application/json"
        "Origin" = "https://app.level.io"
        "Referer" = "https://app.level.io/"
    }

    try {
        $response = Invoke-WebRequest -Uri "https://api.level.io/graphql" -Method POST -Headers $headers -Body $body -UseBasicParsing
        $json = $response.Content | ConvertFrom-Json
        if ($json.errors) {
            Write-Host "Auth error: $($json.errors[0].message)" -ForegroundColor Yellow
        } else {
            Write-Host "SUCCESS!" -ForegroundColor Green
            $json | ConvertTo-Json -Depth 5
            break
        }
    } catch {
        Write-Host "Request error: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
}
