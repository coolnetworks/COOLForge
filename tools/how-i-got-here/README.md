# Historical Scripts

These scripts were used during the development and discovery process for exporting Level.io data.
They are kept here for historical reference only.

## Scripts

| Script | Purpose |
|--------|---------|
| `decode-id.ps1` | Decode Level.io base64 GraphQL IDs |
| `Download-LevelScripts.ps1` | Early API-based script downloader |
| `Extract-LevelAutomationsFromHAR.ps1` | Extract automations from HAR file |
| `Extract-LevelScriptsFromHAR.ps1` | Extract scripts from HAR file |
| `find-automation-queries.ps1` | Find automation GraphQL queries in HAR |
| `get-allowedimport.ps1` | Test allowedImport query |
| `get-auth-headers.ps1` | Extract auth headers from HAR |
| `get-automation-page.ps1` | Test automation page query |
| `get-automation-search.ps1` | Test automation search query |
| `get-import-mutation.ps1` | Find import mutation in HAR |
| `test-automation-query.ps1` | Test automation queries |
| `test-level-api.ps1` | General Level.io API testing |
| `test-tags-query.ps1` | Test tags query |

## Note

The consolidated export script is now `Export-LevelAutomations.ps1` in the parent `tools` folder.
