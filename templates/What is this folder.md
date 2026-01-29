# What is this folder?

This folder is the **COOLForge scratch folder** - a persistent storage location used by COOLForge automation scripts running on this device.

## Purpose

COOLForge scripts need a reliable place to store:
- **PowerShell library modules** (`COOLForge-Common.psm1`) - Downloaded once, reused by all scripts
- **MD5 checksums** (`MD5SUMS`) - Verifies library integrity and triggers updates
- **Lockfiles** (`*.lock`) - Prevents multiple instances of the same script running simultaneously
- **Logs and temporary files** - Script execution logs and working data

## How it works

When a COOLForge script runs via Level.io (or any RMM):
1. The launcher checks if the library exists in this folder
2. Downloads or updates the library if needed (using MD5 checksum verification)
3. Creates a lockfile to prevent concurrent executions
4. Runs the actual script with the library loaded
5. Cleans up the lockfile when finished

## Configuration

This folder location is defined by the `CoolForge_msp_scratch_folder` custom field in Level.io. The default location is `C:\ProgramData\COOLForge`.

## Safe to delete?

**No** - Deleting this folder will cause scripts to re-download the library on next run. Lockfiles and logs will be lost, which could allow duplicate script executions.

If you need to clear it:
- Scripts will automatically recreate necessary files
- Library will be re-downloaded (internet connection required)

## License

COOLForge is licensed under **AGPL-3.0 with commercial exception**.

- **MSP end-users**: Free to use under AGPL-3.0
- **Platform vendors**: Require commercial license

See [LICENSE](LICENSE) in this folder or the full license at [github.com/coolnetworks/COOLForge/blob/main/LICENSE](https://github.com/coolnetworks/COOLForge/blob/main/LICENSE)

## Learn more

**Repository:** [github.com/coolnetworks/COOLForge](https://github.com/coolnetworks/COOLForge)
**Documentation:** [github.com/coolnetworks/COOLForge/tree/main/docs](https://github.com/coolnetworks/COOLForge/tree/main/docs)
