# COOLForge TODO

## Launcher Refactoring

The following launchers could be refactored into a new `MSPSoftwarePolicy` folder structure:

- [ ] `launchers/👀unchecky.ps1` → `launchers/MSPSoftwarePolicy/👀unchecky.ps1`
- [ ] `launchers/👀dnsfilter.ps1` → `launchers/MSPSoftwarePolicy/👀dnsfilter.ps1`
- [ ] Corresponding check scripts in `scripts/Check/` → `scripts/MSPSoftwarePolicy/`

This would organize software policy scripts separately from other script types.
