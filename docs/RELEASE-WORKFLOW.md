# Release Workflow

This document outlines the release process for COOLForge, including when to release on dev vs main, testing procedures, and rollback strategies.

## Branch Strategy

### Dev Branch (`dev`)
- **Purpose:** Development and testing branch
- **Stability:** Pre-release, may contain bugs
- **Audience:** Internal testing, select pilot devices
- **Tags:** Prefixed with `dev-` (e.g., `dev-2025.12.31`)

### Main Branch (`main`)
- **Purpose:** Production-ready stable releases
- **Stability:** Fully tested and verified
- **Audience:** All production devices
- **Tags:** Prefixed with `v` (e.g., `v2025.12.31`)

## Release Process

### 1. Development Work (on `dev` branch)

All development happens on the `dev` branch:

```powershell
# Ensure you're on dev branch
git checkout dev

# Make your changes
# ... edit files ...

# Run pre-release tools
.\pre-release\Test-Syntax.ps1
.\pre-release\Update-Launchers.ps1 -CheckCompleteness  # if template changed
.\pre-release\Update-MD5SUMS.ps1 -UseCache
.\pre-release\Validate-Release.ps1

# Commit changes
git add -A
git commit -m "Your commit message"
```

### 2. Create Dev Release

When ready to test new features:

```powershell
# Run full validation with auto-fix
.\pre-release\Validate-Release.ps1 -AutoFix

# Create dev release tag
.\pre-release\Validate-Release.ps1 -AutoFix -CreateTag

# Push to GitHub
git push origin dev
git push origin dev-YYYY.MM.DD
```

**Dev releases are created:**
- After significant feature additions
- When bugs are fixed and need testing
- Before promoting to main (pre-release testing)

### 3. Testing Period

**Minimum Testing Duration:** 48-72 hours (2-3 days)

**What to test:**
- Deploy to test devices using version pinning
- Run all affected scripts on test endpoints
- Monitor for errors in Level.io logs
- Verify new features work as expected
- Check for unintended side effects

**How to pin test devices:**
```
In Level.io:
1. Navigate to test device/group
2. Set custom field: CoolForge_pin_psmodule_to_version = dev-2025.12.31
3. Save
4. Run scripts on those devices
```

### 4. Rollback (if issues found)

If problems are discovered during testing:

**Option A: Fix Forward on Dev**
```powershell
# Fix the issue
# ... edit files ...

# Run pre-release tools
.\pre-release\Test-Syntax.ps1
.\pre-release\Update-MD5SUMS.ps1 -UseCache
.\pre-release\Validate-Release.ps1 -AutoFix -CreateTag

# Push new dev release
git push origin dev
git push origin dev-2025.12.31.1  # Incremented version
```

**Option B: Rollback Test Devices**
```
In Level.io:
1. Change version pin to previous stable: v2025.12.20
2. Or remove pin entirely to use main branch
```

**Option C: Delete Bad Tag (if not deployed)**
```powershell
# Delete local tag
git tag -d dev-2025.12.31

# Delete remote tag
git push origin :refs/tags/dev-2025.12.31
```

### 5. Promote to Main (Production Release)

After successful testing period (48-72 hours minimum):

```powershell
# Ensure dev is up to date
git checkout dev
git pull origin dev

# Merge dev to main
git checkout main
git pull origin main
git merge dev

# Run final validation on main
.\pre-release\Validate-Release.ps1 -AutoFix

# Create production release tag
.\pre-release\Validate-Release.ps1 -AutoFix -CreateTag

# Push to GitHub
git push origin main
git push origin vYYYY.MM.DD

# Return to dev branch for continued development
git checkout dev
```

**Criteria for promoting to main:**
- All tests passed on dev release
- No critical bugs reported
- Minimum 48-72 hour testing period completed
- All stakeholders notified
- Documentation updated if needed

### 6. Post-Release

**After main release:**
- Remove version pins from test devices (they'll auto-update to main)
- Monitor production devices for 24 hours
- Document any known issues in GitHub releases
- Update README or docs if features changed user-facing behavior

## Testing Checklist

Before promoting dev to main, verify:

- [ ] All scripts execute without errors on test devices
- [ ] No unexpected behavior or side effects
- [ ] Version pinning works correctly
- [ ] MD5 checksums verify correctly
- [ ] Library download and update works
- [ ] Launcher scripts work from Level.io
- [ ] No TODO comments in production scripts
- [ ] All launchers have matching scripts
- [ ] All scripts have emoji prefixes
- [ ] Documentation is up to date

## Version Pinning Reference

**Production (main branch):**
```
No pin set = always uses latest main branch
```

**Testing (dev branch):**
```
CoolForge_pin_psmodule_to_version = dev-2025.12.31
```

**Rollback to specific version:**
```
CoolForge_pin_psmodule_to_version = v2025.12.20
```

**Emergency rollback:**
```
Remove custom field entirely = reverts to main branch
```

## Emergency Procedures

### Critical Bug in Production

If a critical bug is discovered in main branch:

1. **Immediate:** Create hotfix branch from main
   ```powershell
   git checkout main
   git checkout -b hotfix-critical-bug
   ```

2. **Fix:** Make minimal changes to fix the issue
   ```powershell
   # Fix the bug
   .\pre-release\Validate-Release.ps1 -AutoFix
   ```

3. **Test:** Quick validation on test devices (1-4 hours max)

4. **Deploy:** Merge to main and create emergency release
   ```powershell
   git checkout main
   git merge hotfix-critical-bug
   .\pre-release\Validate-Release.ps1 -AutoFix -CreateTag
   git push origin main
   git push origin v2025.12.31.1
   ```

5. **Backport:** Merge hotfix to dev
   ```powershell
   git checkout dev
   git merge hotfix-critical-bug
   git push origin dev
   ```

### Failed Deployment

If main release causes widespread issues:

1. **Revert main to previous tag**
   ```powershell
   git checkout main
   git reset --hard v2025.12.20  # Previous stable version
   git push origin main --force  # ONLY in emergencies
   ```

2. **Notify all users** to clear pins if set

3. **Investigate** on dev branch

4. **Document** what went wrong

## Best Practices

1. **Never skip testing** - Always test on dev before main
2. **Keep commits small** - Easier to identify issues and rollback
3. **Tag everything** - Every release should be tagged
4. **Test incrementally** - Don't bundle too many changes in one release
5. **Monitor actively** - Watch test devices during testing period
6. **Document changes** - Update docs when behavior changes
7. **Communicate** - Let users know about major changes

## Release Cadence

**Recommended schedule:**
- **Dev releases:** As needed (daily/weekly for active development)
- **Main releases:** Weekly or bi-weekly after testing
- **Hotfixes:** Immediately when critical bugs found
- **Major features:** After extended testing (1-2 weeks on dev)

## Version Numbering

**Format:** `YYYY.MM.DD[.increment]`

**Examples:**
- `dev-2025.12.31` - First dev release of the day
- `dev-2025.12.31.1` - Second dev release (hotfix/update)
- `v2025.12.31` - Production release
- `v2025.12.31.1` - Production hotfix

**Increments** are used when multiple releases happen same day.

## Questions?

If you encounter issues not covered in this workflow, check:
- [Pre-Release Scripts README](../pre-release/README.md)
- [Why COOLForge?](WHY.md)
- [Private Fork Guide](PRIVATE-FORK.md)
