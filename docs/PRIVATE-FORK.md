# Using COOLForge with a Private Fork

This guide explains how to use COOLForge when you've forked the repository to a private GitHub repo.

---

## The Problem

GitHub's `raw.githubusercontent.com` URLs don't support authentication for private repositories. When you fork COOLForge to a private repo:

```
https://raw.githubusercontent.com/yourcompany/COOLForge/main/modules/COOLForge-Common.psm1
                                      ↑
                            Returns 404 if repo is private
```

---

## Solution Options

### Option 1: Keep Your Fork Public (Recommended)

**Easiest and most secure approach:**

1. Fork COOLForge to your GitHub account/organization
2. Keep the fork **public**
3. Set `CoolForge_ps_module_library_source` to your fork's URL:
   ```
   https://raw.githubusercontent.com/yourcompany/COOLForge/main/modules/COOLForge-Common.psm1
   ```

**Why this is safe:**
- Your scripts are just PowerShell code - no secrets
- Client-specific data lives in Level.io custom fields, not in the repo
- Your modifications are unlikely to be sensitive
- Follows open-source spirit of the project

**What to keep private:**
- Level.io API keys (store in Level.io, never in Git)
- Client custom field values (stored in Level.io)
- Endpoint credentials (use Level.io custom fields)

---

### Option 2: Use GitHub Personal Access Token

**For scenarios where the fork must be private:**

#### Method A: Separate PAT Custom Field (Recommended)

Store the PAT in a separate admin-only custom field for better security:

1. **Create a GitHub Personal Access Token (classic):**
   - Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Generate new token with `repo` scope
   - Copy the token (e.g., `ghp_abc123xyz...`)

2. **Create custom fields in Level.io:**

   **CoolForge_pat** (Global, Admin Only):
   ```
   Field Type: Text
   Scope: Global (organization-level)
   Visibility: Admin only
   Value: ghp_YOUR_TOKEN_HERE
   ```

   **CoolForge_ps_module_library_source** (Global or per-device):
   ```
   Field Type: Text
   Value: https://raw.githubusercontent.com/yourcompany/COOLForge/main/modules/COOLForge-Common.psm1
   ```

3. **The launcher automatically:**
   - Reads `{{cf_coolforge_pat}}` custom field
   - If present and URL doesn't already contain a token, injects it into GitHub URLs
   - Token never appears in logs or visible output
   - Pattern: `https://TOKEN@raw.githubusercontent.com/...`
   - Injection happens for library, scripts, and MD5SUMS downloads
   - Works with any GitHub repository URL (not just COOLForge)

**Security benefits:**
- ✅ Token stored in admin-only field (not visible to regular users)
- ✅ Token not embedded in URL field (can change repo URL without touching token)
- ✅ Token not visible in script logs or output
- ✅ Easier to rotate token (update one field, not multiple URLs)
- ✅ Can grant different tokens per organization/group if needed

#### Method B: Embed Token in URL (Legacy)

Alternatively, embed the token directly in the URL:

```
CoolForge_ps_module_library_source = https://ghp_YOUR_TOKEN@raw.githubusercontent.com/yourcompany/COOLForge/main/modules/COOLForge-Common.psm1
```

**Security considerations for Method B:**
- ⚠️ Token visible to anyone who can view custom fields
- ⚠️ Token visible in script logs
- ⚠️ Must update multiple fields if URL or token changes
- ⚠️ Token has access to ALL your private repos (limit scope if possible)
- ⚠️ Token expires and needs rotation

**Best practices for Method B:**
- Use a dedicated service account for the token
- Limit token scope to `repo` only
- Set token expiration and rotate regularly
- Document token location for future maintenance
- Consider who can view Level.io custom fields

**Recommendation:** Use Method A (separate PAT field) for better security and maintainability.

---

### Option 3: Self-Hosted Git Server or Web Server

**For air-gapped or highly restricted environments:**

1. Clone your fork to an internal web server or file share
2. Serve the files via:
   - Internal web server (IIS, nginx)
   - File share with UNC path
   - Local file:// paths

3. Set custom field to internal URL:
   ```
   CoolForge_ps_module_library_source = https://internal-git.company.com/COOLForge/main/modules/COOLForge-Common.psm1
   ```
   or
   ```
   CoolForge_ps_module_library_source = file://\\fileserver\share\COOLForge\modules\COOLForge-Common.psm1
   ```

**Use cases:**
- Air-gapped networks
- Compliance requirements (data residency)
- No internet access from endpoints

---

### Option 4: Use GitHub Codespaces or GitHub Actions

**For advanced users:**

Set up a GitHub Action that:
1. Runs on push to your private fork
2. Copies the library to a public gist or public repo
3. Endpoints pull from the public location

This maintains your private development while exposing only the compiled artifacts.

---

## Recommended Workflow for Forks

### Initial Setup

1. **Fork COOLForge** to your GitHub account
   ```bash
   # On GitHub: Fork coolnetworks/COOLForge
   git clone https://github.com/yourcompany/COOLForge.git
   cd COOLForge
   ```

2. **Keep fork public** (recommended) or private (if required)

3. **Set upstream remote** to track original repo:
   ```bash
   git remote add upstream https://github.com/coolnetworks/COOLForge.git
   ```

4. **Configure Level.io custom field**:
   ```
   CoolForge_ps_module_library_source = https://raw.githubusercontent.com/yourcompany/COOLForge/main/modules/COOLForge-Common.psm1
   ```

### Development Workflow

```bash
# Update from upstream
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/my-custom-script

# Make changes, commit, push
git add .
git commit -m "Add custom script for client X"
git push origin feature/my-custom-script

# Merge to main
git checkout main
git merge feature/my-custom-script
git push origin main
```

### Testing Changes

Use version pinning to test your fork's branches:

```powershell
# Test devices use your dev branch
CoolForge_pin_psmodule_to_version = dev
CoolForge_ps_module_library_source = https://raw.githubusercontent.com/yourcompany/COOLForge/dev/modules/COOLForge-Common.psm1

# Production uses your main branch
CoolForge_ps_module_library_source = https://raw.githubusercontent.com/yourcompany/COOLForge/main/modules/COOLForge-Common.psm1
```

---

## What to Customize in Your Fork

**Safe to customize:**
- Add your own scripts to `scripts/` folder
- Add company-specific templates
- Modify script categories/organization
- Add custom functions to the library (contribute back!)
- Create company-specific documentation

**Avoid customizing:**
- Core library functions (contribute improvements upstream)
- Launcher template (unless you know what you're doing)
- Version pinning logic
- Library auto-update mechanism

---

## Contributing Back

If you make improvements, consider contributing them back:

1. **Fork workflow:**
   ```bash
   git remote add upstream https://github.com/coolnetworks/COOLForge.git
   git fetch upstream
   git checkout -b feature/my-improvement upstream/main
   # Make changes
   git push origin feature/my-improvement
   ```

2. **Open pull request** on GitHub from your fork to `coolnetworks/COOLForge`

3. **Benefits:**
   - Your improvements get maintained by the community
   - Others benefit from your work
   - Easier to stay in sync with upstream

---

## Security Checklist

Before making your fork private, ask:

- [ ] Does the repo contain API keys? (They shouldn't - use custom fields)
- [ ] Does it contain client-specific data? (Use custom fields instead)
- [ ] Does it contain proprietary business logic? (Legitimate reason for private)
- [ ] Is it just scripts? (Consider keeping public)

**Remember:** Secrets belong in Level.io custom fields, NOT in Git repos.

---

## Troubleshooting

### Downloads fail with 404

**Problem:** Private repo, no authentication
**Solution:** Use Option 1 (public fork) or Option 2 (PAT token)

### Token expired

**Problem:** GitHub PAT expired
**Solution:** Generate new token, update custom field

### Cannot access from endpoints

**Problem:** Endpoints can't reach GitHub
**Solution:** Use Option 3 (internal hosting)

---

## See Also

- [Main README](../README.md)
- [Version Pinning](VERSION-PINNING.md)
- [Script Launcher Guide](LAUNCHER.md)
