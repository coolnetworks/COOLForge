# Emoji Handling

COOLForge_Lib includes special handling for UTF-8 emojis in script names, which can become corrupted during deployment.

---

## The Problem

When Level.io deploys PowerShell scripts, it may corrupt UTF-8 encoded emojis. For example, the stop sign emoji `⛔` (UTF-8 bytes: `E2 9B 94`) can become corrupted into different character sequences depending on how the script is processed.

**Common corruption patterns:**
- `⛔` → `Γ¢ö` or other garbled text
- `👀` → `≡ƒæÇ` or similar
- `🔧` → Various byte sequences

---

## The Solution

COOLForge_Lib provides two functions to handle this:

1. **`Repair-LevelEmoji`** — Detects known corruption patterns and repairs them to the correct Unicode characters
2. **`Get-LevelUrlEncoded`** — Properly URL-encodes strings with UTF-8 emojis for GitHub downloads

---

## How It Works

The Script Launcher automatically:
1. Loads the library from GitHub
2. Calls `Repair-LevelEmoji` on the script name to fix any corruption
3. Uses `Get-LevelUrlEncoded` to build the correct download URL
4. Downloads and executes the script

This means you can use emojis in script names without worrying about encoding issues.

---

## Supported Emojis

**Policy Tags** (used for software policy enforcement):
| Emoji | Name | Unicode | Policy Action |
|-------|------|---------|---------------|
| 🙏 | Folded hands | U+1F64F | Install |
| 🚫 | Prohibited | U+1F6AB | Remove |
| 📌 | Pushpin | U+1F4CC | Pin |
| 🔄 | Arrows | U+1F504 | Reinstall |
| ✅ | Check mark | U+2705 | Has (status) |

**Script Filename Prefixes** (visual identification):
| Emoji | Name | Unicode | Used For |
|-------|------|---------|----------|
| 👀 | Eyes | U+1F440 | Check/Policy scripts |
| ⛔ | No Entry | U+26D4 | Force Remove scripts |
| 🔧 | Wrench | U+1F527 | Fix scripts |

**Other Supported**:
| Emoji | Name | Unicode |
|-------|------|---------|
| 🚨 | Police light | U+1F6A8 |
| 🛑 | Stop sign octagon | U+1F6D1 |
| 🔚 | End arrow | U+1F51A |
| 🆕 | New button | U+1F195 |

> **Note:** `⛔` (U+26D4) is used for force-remove script filenames. For the Remove **policy tag**, use `🚫` (U+1F6AB).

---

## Adding New Emojis

To add support for additional emojis, update the `$EmojiRepairs` hashtable in the `Repair-LevelEmoji` function in `COOLForge-Common.psm1`:

```powershell
# Get UTF-8 bytes: printf '🔥' | xxd -p  # Returns f09f94a5
# Add to $EmojiRepairs hashtable:
"$([char]0xF0)$([char]0x9F)$([char]0x94)$([char]0xA5)" = [char]::ConvertFromUtf32(0x1F525)
```

---

## Usage Examples

### Repair-LevelEmoji

```powershell
# The launcher uses this automatically to fix corrupted script names
$ScriptToRun = Repair-LevelEmoji -Text $ScriptToRun
```

### Get-LevelUrlEncoded

```powershell
$EncodedName = Get-LevelUrlEncoded -Text "👀Test Script.ps1"
# Returns: %F0%9F%91%80Test%20Script.ps1

# Build a URL with an emoji-containing filename
$ScriptUrl = "$BaseUrl/$(Get-LevelUrlEncoded $ScriptToRun)"
```

> **Note:** These functions are called automatically by the Script Launcher. You typically don't need to call them directly unless working with emoji-containing strings in your own scripts.

---

## See Also

- [Main README](../README.md)
- [Function Reference](FUNCTIONS.md)
