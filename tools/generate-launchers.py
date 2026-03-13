#!/usr/bin/env python3
"""
COOLForge Launcher Generator
Regenerates all launcher files from a single template.
Usage: python3 tools/generate-launchers.py [--dry-run]
"""

import os, sys, json

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_PATH = os.path.join(REPO, "launchers", "_template.ps1")
MANIFEST_PATH = os.path.join(REPO, "launchers", "_manifest.json")

def main():
    dry_run = "--dry-run" in sys.argv

    with open(TEMPLATE_PATH, "r", encoding="utf-8-sig") as f:
        template = f.read()

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    updated = []
    for entry in manifest:
        script_to_run    = entry["scriptToRun"]
        launcher_name    = entry["launcherName"]
        launcher_version = entry["version"]
        extra_fields     = entry.get("extraFields", [])
        out_path         = os.path.join(REPO, "launchers", launcher_name)

        # Build extra fields block (empty string if none)
        if extra_fields:
            lines = [f'${f["var"]} = "{{{{{f["cf"]}}}}}"' for f in extra_fields]
            extra_block = "\n".join(lines) + "\n"
        else:
            extra_block = ""

        content = template
        content = content.replace("__SCRIPT_TO_RUN__", script_to_run)
        content = content.replace("__LAUNCHER_VERSION__", launcher_version)
        content = content.replace("__LAUNCHER_NAME__", launcher_name)
        content = content.replace("__EXTRA_FIELDS__", extra_block)

        if not dry_run:
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w", encoding="utf-8-sig") as f:
                f.write(content)
        updated.append(out_path)
        prefix = "[DRY-RUN] " if dry_run else ""
        action = "would write" if dry_run else "wrote"
        print(f"{prefix}{action}: launchers/{launcher_name}")

    print(f"\n{'Would update' if dry_run else 'Updated'} {len(updated)} launchers.")

if __name__ == "__main__":
    main()
