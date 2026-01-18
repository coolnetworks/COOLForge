#!/bin/bash
# MeshCentral Policy Launcher - macOS
# Version: 2026.01.19.03
# Target: Level.io RMM
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# LEVEL.IO VARIABLES
# ============================================================
export POLICY_MESHCENTRAL="{{cf_policy_meshcentral}}"
export POLICY_SERVER_URL="{{cf_policy_meshcentral_server_url}}"
export POLICY_MAC_DOWNLOAD_URL="{{cf_policy_meshcentral_mac_download_url}}"
export LEVEL_API_KEY="{{cf_apikey}}"
export LEVEL_DEVICE_ID="{{level_device_id}}"
export DEVICE_TAGS="{{level_tag_names}}"

GITHUB_PAT="{{cf_coolforge_pat}}"
PINNED_VERSION="{{cf_coolforge_pin_psmodule_to_version}}"
DEBUG_SCRIPTS="{{cf_debug_scripts}}"
MSP_SCRATCH_FOLDER="{{cf_coolforge_msp_scratch_folder}}"

# ============================================================
# CONFIGURATION
# ============================================================
SCRIPT_NAME="👀meshcentral-mac.sh"
REPO_OWNER="coolnetworks"
REPO_NAME="COOLForge"
MAC_CACHE_BASE="/Library/Caches"

# Determine scratch folder from Windows path
if [ -n "$MSP_SCRATCH_FOLDER" ] && [[ "$MSP_SCRATCH_FOLDER" != "{{cf_"* ]]; then
    # Extract last path component (handles both \ and /)
    FOLDER_NAME=$(basename "${MSP_SCRATCH_FOLDER//\\//}")
    SCRATCH_FOLDER="${MAC_CACHE_BASE}/${FOLDER_NAME}"
else
    SCRATCH_FOLDER="${MAC_CACHE_BASE}/COOLForge"
fi
SCRIPTS_CACHE="${SCRATCH_FOLDER}/Scripts"

# Create cache directory
mkdir -p "$SCRIPTS_CACHE" 2>/dev/null

# Clear cache files older than 30 days
find "$SCRIPTS_CACHE" -type f -mtime +30 -delete 2>/dev/null

# ============================================================
# VALIDATE REQUIRED CUSTOM FIELDS
# ============================================================
MISSING_FIELDS=""

if [ -z "$MSP_SCRATCH_FOLDER" ] || [[ "$MSP_SCRATCH_FOLDER" == "{{cf_"* ]]; then
    MISSING_FIELDS="${MISSING_FIELDS}cf_coolforge_msp_scratch_folder, "
fi

if [ -z "$POLICY_MAC_DOWNLOAD_URL" ] || [[ "$POLICY_MAC_DOWNLOAD_URL" == "{{cf_"* ]]; then
    MISSING_FIELDS="${MISSING_FIELDS}cf_policy_meshcentral_mac_download_url, "
fi

if [ -n "$MISSING_FIELDS" ]; then
    # Remove trailing comma and space
    MISSING_FIELDS="${MISSING_FIELDS%, }"
    echo "[ERROR] Required custom fields are missing: $MISSING_FIELDS"
    echo "Alert: MeshCentral macOS launcher cannot run - missing custom fields. Run the Windows version of this script first on any Windows device and it will create what is required. Then ensure you fill the custom fields: $MISSING_FIELDS"
    exit 1
fi

# Warn if API key is missing (many features disabled)
if [ -z "$LEVEL_API_KEY" ] || [[ "$LEVEL_API_KEY" == "{{cf_"* ]]; then
    echo "[WARN] cf_apikey is not set - Level API features disabled."
    echo "Alert: COOLForge scripts use the Level API to automatically create required custom fields and update device tags to reflect policy state (e.g. adding a 'has' tag after successful install, removing 'install' tags after completion). Without a valid API key in cf_apikey, these features are disabled and tags must be managed manually."
fi

# Determine branch
if [ -n "$PINNED_VERSION" ] && [[ "$PINNED_VERSION" != "{{cf_"* ]]; then
    BRANCH="$PINNED_VERSION"
else
    BRANCH="main"
fi

# Build URL (URL-encode the emoji in filename)
ENCODED_SCRIPT_NAME="%F0%9F%91%80meshcentral-mac.sh"
SCRIPT_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}/scripts/Policy/${ENCODED_SCRIPT_NAME}"

# Add cache-busting in debug mode
if [ "$DEBUG_SCRIPTS" = "true" ]; then
    CACHE_BUSTER=$(date +%s)
    SCRIPT_URL="${SCRIPT_URL}?t=${CACHE_BUSTER}"
    echo "[DEBUG] Script URL: $SCRIPT_URL"
fi

# ============================================================
# DOWNLOAD AND EXECUTE
# ============================================================
echo "[*] MeshCentral macOS Launcher v2026.01.19.03"
echo "[*] Cache folder: $SCRIPTS_CACHE"

CACHED_SCRIPT="${SCRIPTS_CACHE}/${SCRIPT_NAME}"
USE_CACHE=false

# Delete cache in debug mode
if [ "$DEBUG_SCRIPTS" = "true" ] && [ -f "$CACHED_SCRIPT" ]; then
    rm -f "$CACHED_SCRIPT"
    echo "[DEBUG] Deleted cached script"
fi

echo "[*] Downloading script from GitHub..."

# Download script
if [ -n "$GITHUB_PAT" ] && [[ "$GITHUB_PAT" != "{{cf_"* ]]; then
    SCRIPT_CONTENT=$(curl -sSL -H "Authorization: token $GITHUB_PAT" "$SCRIPT_URL" 2>&1)
else
    SCRIPT_CONTENT=$(curl -sSL "$SCRIPT_URL" 2>&1)
fi
CURL_EXIT=$?

# Validate download
DOWNLOAD_OK=false
if [ $CURL_EXIT -eq 0 ]; then
    # Check for GitHub error responses
    if echo "$SCRIPT_CONTENT" | head -1 | grep -q "^404:"; then
        echo "[WARN] Script not found at URL"
    elif echo "$SCRIPT_CONTENT" | head -1 | grep -q "^<!DOCTYPE"; then
        echo "[WARN] Received HTML instead of script (auth issue?)"
    elif ! echo "$SCRIPT_CONTENT" | head -1 | grep -q "^#!/bin/bash"; then
        echo "[WARN] Downloaded content is not a valid bash script"
    else
        DOWNLOAD_OK=true
    fi
else
    echo "[WARN] Download failed (curl exit: $CURL_EXIT)"
fi

if [ "$DOWNLOAD_OK" = true ]; then
    echo "[+] Script downloaded successfully"
    # Cache the script
    echo "$SCRIPT_CONTENT" > "$CACHED_SCRIPT" 2>/dev/null
elif [ -f "$CACHED_SCRIPT" ]; then
    echo "[!] Using cached script"
    SCRIPT_CONTENT=$(cat "$CACHED_SCRIPT")
    USE_CACHE=true
else
    echo "[ERROR] Download failed and no cached version available"
    echo "Alert: MeshCentral launcher failed - could not download script"
    exit 1
fi

# Execute the script
bash -c "$SCRIPT_CONTENT"
exit $?
