#!/bin/bash
# MeshCentral Policy Script - macOS
# Version: 2026.01.19.02
# Target: Level.io RMM
# Exit 0 = Success | Exit 1 = Alert (Failure)
#
# Copyright (c) COOLNETWORKS
# https://github.com/coolnetworks/COOLForge

# ============================================================
# LEVEL.IO VARIABLES (passed via launcher)
# ============================================================
POLICY_MESHCENTRAL="{{cf_policy_meshcentral}}"
POLICY_SERVER_URL="{{cf_policy_meshcentral_server_url}}"
POLICY_MAC_DOWNLOAD_URL="{{cf_policy_meshcentral_mac_download_url}}"
LEVEL_API_KEY="{{cf_apikey}}"
LEVEL_DEVICE_ID="{{level_device_id}}"
DEVICE_TAGS="{{level_tag_names}}"

# ============================================================
# CONFIGURATION
# ============================================================
MESHAGENT_PATHS=(
    "/usr/local/mesh_services/meshagent"
    "/opt/meshagent"
    "/usr/local/mesh"
)
MESHAGENT_BIN="meshagent"
TEMP_DIR="/tmp"
INSTALLER_NAME="meshagent.mpkg"
SOFTWARE_NAME="MESHCENTRAL"
SOFTWARE_NAME_LOWER="meshcentral"
LEVEL_API_BASE="https://api.level.io/v1"

# Policy tag emoji patterns (UTF-8)
# U+1F64F = Pray (Install)
# U+1F6AB = Prohibit (Remove)
# U+1F4CC = Pushpin (Pin)
# U+1F504 = Arrows (Reinstall)
# U+2705 = Checkmark (Has/Installed)
EMOJI_PRAY=$'\xF0\x9F\x99\x8F'
EMOJI_PROHIBIT=$'\xF0\x9F\x9A\xAB'
EMOJI_PIN=$'\xF0\x9F\x93\x8C'
EMOJI_REINSTALL=$'\xF0\x9F\x94\x84'
EMOJI_CHECK=$'\xE2\x9C\x85'

# ============================================================
# LOGGING FUNCTIONS
# ============================================================

log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[SUCCESS] $1"
}

log_error() {
    echo "[ERROR] $1"
}

log_warn() {
    echo "[WARN] $1"
}

log_debug() {
    echo "[DEBUG] $1"
}

# ============================================================
# DEPENDENCY CHECK
# ============================================================

ensure_curl_installed() {
    if command -v curl &> /dev/null; then
        return 0
    fi

    log_info "curl not found - attempting to install..."

    if command -v brew &> /dev/null; then
        brew install curl
    else
        xcode-select --install 2>/dev/null || true
        sleep 5
    fi

    if command -v curl &> /dev/null; then
        log_success "curl is now available"
        return 0
    else
        log_error "curl not available"
        return 1
    fi
}

# ============================================================
# POLICY TAG FUNCTIONS
# ============================================================

# Check if a tag matches software with specific emoji prefix
tag_matches() {
    local tag="$1"
    local emoji="$2"
    local software="$3"

    # Normalize tag (lowercase, trim)
    local tag_lower
    tag_lower=$(echo "$tag" | tr '[:upper:]' '[:lower:]' | xargs)

    # Check if tag starts with emoji and contains software name
    if [[ "$tag" == "${emoji}"* ]] && [[ "$tag_lower" == *"$software"* ]]; then
        return 0
    fi

    return 1
}

# Resolve policy from device tags
# Returns: install, remove, pin, reinstall, none
resolve_policy_from_tags() {
    local tags="$1"

    # If no tags, return none
    if [ -z "$tags" ] || [[ "$tags" == "{{level_"* ]]; then
        echo "none"
        return
    fi

    local has_install=false
    local has_remove=false
    local has_pin=false
    local has_reinstall=false
    local has_installed=false

    # Split tags by comma and check each
    IFS=',' read -ra TAG_ARRAY <<< "$tags"
    for tag in "${TAG_ARRAY[@]}"; do
        # Trim whitespace
        tag=$(echo "$tag" | xargs)

        # Check for software-specific tags
        if tag_matches "$tag" "$EMOJI_PRAY" "$SOFTWARE_NAME_LOWER"; then
            has_install=true
            log_debug "Found Install tag: $tag"
        elif tag_matches "$tag" "$EMOJI_PROHIBIT" "$SOFTWARE_NAME_LOWER"; then
            has_remove=true
            log_debug "Found Remove tag: $tag"
        elif tag_matches "$tag" "$EMOJI_PIN" "$SOFTWARE_NAME_LOWER"; then
            has_pin=true
            log_debug "Found Pin tag: $tag"
        elif tag_matches "$tag" "$EMOJI_REINSTALL" "$SOFTWARE_NAME_LOWER"; then
            has_reinstall=true
            log_debug "Found Reinstall tag: $tag"
        elif tag_matches "$tag" "$EMOJI_CHECK" "$SOFTWARE_NAME_LOWER"; then
            has_installed=true
            log_debug "Found Has/Installed tag: $tag"
        fi
    done

    # Priority resolution (matching PowerShell logic)
    if [ "$has_pin" = true ]; then
        echo "pin"
    elif [ "$has_reinstall" = true ]; then
        echo "reinstall"
    elif [ "$has_install" = true ]; then
        echo "install"
    elif [ "$has_remove" = true ]; then
        echo "remove"
    else
        echo "none"
    fi
}

# Get final policy (tags override custom field)
get_resolved_policy() {
    local tag_policy
    tag_policy=$(resolve_policy_from_tags "$DEVICE_TAGS")

    if [ "$tag_policy" != "none" ]; then
        log_info "Policy from tags: $tag_policy"
        echo "$tag_policy"
        return
    fi

    # Fall back to custom field policy
    if [ -n "$POLICY_MESHCENTRAL" ] && [[ "$POLICY_MESHCENTRAL" != "{{cf_"* ]]; then
        local cf_policy
        cf_policy=$(echo "$POLICY_MESHCENTRAL" | tr '[:upper:]' '[:lower:]' | xargs)
        log_info "Policy from custom field: $cf_policy"
        echo "$cf_policy"
        return
    fi

    echo "none"
}

# ============================================================
# LEVEL.IO API FUNCTIONS
# ============================================================

has_api_key() {
    [ -n "$LEVEL_API_KEY" ] && [[ "$LEVEL_API_KEY" != "{{cf_"* ]]
}

has_device_id() {
    [ -n "$LEVEL_DEVICE_ID" ] && [[ "$LEVEL_DEVICE_ID" != "{{level_"* ]]
}

level_api_request() {
    local method="$1"
    local endpoint="$2"
    local data="$3"

    if [ -n "$data" ]; then
        curl -sS -X "$method" "${LEVEL_API_BASE}${endpoint}" \
            -H "Authorization: Bearer $LEVEL_API_KEY" \
            -H "Content-Type: application/json" \
            -d "$data" 2>/dev/null
    else
        curl -sS -X "$method" "${LEVEL_API_BASE}${endpoint}" \
            -H "Authorization: Bearer $LEVEL_API_KEY" \
            -H "Content-Type: application/json" 2>/dev/null
    fi
}

# Find tag ID by searching for tag containing pattern (macOS compatible)
find_tag_id_by_pattern() {
    local emoji="$1"
    local software="$2"

    local response
    response=$(level_api_request "GET" "/tags")
    if [ -z "$response" ]; then
        return 1
    fi

    # macOS grep doesn't support -P, use sed/grep combo
    echo "$response" | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//'
}

add_tag_to_device() {
    local tag_id="$1"

    if [ -z "$tag_id" ]; then
        return 1
    fi

    level_api_request "POST" "/devices/${LEVEL_DEVICE_ID}/tags" "{\"tagId\": \"${tag_id}\"}" > /dev/null
    return 0
}

remove_tag_from_device() {
    local tag_id="$1"

    if [ -z "$tag_id" ]; then
        return 0
    fi

    level_api_request "DELETE" "/devices/${LEVEL_DEVICE_ID}/tags/${tag_id}" > /dev/null
    return 0
}

add_level_policy_tag() {
    local tag_type="$1"

    if ! has_api_key || ! has_device_id; then
        return 0
    fi

    local tag_id
    tag_id=$(find_tag_id_by_pattern "$tag_type" "$SOFTWARE_NAME")

    if [ -n "$tag_id" ]; then
        add_tag_to_device "$tag_id"
        log_info "Added tag: $tag_type $SOFTWARE_NAME"
    fi
}

remove_level_policy_tag() {
    local tag_type="$1"

    if ! has_api_key || ! has_device_id; then
        return 0
    fi

    local tag_id
    tag_id=$(find_tag_id_by_pattern "$tag_type" "$SOFTWARE_NAME")

    if [ -n "$tag_id" ]; then
        remove_tag_from_device "$tag_id"
        log_info "Removed tag: $tag_type $SOFTWARE_NAME"
    fi
}

# ============================================================
# MESHCENTRAL FUNCTIONS
# ============================================================

is_meshcentral_installed() {
    for path in "${MESHAGENT_PATHS[@]}"; do
        if [ -f "$path/$MESHAGENT_BIN" ]; then
            echo "$path"
            return 0
        fi
    done

    if pgrep -x "meshagent" > /dev/null 2>&1; then
        return 0
    fi

    if [ -f "/Library/LaunchDaemons/meshagent.plist" ]; then
        return 0
    fi

    return 1
}

get_installed_server_url() {
    for path in "${MESHAGENT_PATHS[@]}"; do
        if [ -f "$path/meshagent.msh" ]; then
            grep -oE 'MeshServer\s*=\s*wss?://[^/[:space:]]+' "$path/meshagent.msh" 2>/dev/null | sed 's/.*wss\{0,1\}:\/\///' && return 0
        fi
        if [ -f "$path/meshagent.db" ]; then
            grep -oE 'wss?://[^/[:space:]"]+' "$path/meshagent.db" 2>/dev/null | head -1 | sed 's/wss\{0,1\}:\/\///' && return 0
        fi
    done
    return 1
}

install_meshcentral() {
    if [ -z "$POLICY_MAC_DOWNLOAD_URL" ] || [[ "$POLICY_MAC_DOWNLOAD_URL" == "{{cf_"* ]]; then
        log_error "Mac download URL not configured"
        echo "Alert: MeshCentral install failed - policy_meshcentral_mac_download_url custom field not set"
        return 1
    fi

    log_info "Installing MeshCentral agent..."
    log_info "Download URL: $POLICY_MAC_DOWNLOAD_URL"

    local installer_path="$TEMP_DIR/$INSTALLER_NAME"

    rm -f "$installer_path" 2>/dev/null

    log_info "Downloading installer..."
    if command -v curl &> /dev/null; then
        curl -sSL -o "$installer_path" "$POLICY_MAC_DOWNLOAD_URL"
    elif command -v wget &> /dev/null; then
        wget -q -O "$installer_path" "$POLICY_MAC_DOWNLOAD_URL"
    else
        log_error "Neither curl nor wget available"
        return 1
    fi

    if [ ! -f "$installer_path" ]; then
        log_error "Download failed - installer not found"
        return 1
    fi

    local file_size
    file_size=$(stat -f%z "$installer_path" 2>/dev/null || stat -c%s "$installer_path" 2>/dev/null)
    log_info "Downloaded installer: $file_size bytes"

    log_info "Installing package..."
    sudo installer -pkg "$installer_path" -target / 2>&1
    local exit_code=$?

    rm -f "$installer_path" 2>/dev/null

    if [ $exit_code -ne 0 ]; then
        log_error "Installer failed with exit code $exit_code"
        return 1
    fi

    sleep 5

    if is_meshcentral_installed; then
        log_success "MeshCentral agent installed successfully"

        if [ -n "$POLICY_SERVER_URL" ] && [[ "$POLICY_SERVER_URL" != "{{cf_"* ]]; then
            local detected_server
            detected_server=$(get_installed_server_url)
            if [ -n "$detected_server" ]; then
                if [[ "$detected_server" == *"$POLICY_SERVER_URL"* ]] || [[ "$POLICY_SERVER_URL" == *"$detected_server"* ]]; then
                    log_success "Server URL verified: $detected_server"
                else
                    log_warn "Installed agent points to '$detected_server' but expected '$POLICY_SERVER_URL'"
                fi
            fi
        fi
        return 0
    else
        log_error "Installation verification failed - agent not found"
        return 1
    fi
}

remove_meshcentral() {
    log_info "Removing MeshCentral agent..."

    if [ -f "/Library/LaunchDaemons/meshagent.plist" ]; then
        log_info "Stopping meshagent launch daemon..."
        sudo launchctl unload /Library/LaunchDaemons/meshagent.plist 2>/dev/null || true
    fi

    log_info "Stopping meshagent processes..."
    sudo pkill -f meshagent 2>/dev/null || true
    sleep 2

    for path in "${MESHAGENT_PATHS[@]}"; do
        if [ -f "$path/$MESHAGENT_BIN" ]; then
            log_info "Running uninstaller at $path..."
            sudo "$path/$MESHAGENT_BIN" -fulluninstall 2>/dev/null || true
            sleep 3
        fi
    done

    for path in "${MESHAGENT_PATHS[@]}"; do
        if [ -d "$path" ]; then
            log_info "Removing directory: $path"
            sudo rm -rf "$path" 2>/dev/null || true
        fi
    done

    sudo rm -f /Library/LaunchDaemons/meshagent.plist 2>/dev/null || true
    sudo pkgutil --forget com.meshcentral.meshagent 2>/dev/null || true

    sleep 2
    if is_meshcentral_installed; then
        log_error "Removal verification failed - MeshCentral still present"
        return 1
    fi

    log_success "MeshCentral agent removed successfully"
    return 0
}

# ============================================================
# TAG MANAGEMENT AFTER ACTION
# ============================================================

update_tags_after_action() {
    local action="$1"
    local success="$2"
    local final_installed="$3"

    if ! has_api_key || ! has_device_id; then
        log_info "No API key or device ID - tag updates skipped"
        return 0
    fi

    log_info "Updating tags..."

    if [ "$success" != "true" ]; then
        log_warn "Action failed - tags not updated"
        return 0
    fi

    case "$action" in
        "install")
            remove_level_policy_tag "Install"
            if [ "$final_installed" = "true" ]; then
                add_level_policy_tag "Has"
            fi
            ;;
        "remove")
            remove_level_policy_tag "Remove"
            remove_level_policy_tag "Has"
            ;;
        "reinstall")
            remove_level_policy_tag "Reinstall"
            if [ "$final_installed" = "true" ]; then
                add_level_policy_tag "Has"
            fi
            ;;
        "pin")
            remove_level_policy_tag "Pin"
            ;;
    esac
}

# ============================================================
# MAIN SCRIPT
# ============================================================

log_info "MeshCentral Policy Enforcement - macOS"
log_info "Device tags: $DEVICE_TAGS"

# Ensure curl is installed
if ! ensure_curl_installed; then
    log_warn "curl not available - API tagging disabled"
fi

# Resolve policy from tags first, then custom field
RESOLVED_POLICY=$(get_resolved_policy)
log_info "Resolved policy: $RESOLVED_POLICY"

# Check if any policy is configured
if [ "$RESOLVED_POLICY" = "none" ]; then
    log_info "No policy configured - skipping"
    exit 0
fi

# Check current state
INSTALLED_PATH=$(is_meshcentral_installed)
if [ -n "$INSTALLED_PATH" ]; then
    IS_INSTALLED=true
    log_info "Current state: Installed at $INSTALLED_PATH"
else
    IS_INSTALLED=false
    log_info "Current state: Not installed"
fi

# Execute policy
ACTION_SUCCESS=false
case "$RESOLVED_POLICY" in
    "install")
        if [ "$IS_INSTALLED" = true ]; then
            log_success "Already installed - no action needed"
            ACTION_SUCCESS=true
        else
            log_info "ACTION: Installing MeshCentral"
            if install_meshcentral; then
                ACTION_SUCCESS=true
            else
                echo "Alert: MeshCentral installation failed on macOS"
            fi
        fi
        ;;
    "remove")
        if [ "$IS_INSTALLED" = false ]; then
            log_success "Not installed - no action needed"
            ACTION_SUCCESS=true
        else
            log_info "ACTION: Removing MeshCentral"
            if remove_meshcentral; then
                ACTION_SUCCESS=true
            else
                echo "Alert: MeshCentral removal failed on macOS"
            fi
        fi
        ;;
    "reinstall")
        log_info "ACTION: Reinstalling MeshCentral"
        if [ "$IS_INSTALLED" = true ]; then
            if ! remove_meshcentral; then
                log_error "Failed to remove for reinstall"
                echo "Alert: MeshCentral reinstall failed on macOS"
            fi
        fi
        if install_meshcentral; then
            ACTION_SUCCESS=true
        else
            echo "Alert: MeshCentral reinstall failed on macOS"
        fi
        ;;
    "pin")
        log_info "Pinned - no changes allowed"
        ACTION_SUCCESS=true
        ;;
    *)
        log_warn "Unknown policy value: $RESOLVED_POLICY"
        ACTION_SUCCESS=true
        ;;
esac

# Update tags based on action result
FINAL_INSTALLED=$(is_meshcentral_installed > /dev/null 2>&1 && echo "true" || echo "false")
update_tags_after_action "$RESOLVED_POLICY" "$ACTION_SUCCESS" "$FINAL_INSTALLED"

# Exit based on success
if [ "$ACTION_SUCCESS" = true ]; then
    exit 0
else
    exit 1
fi
