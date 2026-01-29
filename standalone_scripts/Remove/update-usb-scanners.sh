#!/bin/bash
# ============================================================================
# Update USB Security Toolkit - Download Latest Offline Scanners
# ============================================================================
# Downloads latest versions of offline AV scanners to USB toolkit.
# Run this before field deployment to ensure up-to-date signatures.
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "================================================================================"
echo "  UPDATE USB SECURITY TOOLKIT"
echo "================================================================================"
echo -e "${NC}"

# Find USB drive
echo -e "${YELLOW}Looking for USB drive...${NC}"

USB_DEVICE=""
USB_MOUNT="/mnt/usb"

# Look for removable drives
for dev in /dev/sd[b-z]1; do
    if [ -b "$dev" ]; then
        # Check if it's removable
        base_dev=$(echo "$dev" | sed 's/[0-9]*$//')
        base_name=$(basename "$base_dev")
        if [ -f "/sys/block/$base_name/removable" ]; then
            removable=$(cat "/sys/block/$base_name/removable")
            if [ "$removable" = "1" ]; then
                size=$(lsblk -b -n -o SIZE "$dev" 2>/dev/null || echo "0")
                if [ "$size" -gt 1000000000 ]; then  # > 1GB
                    USB_DEVICE="$dev"
                    echo -e "${GREEN}Found USB: $dev ($(lsblk -n -o SIZE $dev))${NC}"
                    break
                fi
            fi
        fi
    fi
done

if [ -z "$USB_DEVICE" ]; then
    echo -e "${RED}ERROR: No USB drive found. Please insert a USB drive.${NC}"
    exit 1
fi

# Mount USB
echo -e "${YELLOW}Mounting USB...${NC}"
sudo mkdir -p "$USB_MOUNT"
sudo mount "$USB_DEVICE" "$USB_MOUNT" 2>/dev/null || true

# Check for toolkit folder
TOOLKIT_DIR="$USB_MOUNT/toolkit"
if [ ! -d "$TOOLKIT_DIR" ]; then
    echo -e "${YELLOW}Creating toolkit folder...${NC}"
    sudo mkdir -p "$TOOLKIT_DIR"
    sudo mkdir -p "$TOOLKIT_DIR/Logs"
fi

# Create temp download directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo ""
echo -e "${CYAN}Downloading latest offline scanners...${NC}"
echo ""

# ============================================================================
# Download functions
# ============================================================================

# Check if file exists and was downloaded within last 24 hours
is_fresh() {
    local file="$1"
    if [ -f "$file" ]; then
        local age=$(( ($(date +%s) - $(stat -c %Y "$file")) / 3600 ))
        if [ $age -lt 24 ]; then
            return 0  # File is fresh (less than 24 hours old)
        fi
    fi
    return 1  # File doesn't exist or is stale
}

download_file() {
    local url="$1"
    local output="$2"
    local name="$3"

    # Check if file already exists on USB and is less than 24 hours old
    if is_fresh "$TOOLKIT_DIR/$output"; then
        local age=$(( ($(date +%s) - $(stat -c %Y "$TOOLKIT_DIR/$output")) / 3600 ))
        local size=$(du -h "$TOOLKIT_DIR/$output" | cut -f1)
        echo -e "${CYAN}  ⏭ $name - already downloaded ${age}h ago ($size)${NC}"
        return 0
    fi

    echo -e "${YELLOW}Downloading $name...${NC}"
    if curl -L -f -# -o "$TEMP_DIR/$output" "$url" 2>/dev/null; then
        size=$(du -h "$TEMP_DIR/$output" | cut -f1)
        echo -e "${GREEN}  ✓ $name ($size)${NC}"
        return 0
    else
        echo -e "${RED}  ✗ Failed to download $name${NC}"
        return 1
    fi
}

# ============================================================================
# Download each scanner
# ============================================================================

echo "1/5: Microsoft Malicious Software Removal Tool (MRT)"
download_file \
    "https://go.microsoft.com/fwlink/?LinkId=212732" \
    "MRT.exe" \
    "MRT.exe (64-bit)" || true

echo ""
echo "2/5: Kaspersky Virus Removal Tool (KVRT)"
download_file \
    "https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe" \
    "KVRT.exe" \
    "KVRT.exe" || true

echo ""
echo "3/5: Kaspersky TDSSKiller (Rootkit Scanner)"
echo -e "${YELLOW}  Note: TDSSKiller may not be available in some regions (US restrictions)${NC}"
download_file \
    "https://media.kaspersky.com/utilities/VirusUtilities/EN/tdsskiller.exe" \
    "TDSSKiller.exe" \
    "TDSSKiller.exe" || true

echo ""
echo "4/5: Malwarebytes AdwCleaner"
download_file \
    "https://adwcleaner.malwarebytes.com/adwcleaner?channel=release" \
    "AdwCleaner.exe" \
    "AdwCleaner.exe" || true

echo ""
echo "5/5: Trellix Stinger (formerly McAfee)"
download_file \
    "https://downloadcenter.trellix.com/products/mcafee-avert/stinger/stinger64.exe" \
    "Stinger.exe" \
    "Stinger.exe (64-bit)" || true

# ============================================================================
# Copy to USB
# ============================================================================

echo ""
echo -e "${CYAN}Copying new downloads to USB toolkit...${NC}"

COPIED=0
for file in MRT.exe KVRT.exe TDSSKiller.exe AdwCleaner.exe Stinger.exe; do
    if [ -f "$TEMP_DIR/$file" ]; then
        sudo cp "$TEMP_DIR/$file" "$TOOLKIT_DIR/"
        echo -e "${GREEN}  ✓ $file (new)${NC}"
        COPIED=$((COPIED + 1))
    fi
done

if [ $COPIED -eq 0 ]; then
    echo -e "${CYAN}  All scanners already up-to-date${NC}"
fi

# ============================================================================
# Create/update the all-in-one scanner launcher
# ============================================================================

echo ""
echo -e "${YELLOW}Updating Run-AllScanners.cmd...${NC}"

# Copy from repo if it exists, otherwise it should already be on USB
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/Run-AllScanners.cmd" ]; then
    sudo cp "$SCRIPT_DIR/Run-AllScanners.cmd" "$TOOLKIT_DIR/"
    echo -e "${GREEN}  ✓ Run-AllScanners.cmd${NC}"
fi

# ============================================================================
# Summary
# ============================================================================

echo ""
echo -e "${CYAN}================================================================================${NC}"
echo -e "${GREEN}  USB TOOLKIT UPDATED${NC}"
echo -e "${CYAN}================================================================================${NC}"
echo ""
echo "  Toolkit location: $TOOLKIT_DIR"
echo ""
echo "  Scanners installed:"
for file in MRT.exe KVRT.exe TDSSKiller.exe AdwCleaner.exe Stinger.exe; do
    if [ -f "$TOOLKIT_DIR/$file" ]; then
        size=$(du -h "$TOOLKIT_DIR/$file" | cut -f1)
        echo "    ✓ $file ($size)"
    else
        echo "    ✗ $file (missing)"
    fi
done

echo ""
echo -e "${YELLOW}Unmounting USB...${NC}"
sudo umount "$USB_MOUNT" 2>/dev/null || true
echo -e "${GREEN}Done! Safe to remove USB.${NC}"
echo ""
