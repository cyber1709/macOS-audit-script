#!/bin/bash

# ANSI escape codes for color
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting macOS Security Audit${NC}"

# Gather System Information
echo -e "${BLUE}Gathering System Information...${NC}"
AUTHOR="MHA (IB)"
VERSION="1.0"
OS_NAME=$(uname -s)
OS_VERSION=$(sw_vers -productVersion)
KERNEL_VERSION=$(uname -r)
HARDWARE_PLATFORM=$(uname -m)
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

# Additional System Information
MACOS_VERSION=$(sw_vers -productVersion)
RAM_SIZE=$(system_profiler SPHardwareDataType | grep "Memory:" | awk '{print $2, $3}')
SSD_SIZE=$(diskutil info / | grep "Total Size" | awk '{print $4, $5}')
INSTALLED_OS_DATE=$(ls -l /System/Library/CoreServices/SystemVersion.plist | awk '{print $6, $7}')
PROCESSOR=$(sysctl -n machdep.cpu.brand_string)

# Network Information
LOCAL_IP=$(ipconfig getifaddr en0)  # Adjust interface name as needed (en0 for Ethernet/Wi-Fi)
PUBLIC_IP=$(curl -s ifconfig.me)
MAC_ADDRESS=$(ifconfig en0 | awk '/ether/{print $2}')

echo -e "${YELLOW} SYSTEM DETAILS ${NC}"
echo -e "  ---------------------------------------------------"
echo -e "  Program version:           $VERSION"
echo -e "  Operating system:          $OS_NAME"
echo -e "  Operating system version:  $OS_VERSION"
echo -e "  Kernel version:            $KERNEL_VERSION"
echo -e "  Hardware platform:         $HARDWARE_PLATFORM"
echo -e "  Hostname:                  $HOSTNAME"
echo -e "  Current User:              $CURRENT_USER"
echo -e "  macOS version:             $MACOS_VERSION"
echo -e "  RAM size:                  $RAM_SIZE"
echo -e "  SSD size:                  $SSD_SIZE"
echo -e "  Installed OS date:         $INSTALLED_OS_DATE"
echo -e "  Processor:                 $PROCESSOR"
echo -e "  Local IP address:          $LOCAL_IP"
echo -e "  Public IP address:         $PUBLIC_IP"
echo -e "  MAC address:               $MAC_ADDRESS"
echo -e "  ---------------------------------------------------"

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check System Integrity Protection (SIP)
echo -e "${BLUE}Checking System Integrity Protection (SIP) status...${NC}"
csrutil status

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check Gatekeeper status
echo -e "${BLUE}Checking Gatekeeper status...${NC}"
spctl --status

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check XProtect status
echo -e "${BLUE}Checking XProtect status...${NC}"
xprotect_plist="/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist"
if [ -f "$xprotect_plist" ]; then
    echo -e "${GREEN}XProtect is enabled${NC}"
    echo -e "${BLUE}XProtect version:${NC}"
    /usr/libexec/PlistBuddy -c "Print :Version" "$xprotect_plist"
else
    echo -e "${RED}XProtect is not found${NC}"
fi

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check FileVault status
echo -e "${BLUE}Checking FileVault status...${NC}"
fdesetup status

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check Privacy controls
echo -e "${BLUE}Checking location services...${NC}"
location_status=$(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist LocationServicesEnabled)
if [ "$location_status" -eq 1 ]; then
    echo -e "${GREEN}Location Services: Enabled${NC}"
else
    echo -e "${RED}Location Services: Disabled${NC}"
fi

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check microphone access
echo -e "${BLUE}Checking microphone access...${NC}"
microphone_access=$(tccutil list Microphone | grep -o "com.*")
if [ -n "$microphone_access" ]; then
    echo -e "${GREEN}Microphone access granted to:${NC}"
    echo "$microphone_access"
fi

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check camera access
echo -e "${BLUE}Checking camera access...${NC}"
camera_access=$(tccutil list Camera | grep -o "com.*")
if [ -n "$camera_access" ]; then
    echo -e "${GREEN}Camera access granted to:${NC}"
    echo "$camera_access"
fi

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check Firmware Password
echo -e "${BLUE}Checking Firmware Password status...${NC}"
firmware_passwd_status=$(sudo firmwarepasswd -check)
if echo "$firmware_passwd_status" | grep -q "Password Enabled: Yes"; then
    echo -e "${GREEN}Firmware Password is enabled${NC}"
else
    echo -e "${RED}Firmware Password is not enabled${NC}"
fi

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check Screen Saver
echo -e "${BLUE}Checking Screen Saver status...${NC}"
if [[ $(defaults -currentHost read com.apple.screensaver idleTime) -gt 0 ]]; then
    echo -e "${GREEN}Screen Saver is enabled${NC}"
else
    echo -e "${RED}Screen Saver is disabled${NC}"
fi

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Listing installed apps helps in auditing which applications are present on the system.
echo -e "${BLUE}List of installed apps written to installed_applications.txt ${NC}"
system_profiler SPApplicationsDataType > installed_applications.txt

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check for updates available for installed softwares
echo -e "${BLUE}Checking for updates available for installed software...${NC}"
echo -e "${BLUE}It will check for applications installed from app store only..${NC}"
sudo softwareupdate -l

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# List third-party applications
echo -e "${BLUE}List of third-party applications${NC}"
# Use Spotlight to list apps in /Applications folder excluding system apps
ls -l /Applications | grep -v "App Store.app"

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check for untrusted or unsigned applications
echo -e "${BLUE}Checking for untrusted or unsigned applications...${NC}"
for app in /Applications/*.app; do
    if ! codesign -dv "$app" &> /dev/null; then
        echo -e "${RED}$app${NC}"
    fi
done

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# List all USB devices (Historical)
echo -e "${BLUE}Getting list of Currently connected USB devices to text file ${NC}"
system_profiler SPUSBDataType -detailLevel full > current_usb_devices.txt

echo -e "${YELLOW}-------------------------------------------------------${NC}"


# List all USB devices (Historical)
echo -e "${BLUE}List of all USB devices ever connected${NC}"
log show --predicate 'eventMessage contains "USBMSC"' --info --last 1d > usb_devices.txt

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check Software Update status
echo -e "${BLUE}Checking for Automatic Software Update status...${NC}"
softwareupdate --schedule

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check if reboot is needed
echo -e "${BLUE}Checking if reboot is needed...${NC}"
needsReboot=$(softwareupdate -l | grep -i "restart")
if [ -n "$needsReboot" ]; then
    echo -e "${RED}Reboot [REQUIRED]${NC}"
else
    echo -e "${GREEN}Reboot [NOT REQUIRED]${NC}"
fi

echo -e "${YELLOW}-------------------------------------------------------${NC}"


# Check if there are third-party kernel extensions loaded
kextstat | grep -v com.apple 

echo -e "${YELLOW}-------------------------------------------------------${NC}"

# Check System Preferences Lockdown
echo -e "${BLUE}Checking if System Preferences is locked...${NC}"
if sudo defaults read /Library/Preferences/com.apple.systempreferences.plist | grep "LockPrefPane" > /dev/null; then
    echo -e "${GREEN}System Preferences is locked${NC}"
else
    echo -e "${RED}System Preferences is not locked${NC}"
fi

echo -e "${YELLOW}-------------------------------------------------------${NC}"