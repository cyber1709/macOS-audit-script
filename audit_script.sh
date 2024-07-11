#!/bin/bash

echo "Starting macOS Security Audit"

# Gather System Information
echo "Gathering System Information..."
AUTHOR="MHA (IB)"
VERSION="1.0"
OS_NAME=$(uname -s)
OS_VERSION=$(sw_vers -productVersion)
KERNEL_VERSION=$(uname -r)
HARDWARE_PLATFORM=$(uname -m)
HOSTNAME=$(hostname)

echo " OPERATING SYSTEM DETAILS "
echo "  ---------------------------------------------------"
echo "  Program version:           $PROGRAM_VERSION"
echo "  Operating system:          $OS_NAME"
echo "  Operating system version:  $OS_VERSION"
echo "  Kernel version:            $KERNEL_VERSION"
echo "  Hardware platform:         $HARDWARE_PLATFORM"
echo "  Hostname:                  $HOSTNAME"
echo "  ---------------------------------------------------"

# Check System Integrity Protection (SIP), 
# security technology in macOS designed to help prevent malcious software from modyfing protected files
# and directories on the macOS, restricts access directories like /System, /usr (except /usr/local), /bin, /sbin
# and the apps that come pre installed in macOS
# It limits system process and kernel extentions from being altered
# restricts code injection into system processes
# to enable/diable "csrutil enable/disable" 
echo "Checking System Integrity Protection (SIP) status..."
csrutil status

# Check Gatekeeper status
# features ensures that only trusted software runs on the macOS
# only authorised softwares having valid certificates can be installed on macOS
# to enable/disable "spctl --master-disable/enable"
echo "Checking Gatekeeper status..."
spctl --status

# Check XProtect status
# XProtect is security feature which automitically blocking known malware software
# Key features- Automatic updates of signatures, File quarantine, Signature based detection
# Integration with Gatekeeper, Silent operations
echo "Checking XProtect status..."
/usr/libexec/xprotectcheck --version

# Check Firewall status
echo "Checking Firewall status..."
echo "If firewall is disable, state is 0"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Check FileVault status
# it is full disk encryption program in macOS, designed for encrypting entire drive
# features- full disk encryption, secure recoevery key , password protection, instant data protection
echo "Checking FileVault status..."
fdesetup status

# Check Privacy controls
echo "Checking location services.."
location_status= $(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist LocationServicesEnabled)
if ["$location_status" -eq 1]; then
    echo "Location Services: Enabled"
else
    echo "Location Services: Disabled"
fi 

# Get code to see all the services which are using microphone and camera 

# Check secure boot
# Secure boot is security feature which ensure that only trusted operating system software loads during startup process
# protecting against tempering or unauthorised modifications 
# Check Secure Boot
echo "Checking Secure Boot"

# external boot security refers to security setting that controls weather macOS allows booting from external devices 
# such as USB drives or external harddisks
echo "Checking boot security"
echo "0-Full security mode, 1- Reduced security mode, 2- No security policy enforced"
sudo nvram security-policy


echo "Review settings in Startup Security Utility in macOS Recovery"

# Check Software Update status
echo "List of installed apps"
softwareupdate -ia

echo "List of apps for whom updates are available"
softwareupdate -l

echo "Checking Software Update status..."
softwareupdate --schedule

# Check Kernel Extensions (KEXT) Management
# KEXT- Kernel extentions are part of base OS which extent functionality to other apps
# macOS imposes restrictions abd requires explicity permissions to load third party KEXTs,
echo "Checking Kernel Extensions (KEXT) status.. getting all third party Kernel extentions loaded"
kextstat | grep -v com.apple

# Check System Preferences Lockdow
# It is feature in macOS that allows administrators to restrict access to certain settings within the system pref app
# allows admin to enforce policies to maintain system intergrity, security and compliance
echo "Checking if System Preferences is locked..."
if sudo defaults read /Library/Preferences/com.apple.systempreferences.plist | grep "LockPrefPane" > /dev/null; then
    echo "System Preferences is locked"
else
    echo "System Preferences is not locked"
fi

# Kernel Hardening
echo "Checking Kernel Hardening settings..."


# Check for NVRAM protections
echo "Checking NVRAM protections..."
nvram -p | grep -i 'csr-active-config'

# Check if rootless mode is enabled
echo "Checking if rootless mode is enabled..."
rootlessStatus=$(nvram -p | grep -i 'boot-args' | grep -i 'rootless=0')
if [ -z "$rootlessStatus" ]; then
    echo "Rootless mode is enabled"
else
    echo "Rootless mode is disabled"
fi


# Checking User Account Security
echo "Checking User Account Security..."
echo "Current user: $(whoami)"
echo "Check user roles and two-factor authentication in System Preferences -> Users & Groups"

# Check Application Layer Security
echo "Checking Application Layer Security..."
echo "Ensure apps are sandboxed and signed. Review applications manually."

# Check Network Security
echo "Checking Network Security..."
networksetup -getwebproxy Wi-Fi
networksetup -getsecurewebproxy Wi-Fi
networksetup -getproxybypassdomains Wi-Fi

# Check for Strong Password Policies
# Strong password policies enforce complex passwords, enhancing security.
echo "Checking for strong password policies..."
pwpolicy getaccountpolicies | grep -i 'policyCategory passwordContent'


# Check for Automatic Login
echo "Checking if Automatic Login is disabled..."
autoLoginEnabled=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if [ -z "$autoLoginEnabled" ]; then
    echo "Automatic Login is disabled"
else
    echo "Automatic Login is enabled for user: $autoLoginEnabled"
fi

# Check for Security & Privacy settings
# Reviewing Security & Privacy settings helps ensure that the system is configured securely.
echo "Checking Security & Privacy settings..."
sudo security authorizationdb read system.preferences > /dev/null 2>&1 && echo "Authorization DB read successfully" || echo "Failed to read Authorization DB"


# Check for SSH Access
echo "Checking if SSH access is enabled..."
sshdStatus=$(systemsetup -getremotelogin)
echo "$sshdStatus"

# Check for Guest Account
echo "Checking if Guest Account is disabled..."
guestAccountStatus=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [ "$guestAccountStatus" == "0" ]; then
    echo "Guest Account is disabled"
else
    echo "Guest Account is enabled"
fi

# Check for Bluetooth Status
echo "Checking Bluetooth status..."
bluetoothStatus=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null)
if [ "$bluetoothStatus" == "0" ]; then
    echo "Bluetooth is turned off"
else
    echo "Bluetooth is turned on"
fi

# Check for Secure Keyboard Entry in Terminal
# secure keyboard entry is feature in macOS to protect keystrokes from being interpreted from being intercepted or monitored 
# by potentially malicious applications.
echo "Checking if Secure Keyboard Entry is enabled in Terminal..."
secureKeyboardEntry=$(defaults read com.apple.Terminal SecureKeyboardEntry 2>/dev/null)
if [ "$secureKeyboardEntry" == "1" ]; then
    echo "Secure Keyboard Entry is enabled in Terminal"
else
    echo "Secure Keyboard Entry is disabled in Terminal"
fi

# Check for EFI Password
# Extensible Firmware password is security feature to protect mac at hardware level
# prevents critical startup functions, such as selecting a startup disk entering mac recovery
echo "Checking for EFI (Firmware) password..."
firmwarePasswordStatus=$(firmwarepasswd -check)
echo "$firmwarePasswordStatus"

echo "macOS Security Audit Completed"

echo "Review the output and adjust settings in System Preferences where necessary."
