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

# Check which apps have access to the microphone and camera
# The tccutil command can be used to manage the privacy database for your Mac.
echo "Checking which apps have access to the microphone and camera..."
tccutil list

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

# Listing installed apps helps in auditing which applications are present on the system.
echo "List of installed apps"
softwareupdate -ia

# List of apps for whom updates are available
# Checking for available updates for installed apps.
echo "List of apps for whom updates are available"
softwareupdate -l

# Check Software Update status
# Keeping macOS updated is crucial for maintaining security as updates often include patches for vulnerabilities.
echo "Checking Software Update status..."
softwareupdate --schedule


# Check if reboot is needed
echo "Checking if reboot is needed..."
needsReboot=$(softwareupdate -l | grep -i "restart")
if [ -n "$needsReboot" ]; then
    echo "Rebot [REQUIRED]"
else
    echo "Reboot [NOT REQUIRED]"
fi

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
# Rootless mode (System Integrity Protection) prevents root from modifying certain protected parts of macOS.
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




echo "-------------------------------------------------------------"
echo "Checking for running web servers"
echo "-------------------------------------------------------------"

# Check for Apache
if pgrep -x "httpd" > /dev/null; then
    echo "Apache [RUNNING]"
    apachectl -v
else
    echo "Apache [NOT RUNNING]"
fi

# Check for Nginx
if pgrep -x "nginx" > /dev/null; then
    echo "Nginx [RUNNING]"
    nginx -v
else
    echo "Nginx [NOT RUNNING]"
fi

# Check for other common web servers
# This can be expanded to include other web servers if needed.
webservers=("lighttpd" "caddy")
for server in "${webservers[@]}"; do
    if pgrep -x "$server" > /dev/null; then
        echo "$server [RUNNING]"
        $server -v
    else
        echo "$server [NOT RUNNING]"
    fi
done

echo "-----------------------------------------------------------"
echo "Starting macOS Memory and Processes Audit"
echo "-----------------------------------------------------------"


# Check /proc/meminfo equivalent on macOS
# vm_stat provides virtual memory statistics on macOS, including information about memory usage, paging activity, and more.
echo "Checking memory information..."
vm_stat


# Searching for dead/zombie processes
# This command lists processes that are in a zombie state (marked with 'Z'), which indicates processes that have completed execution but still have entries in the process table.
echo "Searching for dead/zombie processes..."
ps aux | awk '{ print $8 " " $2 }' | grep -w Z


# Searching for IO waiting processes
# iostat reports CPU and I/O statistics, including input/output activity and CPU utilization. It helps identify processes that may be waiting for I/O operations.
echo "Searching for IO waiting processes..."
iostat


# Search prelink tooling
# This command searches for prelink tooling files across the filesystem. Prelinking is a technique used to optimize dynamic linking of executables and shared libraries on Unix-like systems.
echo "Search prelink tooling..."
sudo find / -name prelink


echo "--------------------------------------------------------------------"

# Check for Time Machine Backup Status
echo "Checking Time Machine backup status..."
tmutil status | grep -q "BackupPhase = 2"
if [ $? -eq 0 ]; then
    echo "Time Machine Backup: YES"
else
    echo "Time Machine Backup: NO"
fi

# Scan for Malware and Adware
echo "Scanning for malware and adware..."
# Example command using a third-party tool like ClamAV
clamscan -r / | grep -q "Infected files: 0"
if [ $? -eq 0 ]; then
    echo "Malware and Adware Scan: No threats found"
else
    echo "Malware and Adware Scan: Threats detected!"
fi

# Review System Logs for Security Events
echo "Reviewing system logs for security events..."
syslog -k Sender kernel -k Message CReq 'denied' | grep -q "denied"
if [ $? -eq 0 ]; then
    echo "Security Events in System Logs: YES"
else
    echo "Security Events in System Logs: NO"
fi

# Check System Integrity Using chkrootkit
echo "Checking system integrity using chkrootkit..."
sudo chkrootkit | grep -q "not infected"
if [ $? -eq 0 ]; then
    echo "System Integrity (chkrootkit): No issues found"
else
    echo "System Integrity (chkrootkit): Potential issues detected!"
fi

# Verify System and Application Integrity with codesign
echo "Verifying system and application integrity..."
codesign -vvv --deep /path/to/application.app 2>&1 | grep -q "satisfies its Designated Requirement"
if [ $? -eq 0 ]; then
    echo "System and Application Integrity (codesign): Verified"
else
    echo "System and Application Integrity (codesign): Not Verified"
fi

# Monitor Open Ports and Network Connections
echo "Monitoring open ports and network connections..."
sudo lsof -i -P -n | grep LISTEN | grep -q "LISTEN"
if [ $? -eq 0 ]; then
    echo "Open Ports and Network Connections: YES"
else
    echo "Open Ports and Network Connections: NO"
fi

# Review System Preferences and Settings
echo "Reviewing critical system preferences..."
# Example: Check if automatic login is disabled
defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null | grep -q "autoLoginUser"
if [ $? -eq 0 ]; then
    echo "Critical System Preferences: Configured"
else
    echo "Critical System Preferences: Not Configured"
fi

# File System Permissions and Ownership Audit
echo "Auditing file system permissions..."
sudo find / -type f \( -perm -4000 -o -perm -2000 \) -ls | grep -q "files"
if [ $? -eq 0 ]; then
    echo "File System Permissions Audit: Issues found"
else
    echo "File System Permissions Audit: No issues found"
fi

# Check for Unused or Outdated Software
echo "Checking for unused or outdated software..."
brew outdated | grep -q "Error"
if [ $? -eq 0 ]; then
    echo "Unused or Outdated Software: Issues found"
else
    echo "Unused or Outdated Software: No issues found"
fi

# Review Crash Reports and Diagnostic Data
echo "Reviewing crash reports and diagnostic data..."
sudo find /Library/Logs/DiagnosticReports -type f -exec tail -n 10 {} \; | grep -q "error"
if [ $? -eq 0 ]; then
    echo "Crash Reports and Diagnostic Data: Issues found"
else
    echo "Crash Reports and Diagnostic Data: No issues found"
fi