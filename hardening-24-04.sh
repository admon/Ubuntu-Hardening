echo "#######################################"
echo -e "${PURPLE}Filesystem Configurations ${NC}"
echo "#######################################"
#report in cosole colors
RED='\033[0;31m' 
GREEN='\033[0;32m' 
YELLOW='\033[0;33m' 
BLUE='\033[0;34m' 
PURPLE='\033[0;35m' 
NC='\033[0m' # No Color

echo -e "THank you for using my hardening script, please note ${YELLOW} This is not an interactive script, but an automated hardening one"
echo -e "${RED}WARNING:${NC} This script is intended for a clean install and should NOT be run on a live server. \n${RED}Running this script on an active server may break critical services.${NC}\n Run it under your own risk with the awareness and acceptance of the risks \nThis script will start in ${YELLOW}10 Seconds...${NC}"
echo "The script will start in 10 seconds. Press 'c' to cancel."
# Read input for 10 seconds and check for 'c' to cancel
read -t 10 -n 1 input
if [ "$input" == "c" ]; then
  echo "Script execution canceled by the user."
  exit 0
fi

# Filesystems to disable
FILESYSTEMS=("cramfs" "freevxfs" "hfs" "hfsplus" "overlayfs" "squashfs" "udf" "jffs2" "usb-storage")

# Configuration files
DISABLED_FS_CONF="/etc/modprobe.d/disabled-fs.conf"
MODPROBE_CONF="/etc/modprobe.d/modprobe.conf"

# Ensure configuration files exist
sudo touch "$DISABLED_FS_CONF" "$MODPROBE_CONF"

# Disable and blacklist filesystems
for FS in "${FILESYSTEMS[@]}"; do
  echo -e "Disabling and blacklisting ${YELLOW}$FS...${NC}"
  sudo bash -c "echo 'install $FS /bin/false' >> $DISABLED_FS_CONF"
  sudo bash -c "echo 'blacklist $FS' >> $MODPROBE_CONF"
done

echo "#######################################"
echo -e "${PURPLE}Disabled unnecessary filesystems: ${NC}"
echo "${FILESYSTEMS[*]}"
echo "#######################################"

# Unload filesystem modules from the kernel
echo "Removing unnecessary filesystems from the kernel..."
for FS in "${FILESYSTEMS[@]}"; do
  sudo modprobe -r "$FS" 2>/dev/null || echo -e "${BLUE}Module $FS is not loaded or already removed.${NC}"
done
echo "#######################################"
echo -e "In the extras section I recommend to install the USBGard software,\n to allow only pre-defined USB devices, to avoid false keyboards or other physical USB attacks\n"
echo -e "there are other Filesystems to check, if needed add them to this script\n, but this covers the CIS Benchmark recommendation"
echo "#######################################"

echo "#######################################"
echo -e "${PURPLE}Mount Points Checking ${NC}"
echo "#######################################"

# Mounts to check
MOUNTS=("/tmp" "/dev/shm" "/home" "/var" "/var/tmp" "/var/log" "/var/log/audit")

# Function to check for required mount options
check_mount_options() {
  local mount_point=$1
  local required_options=("nodev" "nosuid" "noexec")

  # Get mount options for the given mount point
  mount_options=$(sudo findmnt -kn -o OPTIONS "$mount_point" 2>/dev/null)
  if [[ -z "$mount_options" ]]; then
    echo -e "${RED} WARNING: $mount_point is not mounted. ${NC}"
    return
  fi

  # Check if required options are present
  for option in "${required_options[@]}"; do
    if [[ $mount_options == *"$option"* ]]; then
      echo -e " ${GREEN} $mount_point: $option is set.${NC}"
    else
      echo -e " ${RED} WARNING: $mount_point: $option is NOT set! ${NC}"
    fi
  done
}

# Check if individual partitions exist and validate options
for MNT in "${MOUNTS[@]}"; do
  echo "Checking $MNT..."

  if sudo findmnt -kn "$MNT" &>/dev/null; then
    echo -e "${GREEN}$MNT is mounted on its own partition.\n"
    check_mount_options "$MNT"
  else
    echo -e "${RED}WARNING: $MNT does not have its own partition.${NC}\n"
  fi
done
echo "#######################################"
echo -e "${PURPLE}Mountpoint Check Completed${NC}"
echo "#######################################"
echo "#######################################"
echo -e "${PURPLE}Filesystem Configuration Completed${NC}"
echo "#######################################"
echo -e "\n\n\n"
echo "#######################################"
echo -e "${PURPLE}APT recommendations Checking ${NC}"
echo "#######################################"
echo "This is a manual section of the recommendations for this run:"
echo -e "${BLUE} sudo apt-cache policy ${NC}"
echo "to check the list of repositories and status, run:"
echo -e "${BLUE} sudo apt update && sudo apt upgrade ${NC}"
echo "to keep the packages and security patches up to date"
echo -e "check the GPG keys and Signing"
for file in /etc/apt/trusted.gpg.d/*.{gpg,asc} /etc/apt/sources.list.d/*.{gpg,asc}; do
  if [ -f "$file" ]; then
    echo -e "File: $file"
    gpg --list-packets "$file" 2>/dev/null | awk '/keyid/ && !seen[$NF]++ {print "keyid:", $NF}'
    gpg --list-packets "$file" 2>/dev/null | awk '/Signed-By:/ {print "signed-by:", $NF}'
    echo -e
  fi
done

echo "On the extras I recommend some autometad tools to help with this" 
echo -e "${RED}IT IS ABSOLUTELY IMPORTANT TO KEEP THE SYSTEM UP TO DATE!!! ${NC}" 
echo "#######################################"
echo -e "${PURPLE}APT recommendations Completed ${NC}"
echo "#######################################"
echo -e "\n\n\n"
# Function to check and install required packages
install_apparmor_packages() {
  local packages=("apparmor" "apparmor-utils")
  echo "Checking for required packages: ${packages[*]}"

  for package in "${packages[@]}"; do
    if dpkg -s "$package" &>/dev/null; then
      echo "Package $package is already installed."
    else
      echo "Installing $package..."
      if sudo apt install -y "$package" &>/dev/null; then
        echo "Package $package installed successfully."
      else
        echo "Error installing $package. Check logs for details."
      fi
    fi
  done
}

# Function to check and configure GRUB for AppArmor
configure_grub_for_apparmor() {
  echo "Checking GRUB configuration for AppArmor..."

  if ! grep -q "apparmor=1 security=apparmor" /etc/default/grub; then
    echo -e "${BLUE}Updating GRUB to enable AppArmor... ${NC}"
    sudo sed -i '/^GRUB_CMDLINE_LINUX=/ s/"$/ apparmor=1 security=apparmor"/' /etc/default/grub
    if [[ $? -eq 0 ]]; then
      echo -e "${GREEN}GRUB updated successfully. Applying changes... ${NC}"
      sudo update-grub
    else
      echo -e "${RED}Failed to update GRUB configuration.${NC}"
    fi
  else
    echo "AppArmor settings are already configured in GRUB."
  fi
}

# Function to set AppArmor profiles to complain mode
set_apparmor_profiles_to_complain() {
  echo "Setting AppArmor profiles to complain mode..."

  local profiles
  profiles=$(sudo aa-status | grep "profile set" | awk '{print $3}' || true)
  if [[ -z "$profiles" ]]; then
    echo -e "${RED}No active AppArmor profiles found.${NC}"
    return
  fi

  for profile in $profiles; do
    echo "Setting $profile to complain mode..."
    if sudo aa-complain "$profile"; then
      echo "Profile $profile is now in complain mode."
    else
      echo "Failed to set $profile to complain mode."
    fi
  done
}

# Main MAC setup
main_mac_setup() {
  echo "#######################################"
echo -e "${PURPLE}Starting MAC Setup ${NC}"
  echo "#######################################"
  install_apparmor_packages
  configure_grub_for_apparmor
  set_apparmor_profiles_to_complain
  sudo chown root:root /boot/grub/grub.cfg 
  sudo chmod u-x,go-rwx /boot/grub/grub.cfg
  echo "More strict file access permission to /boot/grub/grub.cfg..."
  echo "#######################################"
  echo -e "${PURPLE}Mandatory Access Control (MAC) Setup Completed ${NC}"
  echo "#######################################"
  echo -e "\n\n\n"
}

# Execute the setup
main_mac_setup


echo "#######################################"
echo -e "${PURPLE}Configure Additional Process Hardening ${NC}"
echo "#######################################"

# Apply kernel parameters securely
apply_kernel_hardening() {
  local param=$1
  local value=$2
  local config_file=$3

  echo "Applying kernel parameter: $param = $value..."
  # Append the parameter to the configuration file if not already present
  if ! grep -q "^$param" "$config_file"; then
    printf "%s\n" "$param = $value" | sudo tee -a "$config_file" > /dev/null
  fi

  # Apply the parameter immediately
  if sudo sysctl -w "$param=$value"; then
    echo -e "${GREEN}Applied $param = $value successfully.${NC}"
  else
    echo -e "${RED}Failed to apply $param = $value. Check logs for details.${NC}"
  fi
}

# Remove a package if it exists
remove_package() {
  local package=$1
  echo "Checking if $package is installed..."
  if dpkg-query -s "$package" &>/dev/null; then
    echo "$package is installed. Removing..."
    if sudo apt purge -y "$package" &>/dev/null; then
      echo -e "${GREEN}Removed $package successfully.${NC}"
    else
      echo -e "${RED}Failed to remove $package. Check logs for details.${NC}"
    fi
  else
    echo -e "${YELLOW}$package is not installed.${NC}"
  fi
}

# Stop and disable a service
disable_service() {
  local service=$1
  echo "Disabling $service service..."
  if systemctl is-active --quiet "$service"; then
    sudo systemctl stop "$service"
    echo "$service service stopped."
  fi
  if systemctl is-enabled --quiet "$service"; then
    sudo systemctl mask "$service"
    echo "$service service disabled."
  fi
}

# Kernel hardening parameters
echo "Configuring kernel parameters for process hardening..."
apply_kernel_hardening "kernel.randomize_va_space" "2" "/etc/sysctl.d/60-kernel_sysctl.conf"
apply_kernel_hardening "kernel.yama.ptrace_scope" "2" "/etc/sysctl.d/60-kernel_sysctl.conf"
apply_kernel_hardening "fs.suid_dumpable" "0" "/etc/sysctl.d/60-fs_sysctl.conf"

# Remove unnecessary packages
remove_package "prelink"
remove_package "apport"

# Disable and remove apport service
disable_service "apport"

echo "#######################################"
echo -e "${PURPLE}Additional Process Hardening Completed ${NC}"
echo "#######################################"
echo -e "\n\n\n"

echo "#######################################"
echo -e "${PURPLE}Configure Command Line Warning Banners${NC}"
echo "#######################################"

# Backup files safely
backup_file() {
  local file=$1
  if [[ -f $file ]]; then
    sudo cp "$file" "${file}.bak"
    echo -e "${GREEN}Backup created for $file as ${file}.bak${NC}"
  else
    echo -e "${YELLOW}File $file does not exist. Skipping backup.${NC}"
  fi
}

# Function to update banner content
update_banner() {
  local file=$1
  local content="$2"

  echo "Updating $file..."
  echo "$content" | sudo tee "$file" > /dev/null
  if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}Updated $file successfully.${NC}"
  else
    echo -e "${RED}Failed to update $file. Check logs for details. ${NC}"
  fi
}

# Function to set ownership and permissions
set_permissions() {
  local file=$1
  if [[ -f $file ]]; then
    sudo chown root:root "$file"
    sudo chmod u-x,go-wx "$file"
    echo "Permissions set for $file."
  else
    echo "File $file not found. Skipping permission update."
  fi
}

# Banner content
BANNER=$(cat << 'EOF'
******************************************************
*                                                    *
*          Authorized Access Only                   *
*                                                    *
******************************************************

This system is for authorized use only. Unauthorized access or use is prohibited and may result in disciplinary action and/or civil and criminal penalties.

All activities on this system are subject to monitoring and recording. By using this system, you expressly consent to such monitoring and recording.

Legal Notice:
-------------
Use of this system constitutes consent to security monitoring and testing. All activities are logged and monitored.
Unauthorized access, use, or modification of this system or its data may result in disciplinary action, civil, and/or criminal penalties.

**Important Security Measures:**
1. **Do not share your login credentials.**
2. **Report any suspicious activity to IT security immediately.**
3. **Adhere to the security policies and guidelines.**

Have a secure session!
EOF
)

# Files to update
FILES=("/etc/motd" "/etc/issue" "/etc/issue.net")

# Backup, update, and secure files
for file in "${FILES[@]}"; do
  backup_file "$file"
  update_banner "$file" "$BANNER"
  set_permissions "$file"
done

echo -e "${YELLOW}The banners have been updated successfully.${NC}\n"

echo "#######################################"
echo -e "${PURPLE}Configure Command Line Warning Banners Completed${NC}"
echo "#######################################"
echo -e "\n\n\n"
echo "#######################################"
echo -e "${PURPLE}Removing Desktop GDM${NC}"
echo "#######################################"

# Function to remove a package
remove_package() {
  local package=$1
  echo "Attempting to remove $package..."

  # Purge the package
  sudo apt purge -y "$package" > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}Purged $package successfully.${NC}"
  else
    echo -e "${RED}Failed to purge $package. Check logs for details.${NC}"
  fi

  # Autoremove related dependencies
  sudo apt autoremove -y "$package" > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}Removed $package dependencies successfully.${NC}"
  else
    echo -e "${RED}Failed to remove $package dependencies. Check logs for details.${NC}"
  fi
}

# Remove GDM3
remove_package "gdm3"

# Recommendation message
echo -e "The recommendation is to remove ${RED}ANY desktop environment${NC}, but for CIS, just includes removing GDM3."

echo "#######################################"
echo -e "${PURPLE}Removing Desktop GDM Completed${NC}"
echo "#######################################"
echo -e "\n\n\n"

echo "#######################################"
echo -e "${PURPLE}Removing Unneeded Services${NC}"
echo "#######################################"

PACKAGE_LIST=(
  "autofs" "avahi-daemon" "isc-dhcp-server" "bind9" "dnsmasq" "slapd" 
  "dovecot-imapd" "dovecot-pop3d" "nfs-kernel-server" "ypserv" "cups" 
  "rpcbind" "rsync" "samba" "snmpd" "tftpd-hpa" "squid" "apache2" 
  "nginx" "xinetd" "xserver-common" "postfix" "nis" "rsh-client" "talk"
  "telnet" "inetutils-telnet" "ldap-utils" "ftp" "tnftp" "lp"
)

# Function to stop and remove a package
remove_service() {
  local package=$1

  echo -e "Processing ${YELLOW}$package${NC}..."

  # Stop the service if it exists
  if systemctl list-units --type=service --all | grep -q "$package.service"; then
    echo "Stopping $package.service..."
    sudo systemctl stop "$package.service"
    sudo systemctl disable "$package.service"
    echo -e "${GREEN}$package.service stopped and disabled. ${NC}"
  else
    echo -e "${YELLOW}$package.service is not active or does not exist. Skipping stop.${NC}"
  fi

  # Purge the package if installed
  if dpkg-query -s "$package" &>/dev/null; then
    echo "Removing ${YELLOW}$package${NC} package..."
    sudo apt purge -y "$package" > /dev/null
    echo -e "${GREEN}$package package removed successfully.${NC}"
  else
    echo -e "${YELLOW}$package package is not installed. Skipping removal.${NC}"
  fi

  # Autoremove unused dependencies
  sudo apt autoremove -y > /dev/null
}

# Iterate through each package in the list
for package in "${PACKAGE_LIST[@]}"; do
  remove_service "$package"
done

echo "#######################################"
echo -e "${PURPLE}Removing Unneeded Services Completed${NC}"
echo "#######################################"