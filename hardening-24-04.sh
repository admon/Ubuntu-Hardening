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
echo -e "${RED}WARNING:${NC} This script is intended for a clean install and should NOT be run on a live server. \n${RED}Running this script on an active server may break critical services.${NC}\n
Run it under your own risk with the awareness and acceptance of the risks \nThis script will start in ${YELLOW}10 Seconds...${NC}\n${RED}Press "c" to cancel${NC}"
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
echo -e "\n\n"
for file in /etc/apt/trusted.gpg.d/*.{gpg,asc} /etc/apt/sources.list.d/*.{gpg,asc}; do
  if [ -f "$file" ]; then
    echo -e "File: $file"
    gpg --list-packets "$file" 2>/dev/null | awk '/keyid/ && !seen[$NF]++ {print "keyid:", $NF}'
    gpg --list-packets "$file" 2>/dev/null | awk '/Signed-By:/ {print "signed-by:", $NF}'
    echo -e
  fi
done
echo -e "\n\n"
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
apply_kernel_hardening "kernel.randomize_va_space" "2" "/etc/sysctl.conf"
apply_kernel_hardening "kernel.yama.ptrace_scope" "2" "/etc/sysctl.conf"
apply_kernel_hardening "fs.suid_dumpable" "0" "/etc/sysctl.conf"

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
#disable built-in MOTD banner:
sudo chmod -x /etc/update-motd.d/*

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
    echo -e "${GREEN}$package.service stopped and disabled.${NC}"
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

# Function to configure time synchronization
configure_timesyncd() {
  echo -e "${BLUE}Setting up systemd-timesyncd as the NTP service...${NC}"

  # Remove chrony if installed
  if dpkg-query -s "chrony" &>/dev/null; then
    echo "Removing Chrony..."
    sudo apt purge -y chrony
    sudo apt autoremove -y
    echo -e "${GREEN}Chrony removed.${NC}"
  else
    echo -e "${YELLOW}Chrony is not installed. Skipping.${NC}"
  fi

  # Backup and configure timesyncd
  if [[ -f /etc/systemd/timesyncd.conf ]]; then
    sudo cp /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.bak
    echo -e "${GREEN}Backup created for /etc/systemd/timesyncd.conf.${NC}"
  fi

  sudo sed -i '/^\[Time\]/a NTP=time-a-wwv.nist.gov time-d-wwv.nist.gov' /etc/systemd/timesyncd.conf
  sudo sed -i '/^\[Time\]/a FallbackNTP=time-b-wwv.nist.gov time-c-wwv.nist.gov' /etc/systemd/timesyncd.conf

  sudo systemctl restart systemd-timesyncd
  sudo systemctl enable --now systemd-timesyncd
  echo -e "${GREEN}Timesyncd configured and enabled.${NC}"
}

# Function to configure cron service
configure_cron() {
  echo -e "${BLUE}Configuring the CRON Service and permissions...${NC}"
  sudo systemctl enable --now cron.service
  sudo systemctl start cron.service

  local cron_dirs=(
    "/etc/crontab" "/etc/cron.hourly/" "/etc/cron.daily/" 
    "/etc/cron.weekly/" "/etc/cron.monthly/" "/etc/cron.d/"
  )

  for dir in "${cron_dirs[@]}"; do
    if [[ -e $dir ]]; then
      sudo chown root:root "$dir"
      sudo chmod og-rwx "$dir"
      echo -e "${GREEN}Permissions set for $dir.${NC}"
    else
      echo -e "${YELLOW}$dir does not exist. Skipping.${NC}"
    fi
  done

  sudo touch /etc/cron.allow
  sudo chown root:root /etc/cron.allow
  echo -e "${GREEN}Cron configuration completed.${NC}"
}

# Main script logic
for package in "${PACKAGE_LIST[@]}"; do
  remove_service "$package"
done

configure_timesyncd
configure_cron

echo "#######################################"
echo -e "${PURPLE}Removing Unneeded Services Completed${NC}"
echo "#######################################"
echo -e "\n\n\n"

echo "#######################################"
echo -e "${PURPLE}Networking Configuration${NC}"
echo "#######################################"

# Function to apply sysctl configurations
apply_sysctl() {
  local key=$1
  local value=$2
  local config_file=$3

  echo "Configuring $key = $value..."
  if ! grep -q "^$key" "$config_file"; then
    echo "$key = $value" | sudo tee -a "$config_file" > /dev/null
  fi

  if sudo sysctl -w "$key=$value"; then
    echo -e "${GREEN}Applied $key = $value.${NC}"
  else
    echo -e "${RED}Failed to apply $key. Check logs for details.${NC}"
  fi
}

# Function to disable modules
disable_module() {
  local module=$1

  echo "Disabling module $module..."
  if ! grep -Pq "^\h*install $module /bin/false" /etc/modprobe.d/*; then
    echo "install $module /bin/false" | sudo tee -a /etc/modprobe.d/disabled.conf > /dev/null
  fi
  if ! grep -Pq "^\h*blacklist $module" /etc/modprobe.d/*; then
    echo "blacklist $module" | sudo tee -a /etc/modprobe.d/blacklist.conf > /dev/null
  fi

  if lsmod | grep -q "$module"; then
    sudo modprobe -r "$module" && echo -e "${GREEN}Unloaded $module.${NC}" || echo -e "${RED}Failed to unload $module.${NC}"
  else
    echo -e "${YELLOW}$module is not loaded.${NC}"
  fi
}

# Disable IPv6
echo "Disabling IPv6..."
apply_sysctl "net.ipv6.conf.all.disable_ipv6" "1" "/etc/sysctl.conf"
apply_sysctl "net.ipv6.conf.default.disable_ipv6" "1" "/etc/sysctl.conf"
apply_sysctl "net.ipv6.conf.lo.disable_ipv6" "1" "/etc/sysctl.conf"

if ! grep -q "ipv6.disable=1" /etc/default/grub; then
  echo "Updating GRUB to disable IPv6 at boot..."
  sudo sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT=/ s/"$/ ipv6.disable=1"/' /etc/default/grub
  sudo update-grub && echo -e "${GREEN}GRUB updated successfully.${NC}" || echo -e "${RED}Failed to update GRUB.${NC}"
else
  echo "GRUB already configured to disable IPv6."
fi

# Disable wireless interfaces
echo "Disabling all wireless interfaces..."
if find /sys/class/net/*/ -type d -name wireless &>/dev/null; then
  wireless_drivers=$(for dir in $(find /sys/class/net/*/ -type d -name wireless | xargs dirname); do basename "$(readlink -f "$dir/device/driver/module")"; done | sort -u)
  for driver in $wireless_drivers; do
    disable_module "$driver"
  done
else
  echo "No wireless interfaces found."
fi

# Disable Bluetooth
echo "Disabling Bluetooth..."
disable_module "bluetooth"
sudo systemctl stop bluetooth.service
sudo systemctl disable bluetooth.service
sudo apt purge -y bluez && echo -e "${GREEN}Bluetooth packages removed.${NC}" || echo -e "${RED}Failed to remove Bluetooth packages.${NC}"

# Disable unnecessary protocols
echo "Disabling unnecessary protocols..."
protocols=("dccp" "tipc" "rds" "sctp")
for proto in "${protocols[@]}"; do
  disable_module "$proto"
done

# Configure sysctl for network parameters
echo "Applying network hardening configurations..."
sysctl_params=(
  "net.ipv4.ip_forward=0"
  "net.ipv6.conf.all.forwarding=0"
  "net.ipv4.conf.all.send_redirects=0"
  "net.ipv4.conf.default.send_redirects=0"
  "net.ipv4.icmp_ignore_bogus_error_responses=1"
  "net.ipv4.icmp_echo_ignore_broadcasts=1"
  "net.ipv4.conf.all.accept_redirects=0"
  "net.ipv4.conf.default.accept_redirects=0"
  "net.ipv6.conf.all.accept_redirects=0"
  "net.ipv6.conf.default.accept_redirects=0"
  "net.ipv4.conf.all.secure_redirects=0"
  "net.ipv4.conf.default.secure_redirects=0"
  "net.ipv4.conf.all.rp_filter=1"
  "net.ipv4.conf.default.rp_filter=1"
  "net.ipv6.conf.all.accept_source_route=0"
  "net.ipv6.conf.default.accept_source_route=0"
  "net.ipv4.conf.all.log_martians=1"
  "net.ipv4.conf.default.log_martians=1"
  "net.ipv4.tcp_syncookies=1"
  "net.ipv6.conf.all.accept_ra=0"
  "net.ipv6.conf.default.accept_ra=0"
)

for param in "${sysctl_params[@]}"; do
  key=${param%%=*}
  value=${param##*=}
  apply_sysctl "$key" "$value" "/etc/sysctl.conf"
done

echo -e "${YELLOW}Reminder:${NC} UFW may override sysctl changes. Check ${YELLOW}/etc/default/ufw${NC} for IPT_SYSCTL configuration."

echo "#######################################"
echo -e "${PURPLE}Networking Configuration Completed${NC}"
echo "#######################################"
echo -e "\n\n\n"
echo "#######################################"
echo -e "${Blue}ACcess Control${NC}"
echo "#######################################"
echo -e "\n\n\n"
echo "#######################################"
echo -e "${PURPLE}Configure SSH Server${NC}"
echo "#######################################"

# Backup and secure configuration files
backup_and_secure() {
  local file=$1
  if [[ -f "$file" ]]; then
    # Backup the file if not already backed up
    if [[ ! -f "${file}.bkp" ]]; then
      sudo cp "$file" "${file}.bkp"
      echo -e "${GREEN}Backup created for $file.${NC}"
    else
      echo -e "${YELLOW}Backup already exists for $file. Skipping backup.${NC}"
    fi

    # Set secure permissions
    sudo chmod u-x,og-rwx "$file"
    sudo chown root:root "$file"
    echo -e "${GREEN}Permissions updated for $file.${NC}"
  else
    echo -e "${RED}$file not found. Skipping.${NC}"
  fi
}

# Apply secure permissions to SSH configuration files
echo "Securing SSH configuration files..."
backup_and_secure "/etc/ssh/sshd_config"
if [[ -d /etc/ssh/sshd_config.d ]]; then
  for conf in /etc/ssh/sshd_config.d/*.conf; do
    backup_and_secure "$conf"
  done
fi

# Set up new SSH configuration
echo "Configuring SSH server settings..."
SSH_CONF=$(cat << 'EOF'
Include /etc/ssh/sshd_config.d/*.conf
LogLevel VERBOSE
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
IgnoreRhosts yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
TCPKeepAlive no
PermitUserEnvironment no
ClientAliveCountMax 2
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
LoginGraceTime 60
MaxStartups 10:30:60
ClientAliveInterval 15
Banner /etc/issue.net
Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com
DisableForwarding yes
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com
PermitUserEnvironment no
EOF
)

echo "$SSH_CONF" | sudo tee /etc/ssh/sshd_config > /dev/null
echo -e "${GREEN}New SSH configuration applied.${NC}"

# Add current user to AllowUsers
CURRENT_USER=$SUDO_USER
if ! grep -q "^AllowUsers.*\b$CURRENT_USER\b" /etc/ssh/sshd_config; then
  echo "AllowUsers $CURRENT_USER" | sudo tee -a /etc/ssh/sshd_config > /dev/null
  echo -e "${GREEN}Added $CURRENT_USER to AllowUsers.${NC}"
else
  echo -e "${YELLOW}$CURRENT_USER is already listed in AllowUsers.${NC}"
fi
echo -e "${GREEN}Restarting the SSH services...${NC}"
sudo systemctl restart ssh > /dev/null
sudo systemctl enable ssh > /dev/null

echo "#######################################"
echo -e "${PURPLE}Configure SSH Server Completed${NC}"
echo "#######################################"
echo -e "\n\n\n"
echo "#######################################"
echo -e "${PURPLE}Configure provilege Escalation${NC}"
echo "#######################################"
echo "Installing Sudo"
apt install sudo > /dev/null 2>&1

 # Define the visudo file path 
sudoers_file="/etc/sudoers"
 # Backup the original sudoers file
sudo cp $sudoers_file "${sudoers_file}.bak" 
 # Check if "Defaults use_pty" exists in the sudoers file 
if sudo grep -q "^Defaults use_pty" $sudoers_file; then 
echo '"Defaults use_pty" already exists in the sudoers file.' 
else 
# Add "Defaults use_pty" to the sudoers file 
echo "Defaults use_pty" | sudo tee -a $sudoers_file > /dev/null 
echo '"Defaults use_pty" has been added to the sudoers file.' 
fi 
# Check if "Defaults logfile=\"/var/log/sudo.log\"" exists in the sudoers file 
if sudo grep -q "^Defaults logfile=\"/var/log/sudo.log\"" $sudoers_file; then 
echo '"Defaults logfile=\"/var/log/sudo.log\"" already exists in the sudoers file.' 
else 
# Add "Defaults logfile=\"/var/log/sudo.log\"" to the sudoers file 
echo 'Defaults logfile="/var/log/sudo.log"' | sudo tee -a $sudoers_file > /dev/null 
echo '"Defaults logfile=\"/var/log/sudo.log\"" has been added to the sudoers file.' 
fi

sudo sed -i '/!authenticate/d' $sudoers_file 
sudo sed -i '/NOPASSWD/d' $sudoers_file

# Validate the sudoers file 
sudo visudo -c 
echo "#######################################"
echo -e "${PURPLE}Configure provilege Escalation Completed${NC}"
echo "#######################################"
echo -e "\n\n\n"
echo "#######################################"
echo -e "${PURPLE}PAM Modules${NC}"
echo "#######################################"
sudo apt install libpam-pwquality > /dev/null 2>&1

# # Backup the original PAM configuration files
# sudo cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak
# sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.bak

# # Enable pam_pwhistory
# echo "session     required     pam_pwhistory.so" | sudo tee -a /etc/pam.d/common-auth

# # Enable pam_faillock
# echo "auth        required      pam_faillock.so preauth silent deny=5 unlock_time=900" | sudo tee -a /etc/pam.d/common-auth
# echo "auth        required      pam_faillock.so authfail deny=5 unlock_time=900" | sudo tee -a /etc/pam.d/common-auth
# echo "session     required      pam_faillock.so postauth silent deny=5 unlock_time=900" | sudo tee -a /etc/pam.d/common-auth

# # Enable pam_pwquality
# echo "password    requisite     pam_pwquality.so retry=3 minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" | sudo tee -a /etc/pam.d/common-password

# # Validate the PAM configuration
# sudo pam-auth-update --force 
# sudo systemctl restart systemd-logind

echo -e "${RED}THIS REQUIRES A LOT MORE OF CONFIGURATION! IT IS INCOMPLETE${NC}"
echo "#######################################"
echo -e "${PURPLE}PAM Modules Completed${NC}"
echo "#######################################"

echo "#######################################"
echo -e "${PURPLE}User Accounts and Environment${NC}"
echo "#######################################"
echo "Configuring Password practices for regular users..."
# Backup the original /etc/login.defs file
sudo cp /etc/login.defs /etc/login.defs.bak

# Modify the values in /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

# Ensure ENCRYPT_METHOD is set to SHA512
if grep -q "^ENCRYPT_METHOD" /etc/login.defs; then
  sudo sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
else
  echo "ENCRYPT_METHOD SHA512" | sudo tee -a /etc/login.defs > /dev/null
fi

# Get current date in seconds since 1970-01-01
current_date=$(date +%s)

# Update password expiration policies for all human users
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
  # Get the last password change date in seconds since 1970-01-01
  last_change_date=$(sudo chage -l $user | grep "Last password change" | awk -F": " '{print $2}' | xargs -I{} date -d {} +%s)

  # Check if the last password change date is in the future
  if [ "$last_change_date" -gt "$current_date" ]; then
    echo -e "The last password change date for ${RED}$user is in the future. Forcing a password reset.${NC}"
    sudo chage -d 0 $user
  fi

  # Apply password policies
  sudo chage --mindays 1 $user
  sudo chage --maxdays 365 $user
  sudo chage --warndays 7 $user
  sudo chage --inactive 30 $user
  sudo useradd -D -f 30 #this enable a default INACTIVE lock account of 45 days
done

echo "The password policies have been applied to all users. Password reset has been forced for users with future last password change dates."
echo "Configuring Password practices for System Accounts..."
echo "#######################################"
echo -e "${PURPLE}User Accounts and Environment Completed${NC}"
echo "#######################################"

