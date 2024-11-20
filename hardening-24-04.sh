echo "#######################################"
echo "Filesystem Configurations"
echo "#######################################"

# Filesystems to disable
FILESYSTEMS=("cramfs" "freevxfs" "hfs" "hfsplus" "overlayfs" "squashfs" "udf" "jffs2" "usb-storage")

# Configuration files
DISABLED_FS_CONF="/etc/modprobe.d/disabled-fs.conf"
MODPROBE_CONF="/etc/modprobe.d/modprobe.conf"

# Ensure configuration files exist
sudo touch "$DISABLED_FS_CONF" "$MODPROBE_CONF"

# Disable and blacklist filesystems
for FS in "${FILESYSTEMS[@]}"; do
  echo "Disabling and blacklisting $FS..."
  sudo bash -c "echo 'install $FS /bin/false' >> $DISABLED_FS_CONF"
  sudo bash -c "echo 'blacklist $FS' >> $MODPROBE_CONF"
done

echo "#######################################"
echo "Disabled unnecessary filesystems:"
echo "${FILESYSTEMS[*]}"
echo "#######################################"

# Unload filesystem modules from the kernel
echo "Removing unnecessary filesystems from the kernel..."
for FS in "${FILESYSTEMS[@]}"; do
  sudo modprobe -r "$FS" 2>/dev/null || echo "Module $FS is not loaded or already removed."
done

# Disable autofs
echo "Disabling autofs service..."
sudo systemctl stop autofs
sudo systemctl disable autofs
echo "#######################################"
echo "In the extras section I recommend to install the USBGard software, to allow only pre-defined USB devices, to avoid false keyboards or other physical USB attacks"
echo "   "
echo "there are other Filesystems to check, if needed add them to this script, but this covers the CIS Benchmark recommendation"
echo "#######################################"
echo "   "
echo "#######################################"
echo "Filesystem Configuration Completed"
echo "#######################################"
echo "   "
echo "#######################################"
echo "Mount Points Checking"
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
    echo "WARNING: $mount_point is not mounted."
    return
  fi

  # Check if required options are present
  for option in "${required_options[@]}"; do
    if [[ $mount_options == *"$option"* ]]; then
      echo "$mount_point: $option is set."
    else
      echo "WARNING: $mount_point: $option is NOT set!"
    fi
  done
}

# Check if individual partitions exist and validate options
for MNT in "${MOUNTS[@]}"; do
  echo "Checking $MNT..."

  if sudo findmnt -kn "$MNT" &>/dev/null; then
    echo "$MNT is mounted on its own partition."
    check_mount_options "$MNT"
  else
    echo "WARNING: $MNT does not have its own partition."
  fi
done
echo "#######################################"
echo "Mountpoint Check Completed"
echo "#######################################"
echo " "
echo "#######################################"
echo "APT recommendations Checking"
echo "#######################################"
echo "   "
echo " "
echo "This is a manual section of the recommendations for this run:"
echo " sudo apt-cache policy  "
echo "to check the list of repositories and status, additionally run"
echo " sudo apt update && sudo apt upgrade"
echo "to keep the packages and security patches up to date"
echo "On the extras I recommend some autometad tools to help with this" 
echo "IT IS ABSOLUTELY IMPORTANT TO KEEP THE SSYTEM UP TO DATE!!!" 
echo "#######################################"
echo "APT recommendations Completed"
echo "#######################################"
echo " "
echo " "

# Function to check and install required packages
install_apparmor_packages() {
  local packages=("apparmor" "apparmor-utils")
  echo "Checking for required packages: ${packages[*]}"

  for package in "${packages[@]}"; do
    if dpkg -s "$package" &>/dev/null; then
      echo "Package $package is already installed."
    else
      echo "Installing $package..."
      if sudo apt install -y "$package"; then
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
    echo "Updating GRUB to enable AppArmor..."
    sudo sed -i '/^GRUB_CMDLINE_LINUX=/ s/"$/ apparmor=1 security=apparmor"/' /etc/default/grub
    if [[ $? -eq 0 ]]; then
      echo "GRUB updated successfully. Applying changes..."
      sudo update-grub
    else
      echo "Failed to update GRUB configuration."
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
    echo "No active AppArmor profiles found."
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
  echo "Starting MAC Setup"
  echo "#######################################"

  install_apparmor_packages
  configure_grub_for_apparmor
  set_apparmor_profiles_to_complain

  echo "#######################################"
  echo "Mandatory Access Control (MAC) Setup Completed"
  echo "#######################################"
}

# Execute the setup
main_mac_setup