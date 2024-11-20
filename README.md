# Ubuntu-Hardening
Ubuntu 24.04 bash script for a initial hardening of a clean system

 this script will be divided on 3 areas:

## System Hardening and CIS 24.04 recommendations
I'm working on automating the recommendations from the CIS Benchmark related to this OS version, some on the things in place are:
- SSH Hardening (basic recommendations are there but I prefer to do some extra settings, but I recommend, above all, to setup the SSH Key files for Auth, and Google MFA, obviusly no password of any type allowed)
- Disable unnecesary fylesystem
- Disable USB (I prefer to use USBGuard and allow only the devices needed, but there is the option to completely disable USB storage)
- Disable IPv6 Stack and IPv4 Routing
- NTPd for Time Sync
- Enable and basic config of UFW (please note that if you are running docker containers, UFW WILL NOT TAKE EFFECT, and you will need to modify the IPTables.
- Enable Auditd and implement rules (based on the UK GOV github link with a little clean on some issues with a couple of rules)

## Additional Software and Recommendations (Personal options I want/need for my education porpuses.)
- Wazuh as a HIDS (either this be the server or install the agent), OSSEC is great but WAZUH has so many options and benefits that has my absolute preference.
  - Wazuh for File Integrity (need configuration on the agent file to indicate location of files), AIDE helps but having Wazuh is redundant
  - Wazuh as Threat Hunting (SIEM but also install Splunk in Docker for practice),
  - Wazuh as Vulnerability Scanner (it scans the OS for current software vulanerable and provide references to the CVSS) but Nessus, OpenVAS and Kali are a must.
- Webmin for easy administration (not all heroes use only CLI, others can benefit from a nice GUI)
- Lynis for review auditing results (really helpfull when starting on CyberSec and Hardening Ubuntu, quite a challenge to reach the 90 score...)
- ClamAV and Maldetect for Malware Detection (ClamAV helps but Maldetect is the key here...)
- Chkroot and rkhunter for Rootkit Detection 
- Docker for containerazition of Apps (before and after, using this has opened so many doors on lab setup, automatization and availability! great technology.)

## CyberSec Lab Setup
This section is currently for my CyberSec Lab, including other software such as 
- Suricata as NIDS/NIPS
- Docker images for MISP, Splunk, Nessus, Kali and more
- Python for quick scripts, VSCode on Web, and API setup
- Honeypots 
