#!/bin/bash

# # Define variables
# steamPath="/home/${svc_account}/Steam"
# valheimPath="$steamPath/valheim"


### START INSTANCE BOOTSTRAP ###

# Override echo to print a new line then the echo message with a date time stamp and light green color
function echo(){

    builtin echo ""
    builtin echo -e "\e[92m $(date '+%F %T %z %Z') --- $1 \e[0m"

}

# Configure script to log console output to a log file
# tail -f /var/log/terraform-bootstrap.log to monitor startup progress
exec > >(sudo tee -ia /var/log/terraform-bootstrap.log)
exec 2>&1

# Write start to log
echo "Starting `dirname "$0"`/`basename "$0"` from `pwd`"


## Change time zone

# Change time zone
echo "Change time zone - sudo timedatectl set-timezone America/Edmonton"
sudo timedatectl set-timezone America/Edmonton

# Show time zone
echo "Show time zone - timedatectl"
timedatectl


# # Update 
# echo "Update - sudo apt-get update"
# sudo apt-get update

# echo "Update - sudo apt-get -y upgrade"
# sudo apt-get -y upgrade

# Install SAR and ATOP
echo "Install SAR and ATOP - sudo apt-get -y install atop sysstat"
sudo apt-get -y install atop sysstat


# Change the log collection interval and configure sysstat to report disk and inodes usage by adding -S XALL in the configuration file
echo "Change the log collection interval and configure sysstat to report disk and inodes usage by adding -S XALL in the configuration file"
sudo sed -i 's/^LOGINTERVAL=600.*/LOGINTERVAL=60/' /usr/share/atop/atop.daily
sudo sed -i -e 's|5-55/10|*/1|' -e 's|every 10 minutes|every 1 minute|' -e 's|debian-sa1|debian-sa1 -S XALL|g' /etc/cron.d/sysstat
sudo bash -c "echo 'SA1_OPTIONS=\"-S XALL\"' >> /etc/default/sysstat"

# Enable and restart services
echo "Enable and restart services"
sudo sed -i 's|ENABLED="false"|ENABLED="true"|' /etc/default/sysstat
sudo systemctl enable atop.service cron.service sysstat.service
sudo systemctl restart atop.service cron.service sysstat.service


# ## Set vm.overcommit limits to stop Valheim service from shitting itself

# # Log starting sysctl.conf
# echo "Log starting sysctl.conf - sudo cat /etc/sysctl.conf"
# sudo cat /etc/sysctl.conf

# # Append vm.overcommit configs to sysctl.conf
# echo "Append vm.overcommit configs to sysctl.conf - sudo tee -ia /etc/sysctl.conf &>/dev/null"
# sudo tee -ia /etc/sysctl.conf &>/dev/null <<EOF
# vm.overcommit_ratio=100
# vm.overcommit_memory=2
# EOF

# # Verify sysctl.conf
# echo "Verify sysctl.conf - sudo cat /etc/sysctl.conf"
# sudo cat /etc/sysctl.conf


## Add my customizations to .bashrc

# Show original .bashrc
echo "Show original .bashrc - cat /home/ubuntu/.bashrc"
cat /home/ubuntu/.bashrc

# Append command aliases and bash history time format to .bashrc
echo "Append command aliases and bash history time format - cat >> /home/ubuntu/.bashrc"
cat >> /home/ubuntu/.bashrc <<EOF
alias c='clear'
alias l='ls -hAl --full-time'
alias p='pwd'
export HISTTIMEFORMAT="%F %T %z %Z $ "
export PS1="\[\e[36;1m\][\D{%F %T}] [\w]\[\e[0m\] $ "
EOF

# Verify the change to .bashrc
echo "Verify the change to .bashrc - cat /home/ubuntu/.bashrc"
cat /home/ubuntu/.bashrc


# Ping to validate internet connectivity
echo "Ping to validate internet connectivity - ping -c 3 -W 3 google.com"
ping -c 3 -W 3 google.com


# ### START APP INSTALLATION AND CONFIGURATION ###

# ## Service account

# # Create Valheim service account
# # Need to run commands with sudo -u ${svc_account} to run them as the service user
# echo "Create Valheim service account - sudo useradd --system --user-group --shell /sbin/nologin --create-home ${svc_account}"
# sudo useradd --system --user-group --shell /sbin/nologin --create-home ${svc_account}
# echo "Disable the service account from being able to log in - sudo usermod -L ${svc_account}"
# sudo usermod -L ${svc_account}

# # Verify the service account is usable
# echo "Verify the service account is usable - sudo -u ${svc_account} whoami"
# sudo -u ${svc_account} whoami

# # Make the Steam directory
# echo "Make the Steam directory - sudo -u ${svc_account} mkdir $steamPath"
# sudo -u ${svc_account} mkdir $steamPath

# # Show the Steam directory was made
# echo "Show the Steam directory was made - sudo -u ${svc_account} ls -al --full-time $steamPath"
# sudo -u ${svc_account} ls -al --full-time $steamPath


# ## Download and install packages

# # # Install pre-requisite packages for Steam
# # echo "Install pre-requisite packages for Steam - sudo yum install -y glibc.i686 libstdc++.i686"
# # sudo yum install -y glibc.i686 libstdc++.i686


# # # Install Valheim server
# # echo "Install Valheim server - sudo -u ${svc_account} $steamPath/steamcmd.sh +login anonymous +force_install_dir $valheimPath +app_update 896660 validate +quit"
# # sudo -u ${svc_account} $steamPath/steamcmd.sh +login anonymous +force_install_dir $valheimPath +app_update 896660 validate +quit



# # Install dependencies
# echo "Install dependencies"
# sudo dpkg --add-architecture i386
# sudo apt-get update
# sudo apt-get install -y curl wget file tar bzip2 gzip unzip bsdmainutils python util-linux ca-certificates binutils bc jq tmux netcat lib32gcc1 lib32stdc++6

# # Download steamcmd
# echo "Download steamcmd - sudo -u ${svc_account} wget -P $steamPath http://media.steampowered.com/installer/steamcmd_linux.tar.gz"
# sudo -u ${svc_account} wget -P $steamPath http://media.steampowered.com/installer/steamcmd_linux.tar.gz

# # Untar steamcmd
# echo "Untar steamcmd - sudo -u ${svc_account} tar -xvzf $steamPath/steamcmd_linux.tar.gz -C $steamPath"
# sudo -u ${svc_account} tar -xvzf $steamPath/steamcmd_linux.tar.gz -C $steamPath

# # Show the untarred files
# echo "Show the untarred files - sudo -u ${svc_account} ls -hAl --full-time $steamPath"
# sudo -u ${svc_account} ls -hAl --full-time $steamPath

# # Install and update steamcmd
# echo "Install and update steamcmd - sudo -u ${svc_account} $steamPath/steamcmd.sh +quit"
# sudo -u ${svc_account} $steamPath/steamcmd.sh +quit

# # Install LinuxGSM
# echo "Install LinuxGSM"
# sudo -u ${svc_account} wget -O /home/${svc_account}/linuxgsm.sh https://linuxgsm.sh 
# sudo -u ${svc_account} chmod +x /home/${svc_account}/linuxgsm.sh
# sudo -u ${svc_account} bash /home/${svc_account}/linuxgsm.sh vhserver

# # Download game data files from S3 bucket
# echo "Download game data files from S3 bucket - sudo -u ${svc_account} aws s3 cp s3://${game-data-bucket-name}/ /home/${svc_account}/.config/unity3d/IronGate/Valheim/worlds/ --recursive"
# sudo -u ${svc_account} aws s3 cp s3://${game-data-bucket-name}/ /home/${svc_account}/.config/unity3d/IronGate/Valheim/worlds/ --recursive

# # Show downloaded game data files from S3 bucket
# echo "Show downloaded game data files from S3 bucket - sudo -u ${svc_account} ls -hal --full-time /home/${svc_account}/.config/unity3d/IronGate/Valheim/worlds/"
# sudo -u ${svc_account} ls -hal --full-time /home/${svc_account}/.config/unity3d/IronGate/Valheim/worlds/


# ## Create custom Valheim server startup script

# # Create start_server_custom.sh
# echo "Create start_server_custom.sh - sudo -u ${svc_account} tee -a $valheimPath/start_server_custom.sh"
# sudo -u ${svc_account} tee -a $valheimPath/start_server_custom.sh &>/dev/null <<EOF
# #!/bin/bash
# export templdpath=\$LD_LIBRARY_PATH
# export LD_LIBRARY_PATH=./linux64:\$LD_LIBRARY_PATH
# export SteamAppId=892970

# # Sync game files from S3 bucket to instance before the game service starts
# aws s3 sync s3://${game-data-bucket-name}/ /home/${svc_account}/.config/unity3d/IronGate/Valheim/worlds/

# ./valheim_server.x86_64 -name ${valheim-server-display-name} -password ${valheim-server-world-password} -public ${valheim-server-public} -world ${valheim-server-world-name} -port 2456 -nographics -batchmode

# # Sync game files back to S3 bucket if the game service stops
# # aws s3 sync /home/${svc_account}/.config/unity3d/IronGate/Valheim/worlds/ s3://${game-data-bucket-name}/

# export LD_LIBRARY_PATH=\$templdpath

# EOF

# # Show start_server_custom.sh
# echo "Show start_server_custom.sh - sudo -u ${svc_account} cat $valheimPath/start_server_custom.sh"
# sudo -u ${svc_account} cat $valheimPath/start_server_custom.sh

# # Make start_server_custom.sh executable
# echo "Make start_server_custom.sh executable - sudo chmod +x $valheimPath/start_server_custom.sh"
# sudo chmod +x $valheimPath/start_server_custom.sh

# # Show start_server_custom.sh is executable
# echo "Show start_server_custom.sh is executable - sudo -u ${svc_account} ls -Al --full-time $valheimPath/"
# sudo -u ${svc_account} ls -Al --full-time $valheimPath/


# ## Create Valheim service

# # Create a service to run start_server_custom.sh
# echo "Create a service to run start_server_custom.sh - cat > /etc/systemd/system/valheim.service"
# cat > /etc/systemd/system/valheim.service <<EOF
# [Unit]
# Description=Valheim Server
# Wants=network-online.target
# After=syslog.target network.target nss-lookup.target network-online.target

# [Service]
# Type=simple
# Restart=always
# RestartSec=30
# StartLimitInterval=0s
# StartLimitBurst=10
# User=${svc_account}
# Group=${svc_account}
# ExecStartPre=-$steamPath/steamcmd.sh +login anonymous +force_install_dir $valheimPath +app_update 896660 validate +quit
# ExecStart=$valheimPath/start_server_custom.sh
# ExecReload=/bin/kill -s HUP $MAINPID
# KillSignal=SIGINT
# WorkingDirectory=$valheimPath
# LimitNOFILE=100000

# [Install]
# WantedBy=multi-user.target

# EOF

# # Show the service
# echo "Show the service - cat /etc/systemd/system/valheim.service"
# cat /etc/systemd/system/valheim.service

# # Reload daemons after creating service
# echo "Reload daemons after creating service - systemctl daemon-reload"
# systemctl daemon-reload

# # Enable service to start on boot
# echo "Enable service to start on boot - systemctl enable valheim"
# systemctl enable valheim

# # Show service status
# echo "Show service status - systemctl status valheim"
# systemctl status valheim


# ## Create script to check service logs, so I don't have to remember the command

# # Create service log checking script in ubuntu's home dir
# echo "Create service log checking script in ubuntu's home dir - sudo -u ubuntu tee -a /home/ubuntu/check_valheim_service_log.sh"
# sudo -u ubuntu tee -a /home/ubuntu/check_valheim_service_log.sh &>/dev/null <<EOF
# #!/bin/bash

# sudo journalctl --all --output=short-iso --unit=valheim --since="-2h" --follow \
#   | grep --line-buffered --invert-match "Filename: ./Runtime/Export" \
#   | gawk '{ $2=""; print; system("") }' \
#   | sed -u 's/\([0-9]\{4\}-[0-9][0-9]-[0-9][0-9]\)T\([0-9][0-9]:[0-9][0-9]:[0-9][0-9]\)/\1   \2/' \
#   | sed -u 's/-\([0-9]\{4\}\)/ /' \
#   | sed -u 's/: /   /' \
#   | sed -uE 's~([0-9]{1,2}/){2}[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}: *~~'

# EOF

# # Show the service log checking script
# echo "Show the service log checking script - sudo -u ubuntu cat /home/ubuntu/check_valheim_service_log.sh"
# sudo -u ubuntu cat /home/ubuntu/check_valheim_service_log.sh

# # Make the service log checking script executable
# echo "Make the service log checking script executable - sudo chmod +x /home/ubuntu/check_valheim_service_log.sh"
# sudo chmod +x /home/ubuntu/check_valheim_service_log.sh

# # Show the service log checking script is executable
# echo "Show the service log checking script is executable - sudo -u ubuntu ls -Al --full-time /home/ubuntu/"
# sudo -u ubuntu ls -Al --full-time /home/ubuntu/


# # ## Enable persistent log storage for journalctl
# # May not be needed, as Amazon Linux 2 has /var/log/journal/ in place
# # https://www.digitalocean.com/community/tutorials/how-to-use-journalctl-to-view-and-manipulate-systemd-logs

# # # Log starting journalctl config
# # echo "Log starting journalctl config - sudo cat /etc/systemd/journald.conf"
# # sudo cat /etc/systemd/journald.conf

# # # Append Storage=persistent to journalctl config
# # echo "Append Storage=persistent to journalctl config - sudo tee -ia /etc/systemd/journald.conf &>/dev/null"
# # sudo tee -ia /etc/systemd/journald.conf &>/dev/null <<EOF
# # Storage=persistent
# # EOF

# # # Verify journalctl config
# # echo "Verify journalctl config - sudo cat /etc/systemd/journald.conf"
# # sudo cat /etc/systemd/journald.conf


# ## Keep journalctl logs down to max 1 GB
# # Log starting journalctl config
# echo "Log starting journalctl config - sudo cat /etc/systemd/journald.conf"
# sudo cat /etc/systemd/journald.conf

# # Append SystemMaxUse=1G to journalctl config
# echo "Append SystemMaxUse=1G to journalctl config - sudo tee -ia /etc/systemd/journald.conf &>/dev/null"
# sudo tee -ia /etc/systemd/journald.conf &>/dev/null <<EOF
# SystemMaxUse=1G
# EOF

# # Verify journalctl config
# echo "Verify journalctl config - sudo cat /etc/systemd/journald.conf"
# sudo cat /etc/systemd/journald.conf


# # ## Sync game files to S3 every 5 minutes

# # # Log starting crontab config
# # echo "Log starting crontab config - sudo -u ${svc_account} crontab -l"
# # sudo -u ${svc_account} crontab -l

# # # Write out current crontab to crontemp
# # echo "Write out current crontab to crontemp - sudo -u ${svc_account} crontab -l > $valheimPath/AWSS3SyncCronTemp"
# # sudo -u ${svc_account} crontab -l | sudo -u ${svc_account} tee -a $valheimPath/AWSS3SyncCronTemp

# # # Append new cronjob to crontemp
# # echo "Append new cronjob to crontemp - sudo -u ${svc_account} tee -a $valheimPath/AWSS3SyncCronTemp"
# # sudo -u ${svc_account} tee -a $valheimPath/AWSS3SyncCronTemp &>/dev/null <<EOF
# # */5 * * * * /usr/bin/aws s3 sync /home/${svc_account}/.config/unity3d/IronGate/Valheim/worlds/ s3://${game-data-bucket-name}/
# # EOF

# # # Install crontemp
# # echo "Install crontemp - sudo -u ${svc_account} crontab $valheimPath/AWSS3SyncCronTemp"
# # sudo -u ${svc_account} crontab $valheimPath/AWSS3SyncCronTemp

# # # Verify crontab config
# # echo "Verify crontab config - sudo -u ${svc_account} crontab -l"
# # sudo -u ${svc_account} crontab -l


# ## Reboot

# # Reboot to finish installing updates, and service will come online after reboot
# echo "Reboot to finish installing updates, and service will come online after reboot - sudo shutdown -r now"
# sudo shutdown -r now
