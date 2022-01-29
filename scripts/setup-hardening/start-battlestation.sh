#!/bin/bash
#
# start-battlestation.sh  Author: An00bRektn, inspired by pimpmykali.sh
# Usage: sudo ./start-battlestation.sh  
#
# You are advised not to use this in a real-world production environment. This is
# for the sole purpose of Red v Blue competitions like CCDC.
#
# Standard Disclaimer: Author assumes no liability for any damage

# a e s t h e t i c
greenplus='\e[1;32m[+]\e[0m'
blueinfo='\e[1;34m[*]\e[0m'
redminus='\e[1;31m[-]\e[0m'
redexclaim='\e[1;31m[!!]\e[0m'
redstar='\e[1;31m[**]\e[0m'
blinkexclaim='\e[1;31m[\e[5;31m!!\e[0m\e[1;31m]\e[0m'
fourblinkexclaim='\e[1;31m[\e[5;31m!!!!\e[0m\e[1;31m]\e[0m'

asciiart=$(base64 -d <<< "H4sIAD5m9GEA/7VQSw5DIQjcewqWmjThQib2/qd4Mww+WHRbXkBxPtCa2WGg4lpRbaDt9eYvJrJ5DDOn3N38DmGwFYOwLUF8vRkjklnoPKTmRjDfODYtwuarWWxTS25BSlRpsi807gHZHiK0lfCpffd64UaCbHLq6sJe+Y3wcGzP/MASQv4YHpiiCYKSBAqqhjdhIWHCxN/yv3gAjMS4Zy0CAAA="  | gunzip )

check_for_root () {
    if [ "$EUID" -ne 0 ]
        then echo -e "\n\n$redexclaim Script must be run with sudo ./start-battlestation.sh or as root \n"
        exit
    fi
}

print_header () {
    echo -e "\e[1;36m$asciiart\e[0m"
    echo -e "\e[1;35mAn00bRektn - https://an00brektn.github.io\e[0m"
    date
    echo
}

print_checklists () {
    echo -e "\n\n  \e[1;33m..aaannnd DONE!\e[0m"
    echo -e "  Because CCDC is scuffed and doesn't give us a chance to look at our stuff, here are the first few things to do:\n
            $blueinfo READ THE RULES\n
            $blueinfo LOCK ROOT ACCOUNT USING sudo usermod -U root (making you do this manually in case this script goes bad).\n
            $blueinfo Identify the necessary services running on the system. Disable any that are not necessary.\n
            $blueinfo Fix the SSH configuration in /etc/ssh/sshd_config\n
            $blueinfo Check the other users that might be on this system and see what they are capable of\n
            $blueinfo Identify any and all files that seem out of order from a typical Linux system\n
            $blueinfo Use our team's repository here: https://github.com/Lewis-Cyber-Defense/mwccdc\n
            $blueinfo Find a hardening guide here: https://security.utexas.edu/os-hardening-checklist\n
            $greenplus There's definitely more things than that, but I can't think of them right now. Good luck!\n
            $blueinfo Happy defending! o7\n
            "
}

print_info () {
    echo -e "$greenplus Printing basic information..."
    echo
    cat /etc/issue && cat /etc/*-release
    uname -a
    for user in $(cat /etc/passwd | cut -f1 -d":"); do id $user; done
}

start_battlestation () {
    echo -e "\n  $greenplus STARTING BATTLESTATION $greenplus\n"
    useradd -m -G sudo -c "Blue Team User" -s /bin/bash blueteam
    echo -e "$blueinfo Please set the blueteam password"
    passwd blueteam
    mkdir /home/blueteam/tools
    chown blueteam:blueteam /home/blueteam/tools
    sudo -u blueteam chmod 0700 /home/blueteam/tools

    # Download some basic stuffs
    wget https://raw.githubusercontent.com/Lewis-Cyber-Defense/mwccdc/main/scripts/enumeration/linux/linpeas.sh -O /home/blueteam/tools/linpeas.sh
    wget https://raw.githubusercontent.com/Lewis-Cyber-Defense/mwccdc/main/scripts/enumeration/linux/LinEnum.sh -O /home/blueteam/tools/LinEnum.sh
    wget https://github.com/Lewis-Cyber-Defense/mwccdc/blob/main/scripts/enumeration/linux/rkhunter-1.4.6.tar.gz?raw=true -O /home/blueteam/tools/rkhunter-1.4.6.tar.gz
    wget https://github.com/Lewis-Cyber-Defense/mwccdc/blob/main/utilities/pspy/pspy64?raw=true -O /home/blueteam/tools/pspy64
    wget https://github.com/Lewis-Cyber-Defense/mwccdc/blob/main/utilities/lynis-3.0.7.zip?raw=true -O /home/blueteam/tools/lynis-3.0.7.zip

    # change ownership
    find /home/blueteam/tools -type f | while read line; do chown blueteam:blueteam $line; sudo -u blueteam chmod 0700 $line; done

}

apt_update() {
    echo -e "\n  $greenplus running: apt update \n"
    eval apt -y update
}

apt_upgrade() {
    echo -e "\n  $greenplus running: apt upgrade \n"
    eval apt -y upgrade
}

print_header
check_for_root
print_info
start_battlestation

apt_update
apt_upgrade

print_checklists