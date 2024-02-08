#!/bin/bash

# Checks for/creates initial user file
if ! [ -f "usersover1000" ]; 
then
	cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > usersover1000
fi
initial_users=$(cat usersover1000)
echo "Started at $(date '+%Y-%m-%d %H:%M:%S')"
# Main loop
while :; do
	echo
	current_users=$(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
	# Compares current users to initial user file
	if [ "$current_users" != "$initial_users" ]; then
	    alert_time=$(date "+%Y-%m-%d %H:%M:%S")
    	    echo -e "[$alert_time] ALERT: There have been changes to the user configuration on the system!"
	    cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > modified_users
	    echo "$(diff modified_users usersover1000)"
	fi
	sleep 60
	if ! [ -f "modified_users" ];
	then
		rm modified_users
	fi
done
