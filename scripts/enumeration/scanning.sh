#!/bin/bash

if ! command -v rustscan &> /dev/null
then
    echo "Rustscan could not be found, using nmap"
    # insert nmap command
else
    echo "Running rustscan"
    ports=$(rustscan -a 'hosts.a' --ulimit 5000 -g | grep -Po '(?<=\[).*(?=\])'| tr '\n' ','| sed 's/.$//')
    echo "Open ports: $ports"
    sudo rustscan -a 'hosts.a' --ulimit 5000 --ports $ports -- -sV -g 53 -Pn --disable-arp-ping -A > scan_results
fi
