#!/bin/bash

ports=$(nmap -p- -vvv -n --min-rate 5000 -T5 $1 -oN ports | grep "open" | grep -v "Discovered" | awk '{print $1}' | awk -F '/' '{print $1}' | tr '\n' ',')


# Taking last character
new_ports=${ports::-1}

nmap -p$ports -sC -sV $1 -oN scan

nmap --script vuln $1 -oN vulns