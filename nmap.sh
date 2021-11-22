#!/bin/bash


nmap_func () {

	nmap -p- -vvv -n --min-rate 5000 -T5 $1 $2 -oN ports 1>/dev/null
	

  
	open=$(cat ports | grep "open" | grep -v "Discovered" | awk '{print $1}' | awk -F '/' '{print $1}' | tr '\n' ',')
	closed=$(cat ports | grep "closed" | grep -v "Discovered" | awk '{print $1}' | awk -F '/' '{print $1}' | tr '\n' ',')
	filtered=$(cat ports| grep "filter" | grep -v "Discovered" | awk '{print $1}' | awk -F '/' '{print $1}' | tr '\n' ',')


	echo "Open ports : " ${open::-1}
	echo "Closed ports : " ${closed::-1}
	echo "Filtered ports : " ${filtered::-1}

	nmap -p$open -sC -sV $1 $2 -oN scan

	nmap --script vuln $1 $2 -oN vulns
}

rm scan
rm ports
rm vulns

nmap -p- -vvv -n --min-rate 5000 -T5 $1 -oN ports 2>&1 > err 

output=$(cat err)

echo $output

if [[ "$output" == *"try -Pn"* ]]; then
	nmap_func $1 "-Pn"

else
	nmap_func $1 
fi

rm err