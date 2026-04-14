# HTB — Editor (Linux)

## Enumeration

Initial enumeration with `nmap` identified three open TCP ports:

```
22/tcp   OpenSSH 8.9p1 (Ubuntu)
80/tcp   nginx 1.18.0
8080/tcp Jetty 10.0.20
```

Port **80** redirected to `http://editor.htb/`, indicating name-based virtual hosting. Browsing the application revealed a **Docs** link which redirected to:

```
http://wiki.editor.htb/xwiki/bin/view/Main/
```

This instance was hosted on **port 8080** and identified as **XWiki Debian 15.10.8**, running on Jetty. Given the exposed CMS and clear version disclosure, this service became the primary attack surface.

---

## Initial Foothold

Researching known vulnerabilities affecting XWiki 15.10.8 revealed **CVE-2025-24893**, a remote code execution vulnerability. A public proof-of-concept was available and used to target the vulnerable endpoint.

To validate command execution, a simple `ping` payload was sent and successfully captured using `tcpdump`, confirming RCE.

Initial attempts to obtain a reverse shell using standard Bash and Netcat payloads were unsuccessful, likely due to command parsing limitations within the application context. To bypass this, a base64-encoded payload wrapped in braces was used to avoid character interpretation issues, resulting in a successful reverse shell as the **xwiki** user.

---

## Post-Exploitation

With initial access established, local enumeration was performed. Inspecting `/etc/passwd` revealed two relevant users:

```
oliver
root
```

Given the nature of the application, configuration files were searched for credentials. XWiki configuration files were located under `/etc/xwiki/`. Inspecting `hibernate.cfg.xml` revealed database credentials:

```
hibernate.connection.password = theEd1t0rTeam99
```

While switching users locally with `su oliver` failed, the credentials were successfully reused for **SSH authentication**, granting a stable shell as **oliver**.

---

## Privilege Escalation

As user `oliver`, a search for SUID binaries revealed several Netdata-related executables, including:

```
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
```

Further research showed that `ndsudo` is vulnerable to **CVE-2024-32019**, a privilege escalation vulnerability caused by unsafe command execution and improper PATH handling.

The vulnerability allows execution of attacker-controlled binaries when `ndsudo` resolves commands without using absolute paths. By placing a malicious executable earlier in the `PATH`, the vulnerable binary was coerced into executing attacker-controlled code with elevated privileges.

Executing `ndsudo` in this context resulted in a root shell.

---

## Root

A root shell was obtained successfully, and the final flag was retrieved:

```
root@editor:/opt/netdata#
```

---

## Summary

The compromise of **Editor** followed a clear and realistic attack path:

- Publicly exposed CMS vulnerable to remote code execution
- Credential reuse enabling SSH access
- Misconfigured SUID binary allowing PATH hijacking

This machine demonstrates how chaining well-known vulnerabilities and common misconfigurations can lead to full system compromise.
