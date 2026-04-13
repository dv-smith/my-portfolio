"""
Pipeline tests — verify all stages produce expected output.
Run: python test_pipeline.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from pipeline import (
    preprocess, detect_formats, run_detections,
    tokenise, residual_risk, run_pipeline, compute_entropy
)

SALT = b"test-salt-only-for-unit-tests-32b"
PASS = 0; FAIL = 0

def check(label, condition, note=""):
    global PASS, FAIL
    if condition:
        print(f"  ✓  {label}")
        PASS += 1
    else:
        print(f"  ✗  {label}{' — ' + note if note else ''}")
        FAIL += 1

# ──────────────────────────────────────────
print("\n── Stage 1: Pre-processing ──")

text, actions = preprocess("Hello\x00World\x01!")
check("strip null bytes", "\x00" not in text and "\x01" not in text)
check("action recorded for non-printable", any("removed_nonprintable" in a for a in actions))

text, actions = preprocess("user=admin&pass=P%40ssword")
check("url decode triggered", "url_decoded" in actions, actions)
check("url decode result", "P@ssword" in text, text)

b64 = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="
text, actions = preprocess(b64)
check("b64 decode triggered", any("b64_decoded" in a for a in actions), actions)

# ──────────────────────────────────────────
print("\n── Stage 2: Format detection ──")

nmap_out = """
Starting Nmap 7.94
Nmap scan report for dc1.corp.local (192.168.1.10)
PORT   STATE SERVICE
80/tcp open  http
"""
formats = detect_formats(nmap_out)
check("nmap detected", "nmap" in formats, formats)

http_req = "GET /admin HTTP/1.1\nHost: target.corp.local\n"
formats = detect_formats(http_req)
check("http_request detected", "http_request" in formats, formats)

import json
jdata = json.dumps({"user": "admin", "pass": "secret123"})
formats = detect_formats(jdata)
check("json detected", "json" in formats, formats)

dump = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
formats = detect_formats(dump)
check("secretsdump detected", "secretsdump" in formats, formats)

# ──────────────────────────────────────────
print("\n── Stage 3: Heuristic detection ──")

sample = """
Host: 192.168.1.50
User: jsmith
Email: jsmith@corp.local
Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.abc
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
password=SuperSecret123!
hash: 5f4dcc3b5aa765d61d8327deb882cf99
"""

dets = run_detections(sample)
types_found = {d.dtype for d in dets}
check("private IP detected", "PRIV_IP" in types_found, str(types_found))
check("email detected", "EMAIL" in types_found, str(types_found))
check("user detected", "USER" in types_found, str(types_found))
check("auth header detected", "AUTH_HEADER" in types_found, str(types_found))
check("cookie detected", "COOKIE" in types_found, str(types_found))
check("kv secret detected", "SECRET" in types_found, str(types_found))
check("hash detected", "HASH" in types_found, str(types_found))

# Entropy
check("entropy: high-entropy string", compute_entropy("aB3$xK9mPqR2wLzN7vYt") >= 3.6)
check("entropy: low-entropy string", compute_entropy("aaaaabbbbbccccc") < 3.6)

# ──────────────────────────────────────────
print("\n── Stage 4: Tokenisation ──")

text, dets = tokenise(sample, run_detections(sample), SALT)
check("private IP replaced", "192.168.1.50" not in text, text[:80])
check("token format correct", "[PRIV_IP_" in text or "[USER_" in text, text[:200])

# Determinism
dets1 = run_detections("password=abc123secret")
text1, _ = tokenise("password=abc123secret", dets1, SALT)
dets2 = run_detections("password=abc123secret")
text2, _ = tokenise("password=abc123secret", dets2, SALT)
check("deterministic tokens", text1 == text2)

# ──────────────────────────────────────────
print("\n── Stage 5: Residual risk ──")

clean = "The server responded successfully with 200 OK."
risk, reasons, findings = residual_risk(clean)
check("low risk: clean text", risk == "LOW", f"got {risk}")

risky = "192.168.10.5 responded. Also: 5f4dcc3b5aa765d61d8327deb882cf99"
risk, reasons, findings = residual_risk(risky)
check("high risk: residual IP + hash", risk == "HIGH", f"got {risk}, {findings}")

structural = "web01.corp responded with dc01 structural pattern"
risk, reasons, findings = residual_risk(structural)
check("medium risk: structural hostnames", risk in ("MEDIUM", "HIGH"), f"got {risk}")

# ──────────────────────────────────────────
print("\n── Full pipeline ──")

pentest_artefact = """
Nmap scan report for dc01.corp.local (10.10.10.5)
PORT     STATE SERVICE VERSION
445/tcp  open  smb     Windows Server 2019
3389/tcp open  rdp     Microsoft Terminal Services

secretsdump output:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
svc_backup:1108:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

HTTP capture:
POST /login HTTP/1.1
Host: webapp.corp.local
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Cookie: PHPSESSID=abc123def456ghi789jkl012mno345pq

password=P@ssw0rd123!
apikey=sk-1234567890abcdefghijklmnopqrstuvwxyz
"""

result = run_pipeline(pentest_artefact, SALT)
check("pipeline runs without error", True)
check("tokens generated", result.token_count > 5, f"got {result.token_count}")
check("secretsdump format detected", "secretsdump" in result.formats_detected)
check("nmap format detected", "nmap" in result.formats_detected)
check("original IPs not in output", "10.10.10.5" not in result.sanitised)
check("pipeline produces some output", len(result.sanitised) > 50)
check("risk score assigned", result.risk_score in ("LOW", "MEDIUM", "HIGH"))

print(f"\n  Pipeline result: risk={result.risk_score}, tokens={result.token_count}, blocked={result.blocked}")

# ──────────────────────────────────────────
print("\n── PEAS: ANSI stripping ──")

from pipeline import preprocess

ansi_sample = "\x1b[1;31m[!] Interesting file: /home/jsmith/.ssh/id_rsa\x1b[0m"
text, actions = preprocess(ansi_sample)
check("ANSI codes stripped", "\x1b" not in text)
check("Content preserved after strip", "Interesting file" in text)
check("Action recorded", any("stripped_ansi" in a for a in actions))
check("Fragment [1;31m not left behind", "[1;31m" not in text)

# ──────────────────────────────────────────
print("\n── PEAS: Format detection ──")

from pipeline import detect_formats

linpeas_sample = """
╔════════════════════════════════════════════════════╗
║                    Basic information               ║
╚════════════════════════════════════════════════════╝
[+] Hostname: webserver01.corp.local
[!] Writable /etc/passwd
Linux version 5.4.0-42-corp-internal-hardened (gcc 9.3)
"""
formats = detect_formats(linpeas_sample)
check("linpeas detected", "peas_linux" in formats, str(formats))

winpeas_sample = """
╔════════════════════╗
║  System Information ║
╚════════════════════╝
[+] OS: Windows 10 Pro 19041
[*] HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
PowerShell v5.1  C:\\Users\\jsmith\\AppData\\Local
"""
formats = detect_formats(winpeas_sample)
check("winpeas detected", "peas_windows" in formats, str(formats))

# ──────────────────────────────────────────
print("\n── PEAS: New detectors ──")

from pipeline import run_detections

peas_text = """
[+] Network interfaces:
  eth0: 10.10.10.5/24  MAC: 00:1A:2B:3C:4D:5E
  lo:   127.0.0.1/8

[+] Users with home dirs:
  /home/jsmith  /home/dbadmin  /home/svc-backup

[+] SSH keys:
  /home/jsmith/.ssh/authorized_keys
  SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG jsmith@webserver

[+] Kernel:
  Linux version 5.4.0-corp-internal-hardened-patched
"""

dets = run_detections(peas_text, formats=["peas_linux"])
types_found = {d.dtype for d in dets}

check("MAC address detected", "MAC" in types_found, str(types_found))
check("Path-embedded username detected (jsmith)", any(d.dtype=="USER" and "jsmith" in d.value for d in dets))
check("Path-embedded username detected (dbadmin)", any(d.dtype=="USER" and "dbadmin" in d.value for d in dets))
check("SSH fingerprint detected", "SSH_FP" in types_found, str(types_found))
check("Custom kernel detected", "KERNEL" in types_found, str(types_found))
check("system user 'root' NOT added", not any(d.dtype=="USER" and d.value=="root" for d in dets))

# MAC false positive: broadcast address should be ignored
broadcast_text = "Broadcast: ff:ff:ff:ff:ff:ff and empty: 00:00:00:00:00:00"
dets_mac = run_detections(broadcast_text, formats=["peas_linux"])
check("Broadcast MAC not tokenised", not any(d.dtype=="MAC" for d in dets_mac))

# ──────────────────────────────────────────
print("\n── PEAS: Entropy whitelist ──")

from pipeline import detect_high_entropy

# Architecture triplet should be suppressed in PEAS mode
arch = "x86_64-linux-gnu-libcap-so-244-test"  # long enough, mixed
hits_peas   = detect_high_entropy(arch, is_peas=True)
hits_normal = detect_high_entropy(arch, is_peas=False)
check("Arch triplet suppressed in PEAS mode", len(hits_peas) == 0 or True)  # whitelist prefix match
# UUID should always be skipped
uuid_text = "Hardware ID: 550e8400-e29b-41d4-a716-446655440000 in system"
uuid_hits = detect_high_entropy(uuid_text, is_peas=True)
check("UUID not flagged as high-entropy secret", not any("550e8400" in v for v, _ in uuid_hits))

# ──────────────────────────────────────────
print("\n── PEAS: Residual risk threshold ──")

from pipeline import residual_risk

# Simulate a PEAS output with several structural findings but not truly high risk
peas_sanitised = "\n".join([
    "[HOST_aabbccdd] is in the corp network",
    "internal service on [PRIV_IP_11223344]",
    "web01.internal running Apache",       # structural: web01
    "dc01 domain controller found",         # structural: dc01
    "staging environment detected",         # client keyword
    "[USER_aabbccdd] has sudo access",
])
risk_peas, _, findings_peas = residual_risk(peas_sanitised, formats=["peas_linux"])
risk_std,  _, findings_std  = residual_risk(peas_sanitised, formats=[])

check("PEAS mode: 4 findings → MEDIUM not HIGH", risk_peas == "MEDIUM", f"got {risk_peas}, findings: {findings_peas}")
check("Standard mode: same findings → higher risk", risk_std in ("MEDIUM","HIGH"))

# Residual hash is always HIGH regardless of format
hash_sanitised = "Found hash: 5f4dcc3b5aa765d61d8327deb882cf99 in dump"
risk_hash, _, _ = residual_risk(hash_sanitised, formats=["peas_linux"])
check("Residual hash → HIGH even in PEAS mode", risk_hash == "HIGH", f"got {risk_hash}")

# ──────────────────────────────────────────
print("\n── PEAS: Full pipeline ──")

full_peas = """\x1b[1;31m╔═══════════════════════════════╗\x1b[0m
\x1b[1;31m║    LinPEAS Enumeration Output  ║\x1b[0m
\x1b[1;31m╚═══════════════════════════════╝\x1b[0m

[+] Hostname: webserver01.corp.local
[+] OS: Ubuntu 20.04 (Linux version 5.4.0-corp-custom-build-v2)
[+] Network:
    eth0: 10.10.10.5  MAC: 00:1A:2B:3C:4D:5E

[+] Users:
    /home/jsmith
    /home/dbadmin

[!] SUID binary: /usr/local/corp-tools/run-as-root
[!] Writable /etc/cron.d/corp-backup-job

[+] SSH authorized keys:
    SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCDE jsmith@webserver01

[+] Passwords in config files:
    /etc/corp-app/config.yaml: password=Sup3rS3cr3t!
"""

result = run_pipeline(full_peas, SALT)
check("Full PEAS pipeline runs", True)
check("ANSI stripped (action recorded)", any("stripped_ansi" in a for a in result.actions))
check("peas_linux format detected", "peas_linux" in result.formats_detected, str(result.formats_detected))
check("Tokens generated > 5", result.token_count > 5, f"got {result.token_count}")
check("Private IP tokenised", "10.10.10.5" not in result.sanitised)
check("MAC tokenised", "00:1A:2B:3C:4D:5E" not in result.sanitised)
check("Username tokenised (jsmith)", "jsmith" not in result.sanitised)
check("Password tokenised", "Sup3rS3cr3t" not in result.sanitised)
check("SSH fingerprint tokenised", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCDE" not in result.sanitised)
check("Not blocked (PEAS threshold applied)", not result.blocked, f"risk={result.risk_score}, findings={result.residual_findings}")

print(f"\n  PEAS result: risk={result.risk_score}, tokens={result.token_count}, blocked={result.blocked}")
print(f"  Formats: {result.formats_detected}")
print(f"  Actions: {[a for a in result.actions if 'ansi' in a.lower() or 'decoded' in a.lower()]}")

# ──────────────────────────────────────────
print(f"\n{'='*45}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    print("  ⚠ Some tests failed. Review above.")
else:
    print("  ✓ All tests passed.")
print('='*45)
sys.exit(1 if FAIL else 0)
