"""
Sanitisation pipeline — strict linear execution, no optional stages.
Each stage is isolated. Raw input never persists.
"""

import re
import json
import math
import base64
import hashlib
import hmac
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Any
from collections import Counter

# ─────────────────────────────────────────────
# ANSI ESCAPE CODE PATTERN
# Compiled once at module load — used in Stage 1 before anything else.
# Covers CSI sequences (\x1b[...m), single-char escapes, and OSC strings.
# Must strip before the non-printable loop so fragments don't survive.
# ─────────────────────────────────────────────
_RE_ANSI = re.compile(
    r'\x1b'                                     # ESC
    r'(?:'
    r'\[[0-9;?]*[A-Za-z]'                       # CSI: \x1b[...A-Za-z  (colours, cursor)
    r'|\][^\x07\x1b]*(?:\x07|\x1b\\)'          # OSC: \x1b]...BEL or ST
    r'|[@-Z\\-_]'                               # Fe/Fp single-char escapes
    r')'
)


# ─────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────

@dataclass
class Detection:
    dtype: str          # IP, HOSTNAME, USER, HASH, SECRET, etc.
    value: str
    token: str
    confidence: float
    context: str = ""


@dataclass
class PipelineResult:
    sanitised: str
    detections: list[Detection] = field(default_factory=list)
    risk_score: str = "LOW"       # LOW / MEDIUM / HIGH
    risk_reasons: list[str] = field(default_factory=list)
    residual_findings: list[str] = field(default_factory=list)
    formats_detected: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    blocked: bool = False
    token_count: int = 0


# ─────────────────────────────────────────────
# STAGE 1 — PRE-PROCESSING
# ─────────────────────────────────────────────

def preprocess(raw: str) -> tuple[str, list[str]]:
    """
    Normalise input. Strict rules only — no guessing.
    Returns (cleaned_text, actions_taken).
    """
    actions = []

    # UTF-8 normalise
    text = unicodedata.normalize("NFC", raw)

    # Strip ANSI escape sequences FIRST — before the non-printable loop.
    # LinPEAS/WinPEAS output is heavily colour-coded; if \x1b is removed
    # character-by-character the CSI parameter bytes ("[1;31m") survive as
    # literal text and corrupt every downstream regex match.
    ansi_count = len(_RE_ANSI.findall(text))
    if ansi_count:
        text = _RE_ANSI.sub("", text)
        actions.append(f"stripped_ansi:{ansi_count}_sequences")

    # Strip non-printable chars (keep newlines, tabs)
    cleaned = []
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in ("\n", "\r", "\t") or not cat.startswith("C"):
            cleaned.append(ch)
        else:
            actions.append(f"removed_nonprintable:{ord(ch):#04x}")
    text = "".join(cleaned)

    # URL decode only if valid percent-encoded patterns exist
    if re.search(r"%[0-9A-Fa-f]{2}", text):
        try:
            decoded = urllib.parse.unquote(text, errors="strict")
            # Only accept if result doesn't expand dramatically
            if len(decoded) <= len(text) * 1.1:
                text = decoded
                actions.append("url_decoded")
        except Exception:
            pass

    # Base64 decode — ALL conditions must hold
    b64_candidates = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
    for candidate in b64_candidates:
        if _safe_b64_decode(candidate):
            decoded_bytes, decoded_str = _safe_b64_decode(candidate)
            # Only replace if decoded is more informative (not binary noise)
            text = text.replace(candidate, decoded_str, 1)
            actions.append(f"b64_decoded:{candidate[:12]}…")

    return text, actions


def _safe_b64_decode(s: str) -> tuple[bytes, str] | None:
    """Returns (bytes, str) only if decode is safe and meaningful."""
    if len(s) < 24:
        return None
    # Pad if needed
    padded = s + "=" * (-len(s) % 4)
    try:
        decoded = base64.b64decode(padded)
    except Exception:
        return None
    # ≥85% printable after decode
    printable = sum(1 for b in decoded if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    if printable / len(decoded) < 0.85:
        return None
    # Decoded size must not absurdly expand (already guarded by length check)
    if len(decoded) > len(s) * 4:
        return None
    decoded_str = decoded.decode("utf-8", errors="replace")
    return decoded, decoded_str


# ─────────────────────────────────────────────
# STAGE 2 — STRUCTURED PARSING
# ─────────────────────────────────────────────

def detect_formats(text: str) -> list[str]:
    """Identify known pentest artifact formats."""
    formats = []

    # JSON
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            json.loads(stripped)
            formats.append("json")
        except Exception:
            pass

    # HTTP traffic
    if re.search(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) .+ HTTP/\d", text, re.MULTILINE):
        formats.append("http_request")
    if re.search(r"^HTTP/\d\.\d \d{3}", text, re.MULTILINE):
        formats.append("http_response")

    # Nmap
    if "Nmap scan report for" in text or "PORT   STATE" in text:
        formats.append("nmap")

    # secretsdump
    if re.search(r"[A-Za-z0-9_]+:[0-9]+:[a-f0-9]{32}:[a-f0-9]{32}", text):
        formats.append("secretsdump")

    # LDAP / BloodHound
    if re.search(r"(?i)(CN|OU|DC)=[^,\n]+", text):
        formats.append("ldap")

    # LinPEAS — box-drawing section headers + Linux enumeration markers
    # PEAS uses ╔══╗ framing, [+]/[!]/[*] prefixes, and "Linux version" lines.
    # Check for box chars first (most reliable); fall back to marker density.
    _peas_box    = "╔" in text or "╚" in text or "╠" in text
    _peas_linux  = bool(re.search(r"(?i)(linux version|linpeas|lse\.sh)", text))
    _peas_markers = len(re.findall(r"^\s*\[[\+\!\*\?]\]", text, re.MULTILINE)) >= 3
    if (_peas_box or _peas_markers) and (_peas_linux or _peas_markers):
        formats.append("peas_linux")

    # WinPEAS — same box chars but Windows-specific section content
    _peas_win = bool(re.search(
        r"(?i)(winpeas|SystemInfo|HKLM\\|PowerShell|\\AppData\\|win32_)", text
    ))
    if (_peas_box or _peas_markers) and _peas_win:
        # Replace peas_linux with peas_windows if Windows indicators dominate
        if "peas_linux" in formats and not _peas_linux:
            formats.remove("peas_linux")
        formats.append("peas_windows")

    return formats


def extract_json_values(text: str) -> list[tuple[str, str]]:
    """Recursively walk JSON and yield (key, value) leaf pairs."""
    results = []

    def walk(obj, parent_key=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, k)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, parent_key)
        elif isinstance(obj, str):
            results.append((parent_key, obj))

    try:
        parsed = json.loads(text.strip())
        walk(parsed)
    except Exception:
        pass
    return results


# ─────────────────────────────────────────────
# STAGE 3 — HEURISTIC DETECTION
# ─────────────────────────────────────────────

# Regex patterns
_RE_PRIV_IP   = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
_RE_PUB_IP    = re.compile(r"\b(?!10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)(\d{1,3}\.){3}\d{1,3}\b")
_RE_EMAIL     = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_RE_HOSTNAME  = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:local|internal|corp|lan|home|intranet)\b", re.IGNORECASE)
_RE_DOMAIN    = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|co|uk|de|fr|es|it|nl|se|no|dk|fi|ch|at|be|pl|ru|cn|jp|au|nz|ca|br)\b", re.IGNORECASE)
_RE_HASH32    = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_HASH40    = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_HASH64    = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_NTLM      = re.compile(r"[A-Za-z0-9_\-]+:[0-9]+:[a-f0-9]{32}:[a-f0-9]{32}")
_RE_LDAP_DN   = re.compile(r"(?i)(?:CN|OU|DC)=[^,\n]{2,}(?:,(?:CN|OU|DC)=[^,\n]+)*")
_RE_AUTH_HDR  = re.compile(r"(?i)Authorization:\s*(Bearer|Basic|Digest|NTLM|Negotiate)\s+\S+")
_RE_COOKIE    = re.compile(r"(?i)(?:Set-)?Cookie:\s*[^\r\n]+")
_RE_KV_SECRET = re.compile(r"(?i)(?:password|passwd|pwd|secret|token|api[-_]?key|auth[-_]?key|access[-_]?key|private[-_]?key)\s*[=:]\s*\S+")
_RE_USERNAME  = re.compile(r"(?i)(?:user(?:name)?|login|account)\s*[=:]\s*([A-Za-z0-9_\-\.@]+)")

_SENSITIVITY_KEYWORDS = re.compile(r"(?i)(password|secret|token|auth|cookie|apikey|api_key|private|credential)")

# ── PEAS-specific patterns ──────────────────────────────────────────────────

# MAC addresses (both colon and hyphen separators)
_RE_MAC = re.compile(
    r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'
)

# Path-embedded usernames
# Unix:    /home/username/  or  /home/username (EOL/space)
# macOS:   /Users/username/
# Windows: C:\Users\username\  (any drive letter)
_RE_UNIX_HOME = re.compile(
    r'/(?:home|Users)/([a-zA-Z0-9_\.\-]{2,32})(?:/|\s|$)', re.MULTILINE
)
_RE_WIN_HOME = re.compile(
    r'[A-Za-z]:\\[Uu]sers\\([a-zA-Z0-9_\.\-]{2,32})(?:\\|\s|$)', re.MULTILINE
)

# SSH key fingerprints — SHA256 (base64) and MD5 (colon-hex) formats
_RE_SSH_FP = re.compile(
    r'(?:SHA256:[A-Za-z0-9+/]{43}=?'          # SHA256:xxxxxxx...
    r'|MD5:(?:[0-9a-f]{2}:){15}[0-9a-f]{2})'  # MD5:xx:xx:...:xx
)

# Kernel version strings that contain custom/internal build identifiers.
# "Linux version 5.4.0-generic" → benign (≤3 dash segments after the base).
# "Linux version 5.4.0-42-corp-internal-build" → identifying (>3 segments).
_RE_KERNEL_VER = re.compile(r'Linux version (\S+)')

# UUID pattern — common in PEAS hardware/interface output; add to FP blocklist
_RE_UUID = re.compile(
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
)

# Known-benign path/architecture strings that the entropy detector will
# otherwise flag on PEAS output.
_PEAS_ENTROPY_WHITELIST = re.compile(
    r'^(?:'
    r'x86_64-linux-gnu|aarch64-linux-gnu|arm-linux-gnueabihf'   # arch triplets
    r'|[a-z0-9_\-]+\.so(?:\.\d+)*'                              # shared libs
    r'|libgcc[-_]s|libstdc\+\+'                                  # common libs
    r'|/usr/lib/[a-z0-9/_\-\.]+|/lib/[a-z0-9/_\-\.]+'          # system paths
    r')$',
    re.IGNORECASE
)

_COMMON_FALSE_POSITIVES = {
    "localhost", "example.com", "test.com", "null", "none", "true", "false",
    "00000000000000000000000000000000",  # empty NTLM hash
    "aad3b435b51404eeaad3b435b51404ee",  # empty LM hash
    "31d6cfe0d16ae931b73c59d7e0c089c0",  # empty NTLM hash
}


def compute_entropy(s: str) -> float:
    """Shannon entropy in bits/char."""
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def has_mixed_charset(s: str) -> bool:
    has_lower = any(c.islower() for c in s)
    has_upper = any(c.isupper() for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_special = any(not c.isalnum() for c in s)
    return sum([has_lower, has_upper, has_digit, has_special]) >= 3


def detect_high_entropy(text: str, is_peas: bool = False) -> list[tuple[str, float]]:
    """Find high-entropy strings (≥20 chars, mixed charset, entropy ≥3.6).

    is_peas: when True, applies an additional whitelist pass to suppress
    architecture triplets, shared library names, and system paths that
    are structurally common in PEAS output but not client-identifying.
    """
    hits = []
    # Pre-collect UUIDs so we can skip them — they appear frequently in
    # PEAS hardware/interface sections and are not client-identifying.
    uuid_spans = {m.span() for m in _RE_UUID.finditer(text)}

    for match in re.finditer(r"\b[A-Za-z0-9+/=_\-\.]{20,}\b", text):
        val = match.group()
        if val.lower() in _COMMON_FALSE_POSITIVES:
            continue
        if len(val) < 20:
            continue
        # Skip if this span overlaps a UUID
        if any(s <= match.start() and match.end() <= e for s, e in uuid_spans):
            continue
        if not has_mixed_charset(val):
            continue
        entropy = compute_entropy(val)
        if entropy < 3.6:
            continue
        # PEAS mode: suppress known-benign architecture/library strings
        if is_peas and _PEAS_ENTROPY_WHITELIST.match(val):
            continue
        # Boost confidence if near a sensitivity keyword
        context_start = max(0, match.start() - 30)
        context = text[context_start: match.start()]
        if _SENSITIVITY_KEYWORDS.search(context):
            hits.append((val, entropy * 1.2))
        else:
            hits.append((val, entropy))
    return hits


def run_detections(text: str, formats: list[str] | None = None) -> list[Detection]:
    """
    Run all heuristic detectors. Return ordered list of Detections.
    formats: if supplied, enables format-specific detector adjustments.
    """
    formats = formats or []
    is_peas = "peas_linux" in formats or "peas_windows" in formats
    is_peas_win = "peas_windows" in formats

    detections = []
    seen_values = set()

    def add(dtype, value, confidence, context=""):
        if value in seen_values or value.lower() in _COMMON_FALSE_POSITIVES:
            return
        seen_values.add(value)
        detections.append(Detection(dtype=dtype, value=value, token="", confidence=confidence, context=context))

    # NTLM hashes first (highest priority, specific format)
    for m in _RE_NTLM.finditer(text):
        add("NTLM_HASH", m.group(), 1.0, "secretsdump line")

    # Hashes
    for m in _RE_HASH64.finditer(text):
        add("HASH", m.group(), 0.95)
    for m in _RE_HASH40.finditer(text):
        add("HASH", m.group(), 0.9)
    for m in _RE_HASH32.finditer(text):
        add("HASH", m.group(), 0.85)

    # Auth header
    for m in _RE_AUTH_HDR.finditer(text):
        add("AUTH_HEADER", m.group(), 1.0)

    # Cookies
    for m in _RE_COOKIE.finditer(text):
        add("COOKIE", m.group(), 0.95)

    # KV secrets
    for m in _RE_KV_SECRET.finditer(text):
        add("SECRET", m.group(), 0.95)

    # Emails
    for m in _RE_EMAIL.finditer(text):
        add("EMAIL", m.group(), 0.95)

    # Private IPs
    for m in _RE_PRIV_IP.finditer(text):
        add("PRIV_IP", m.group(), 0.99)

    # Public IPs (lower confidence — could be docs)
    for m in _RE_PUB_IP.finditer(text):
        if not _RE_PRIV_IP.match(m.group()):
            add("PUB_IP", m.group(), 0.7)

    # Hostnames (internal)
    for m in _RE_HOSTNAME.finditer(text):
        add("HOSTNAME", m.group(), 0.9)

    # LDAP DNs
    for m in _RE_LDAP_DN.finditer(text):
        add("LDAP_DN", m.group(), 0.95)

    # Usernames
    for m in _RE_USERNAME.finditer(text):
        if m.group(1):
            add("USER", m.group(1), 0.8)

    # Domains
    for m in _RE_DOMAIN.finditer(text):
        val = m.group()
        if not any(d.value == val or val in d.value for d in detections):
            add("DOMAIN", val, 0.6)

    # ── PEAS-specific detectors ───────────────────────────────────────────

    # MAC addresses — appear in interface listings on both Linux and Windows
    for m in _RE_MAC.finditer(text):
        val = m.group()
        # Skip all-zero and broadcast MACs (not client-identifying)
        if val.replace(":", "").replace("-", "").lower() not in ("000000000000", "ffffffffffff"):
            add("MAC", val, 0.95, "interface listing")

    # Path-embedded usernames — /home/user/ and C:\Users\user\
    for m in _RE_UNIX_HOME.finditer(text):
        uname = m.group(1)
        if uname.lower() not in ("root", "nobody", "daemon", "www-data", "systemd",
                                  "sync", "games", "man", "lp", "mail", "news",
                                  "uucp", "proxy", "backup", "list", "irc", "gnats"):
            add("USER", uname, 0.92, "unix home path")

    for m in _RE_WIN_HOME.finditer(text):
        uname = m.group(1)
        if uname.lower() not in ("public", "default", "all users", "defaultuser0"):
            add("USER", uname, 0.92, "windows home path")

    # SSH key fingerprints
    for m in _RE_SSH_FP.finditer(text):
        add("SSH_FP", m.group(), 0.98, "ssh fingerprint")

    # Custom kernel version strings (Linux-only PEAS)
    if not is_peas_win:
        for m in _RE_KERNEL_VER.finditer(text):
            ver = m.group(1)
            # Only tokenise if it looks custom: more than 3 dash-separated
            # segments suggests a vendor/org build suffix
            segments = ver.split("-")
            if len(segments) > 3:
                add("KERNEL", ver, 0.85, "custom kernel build string")

    # High-entropy strings — PEAS mode uses whitelist to suppress FPs
    for val, entropy in detect_high_entropy(text, is_peas=is_peas):
        if not any(d.value == val for d in detections):
            add("SECRET", val, min(entropy / 6.0, 1.0), f"entropy={entropy:.2f}")

    return detections


# ─────────────────────────────────────────────
# STAGE 4 — TOKENISATION ENGINE
# ─────────────────────────────────────────────

# Type → token prefix map
_TYPE_PREFIX = {
    "PRIV_IP":     "PRIV_IP",
    "PUB_IP":      "PUB_IP",
    "HOSTNAME":    "HOST",
    "DOMAIN":      "DOMAIN",
    "EMAIL":       "EMAIL",
    "USER":        "USER",
    "HASH":        "HASH",
    "NTLM_HASH":   "NTLM",
    "AUTH_HEADER": "AUTH",
    "COOKIE":      "COOKIE",
    "SECRET":      "SECRET",
    "LDAP_DN":     "LDAP",
    "MAC":         "MAC",
    "SSH_FP":      "SSH_FP",
    "KERNEL":      "KERNEL",
}


def make_token(dtype: str, value: str, salt: bytes) -> str:
    """Deterministic HMAC-based token."""
    digest = hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
    prefix = _TYPE_PREFIX.get(dtype, "REDACTED")
    return f"[{prefix}_{digest}]"


def tokenise(text: str, detections: list[Detection], salt: bytes) -> tuple[str, list[Detection]]:
    """
    Replace detected values with deterministic tokens.
    Sort by length descending to avoid partial replacements.
    """
    # Assign tokens
    for d in detections:
        d.token = make_token(d.dtype, d.value, salt)

    # Sort longest first to avoid partial substring replacement
    ordered = sorted(detections, key=lambda d: len(d.value), reverse=True)

    result = text
    for d in ordered:
        result = result.replace(d.value, d.token)

    return result, detections


# ─────────────────────────────────────────────
# STAGE 5 — RESIDUAL RISK ANALYSIS
# ─────────────────────────────────────────────

_RESIDUAL_IP      = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_RESIDUAL_DOMAIN  = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.){2,}[a-zA-Z]{2,}\b")
_RESIDUAL_HASH    = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_RESIDUAL_STRUCT  = re.compile(r"\b(?:dc\d+|web\d+|sql\d+|app\d+|srv\d+|win\d+|lin\d+|prod\d+|dev\d+)\b", re.IGNORECASE)
_RESIDUAL_CLIENT  = re.compile(r"\b(?:corp|internal|intranet|production|staging|uat|vpn)\b", re.IGNORECASE)
_RESIDUAL_MAC     = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b')

# All known token prefixes — used to mask already-tokenised placeholders
# before rescanning, so they don't generate false residual findings.
_RESIDUAL_TOKEN_PLACEHOLDER = re.compile(
    r"\[(?:PRIV_IP|PUB_IP|HOST|DOMAIN|EMAIL|USER|HASH|NTLM|AUTH|COOKIE"
    r"|SECRET|LDAP|MAC|SSH_FP|KERNEL)_[0-9a-f]{8}\]"
)


def residual_risk(sanitised: str, formats: list[str] | None = None) -> tuple[str, list[str], list[str]]:
    """
    Scan sanitised output for leftover sensitive patterns.
    formats: used to adjust thresholds for high-volume artefact types.
    Returns (risk_level, reasons, findings).
    """
    formats = formats or []
    is_peas = "peas_linux" in formats or "peas_windows" in formats

    findings = []
    reasons = []

    # Mask already-tokenised placeholders before scanning
    scan_text = _RESIDUAL_TOKEN_PLACEHOLDER.sub("__TOKEN__", sanitised)

    for m in _RESIDUAL_IP.finditer(scan_text):
        ip = m.group()
        if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.0", "255.255.255.255"):
            findings.append(f"residual_ip:{ip}")
            reasons.append(f"Residual IP address: {ip}")

    for m in _RESIDUAL_HASH.finditer(scan_text):
        findings.append(f"residual_hash:{m.group()[:12]}…")
        reasons.append("Residual hex hash detected")

    for m in _RESIDUAL_STRUCT.finditer(scan_text):
        findings.append(f"structural_hostname:{m.group()}")
        reasons.append(f"Structural hostname pattern: {m.group()}")

    for m in _RESIDUAL_CLIENT.finditer(scan_text):
        findings.append(f"client_keyword:{m.group()}")
        reasons.append(f"Client-identifying keyword: {m.group()}")

    for m in _RESIDUAL_MAC.finditer(scan_text):
        val = m.group().replace(":", "").replace("-", "").lower()
        if val not in ("000000000000", "ffffffffffff"):
            findings.append(f"residual_mac:{m.group()}")
            reasons.append(f"Residual MAC address: {m.group()}")

    # Deduplicate
    reasons  = list(dict.fromkeys(reasons))
    findings = list(dict.fromkeys(findings))

    # PEAS output is inherently dense — raise the HIGH threshold to avoid
    # blocking every run. Still block on unambiguously high-risk signals
    # (residual hashes or very large finding counts).
    if is_peas:
        high_threshold = 15
    else:
        high_threshold = 5

    has_residual_hash = any("residual_hash" in f for f in findings)

    if len(findings) >= high_threshold or has_residual_hash:
        risk = "HIGH"
    elif len(findings) >= 3:
        risk = "MEDIUM"
    elif findings:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return risk, reasons, findings


# ─────────────────────────────────────────────
# MAIN PIPELINE ORCHESTRATOR
# ─────────────────────────────────────────────

def run_pipeline(raw_text: str, salt: bytes) -> PipelineResult:
    result = PipelineResult(sanitised="")

    # Stage 1: Pre-processing
    text, actions = preprocess(raw_text)
    result.actions.extend(actions)

    # Stage 2: Structured parsing / format detection
    result.formats_detected = detect_formats(text)

    # Stage 3: Heuristic detection (format-aware)
    detections = run_detections(text, formats=result.formats_detected)

    # Stage 4: Tokenisation
    sanitised, detections = tokenise(text, detections, salt)
    result.detections = detections
    result.token_count = len(detections)

    # Stage 5: Residual risk analysis (format-aware threshold)
    risk, reasons, findings = residual_risk(sanitised, formats=result.formats_detected)
    result.risk_score = risk
    result.risk_reasons = reasons
    result.residual_findings = findings

    # Block HIGH risk by default
    if risk == "HIGH":
        result.blocked = True
        result.actions.append("BLOCKED:high_residual_risk")

    result.sanitised = sanitised
    return result
