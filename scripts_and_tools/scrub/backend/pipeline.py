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
class Finding:
    """A security observation generated during sanitisation."""
    ftype: str          # plaintext_password, jwt_alg_none, debug_enabled, etc.
    path: str           # JSON path where found e.g. auth.jwt.alg
    severity: str       # HIGH / MEDIUM / LOW
    detail: str = ""    # Human-readable description


@dataclass
class PipelineResult:
    sanitised: str
    detections: list[Detection] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
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

    # Base64 decode — ALL conditions must hold.
    # Skip entirely if the input is valid JSON — base64 strings inside JSON
    # are opaque values; decoding them corrupts the structure (e.g. JWT payloads
    # decode to raw JSON that breaks the outer document).
    _is_json = False
    _stripped = text.strip()
    if _stripped.startswith(('{', '[')):
        try:
            json.loads(_stripped)
            _is_json = True
        except Exception:
            pass

    if not _is_json:
        b64_candidates = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
        for candidate in b64_candidates:
            if _safe_b64_decode(candidate):
                decoded_bytes, decoded_str = _safe_b64_decode(candidate)
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

    # HTTP traffic — detect request, response, or pair
    # Pair detection takes priority: when both are present the splitter
    # runs separately on each half so tokens are consistent across both sides.
    _has_req  = bool(re.search(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) .+ HTTP/\d", text, re.MULTILINE))
    _has_resp = bool(re.search(r"^HTTP/\d[\d.]* \d{3}", text, re.MULTILINE))
    if _has_req and _has_resp:
        formats.append("http_pair")
        formats.append("http_request")
        formats.append("http_response")
    else:
        if _has_req:
            formats.append("http_request")
        if _has_resp:
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


def split_http_pair(text: str) -> tuple[str, str] | None:
    """
    Split a combined HTTP request+response into (request_text, response_text).
    The split point is the first HTTP status line (HTTP/x.x NNN ...).
    Returns None if the text doesn't contain a clear pair.

    Strategy: find the response status line. Everything before it is the
    request; everything from the status line onward is the response.
    We skip the first line if it IS the request line to avoid false matches.
    """
    lines = text.splitlines(keepends=True)
    response_start_idx = None

    for i, line in enumerate(lines):
        # HTTP status line: HTTP/1.1 200 OK  or  HTTP/2 200
        if re.match(r'^HTTP/[\d.]+ \d{3}', line):
            response_start_idx = i
            break

    if response_start_idx is None:
        return None

    request_text  = "".join(lines[:response_start_idx]).rstrip()
    response_text = "".join(lines[response_start_idx:]).strip()

    # Sanity check — request part should contain a request line
    if not re.search(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) .+ HTTP/\d', request_text, re.MULTILINE):
        return None

    return request_text, response_text


def extract_json_values(text: str) -> list[tuple[str, str, str]]:
    """
    Recursively walk a JSON structure and yield (path, key, value) leaf triples.
    path is the dot-separated key path e.g. 'auth.jwt.token'.
    Only string values are returned — numbers, booleans, nulls are not sensitive.
    """
    results = []

    def walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                child_path = f"{path}.{k}" if path else k
                walk(v, child_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")
        elif isinstance(obj, str) and obj:
            # Leaf key is the last segment of the path
            leaf_key = path.split(".")[-1].split("[")[0]
            results.append((path, leaf_key, obj))

    try:
        parsed = json.loads(text.strip())
        walk(parsed)
    except Exception:
        pass
    return results


# ─────────────────────────────────────────────
# JSON STRUCTURED PROCESSOR
# ─────────────────────────────────────────────

# Keys that always indicate sensitive values regardless of the value's appearance
_SENSITIVE_JSON_KEYS = {
    # Credentials
    "password", "passwd", "pass", "pwd", "passphrase",
    "secret", "secret_key", "secretkey", "client_secret",
    "api_key", "apikey", "api_token",
    "access_key", "access_token", "access_secret",
    "private_key", "privatekey",
    # Auth / session
    "token", "auth_token", "authtoken", "bearer",
    "session", "session_token", "sessiontoken", "session_id", "sessionid",
    "jwt", "refresh_token",
    # Database credentials
    "db_pass", "db_password", "database_password",
    "db_user", "db_username",
    # Keys / secrets in env-style naming
    "db_pass", "secret_key", "app_secret", "signing_key",
    "encryption_key", "master_key", "root_password",
    # Generic sensitive patterns
    "credential", "credentials", "auth", "authorization",
}

# Block-level keys — entire subtree is redacted, not just the value
_REDACTED_BLOCK_KEYS = {
    "debug", "env", "environment_vars", "secrets",
    "stack_trace", "stacktrace", "backtrace",
}

# JWT pattern — three base64url segments separated by dots
_RE_JWT = re.compile(
    r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*'
)

# Path traversal pattern
_RE_PATH_TRAVERSAL = re.compile(r'\.\./')

# Hash prefixes common in password fields
_HASH_PREFIXES = ('$2y$', '$2b$', '$2a$', '$1$', '$5$', '$6$', '$argon2', '$scrypt')


def classify_json_value(key: str, value: str, path: str) -> str:
    """
    Classify a JSON leaf value into a sensitivity type.
    Returns: PASSWORD | JWT | HASH | PATH_TRAVERSAL | FILE_PATH | SESSION | SECRET | SAFE
    """
    key_lower = key.lower().replace('-', '_').replace(' ', '_')

    # Path traversal — always flag regardless of key
    if _RE_PATH_TRAVERSAL.search(value):
        return "PATH_TRAVERSAL"

    # JWT — structural pattern match
    if _RE_JWT.match(value):
        return "JWT"

    # Hash — known prefix formats
    if any(value.startswith(p) for p in _HASH_PREFIXES):
        return "HASH"

    # Key-based classification
    if key_lower in {"password", "passwd", "pass", "pwd", "passphrase",
                     "db_pass", "db_password", "root_password"}:
        return "PASSWORD"

    if key_lower in {"session", "session_token", "sessiontoken",
                     "session_id", "sessionid"}:
        return "SESSION"

    if key_lower in _SENSITIVE_JSON_KEYS:
        return "SECRET"

    # File path in value
    if value.startswith('/') or (len(value) > 2 and value[1] == ':' and value[2] == '\\'):
        return "FILE_PATH"

    return "SAFE"


def process_json_structure(
    text: str, salt: bytes
) -> tuple[str, list[Detection], list[Finding]]:
    """
    Process a JSON structure with full path context.
    Returns (sanitised_text, detections, findings).

    Strategy:
    - Parse JSON, walk the full tree
    - Redact entire blocks for known high-risk keys (debug, env, etc.)
    - Tokenise values under sensitive keys
    - Generate findings for security-relevant observations
    - Re-serialise to JSON preserving structure
    """
    try:
        parsed = json.loads(text.strip())
    except Exception:
        return text, [], []  # Not valid JSON, fall through to regex pipeline

    detections: list[Detection] = []
    findings:   list[Finding]   = []
    seen_values: set[str] = set()

    def make_det(dtype: str, value: str, path: str) -> Detection:
        tok = make_token(dtype, value, salt)
        d = Detection(dtype=dtype, value=value, token=tok, confidence=1.0, context=path)
        return d

    def walk_and_sanitise(obj, path: str = ""):
        """Recursively walk, returning a sanitised copy."""
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                child_path = f"{path}.{k}" if path else k
                k_lower = k.lower().replace('-', '_').replace(' ', '_')

                # Block-level redaction
                if k_lower in _REDACTED_BLOCK_KEYS:
                    result[k] = "[REDACTED_BLOCK]"
                    findings.append(Finding(
                        ftype=f"redacted_block:{k_lower}",
                        path=child_path,
                        severity="HIGH",
                        detail=f"Entire '{k}' block redacted — contains infrastructure/debug data"
                    ))
                    # Special findings for specific blocks
                    if k_lower == "debug" and isinstance(v, dict):
                        enabled = v.get("enabled", v.get("mode", False))
                        if enabled is True or enabled == "true":
                            findings.append(Finding(
                                ftype="debug_mode_enabled",
                                path=child_path + ".enabled",
                                severity="HIGH",
                                detail="Debug mode is enabled in production configuration"
                            ))
                    continue

                result[k] = walk_and_sanitise(v, child_path)
            return result

        elif isinstance(obj, list):
            return [walk_and_sanitise(item, f"{path}[{i}]") for i, item in enumerate(obj)]

        elif isinstance(obj, str) and obj:
            leaf_key = path.split(".")[-1].split("[")[0]
            k_lower  = leaf_key.lower().replace('-', '_').replace(' ', '_')
            vtype    = classify_json_value(leaf_key, obj, path)

            # Path traversal — replace with marker and generate finding
            if vtype == "PATH_TRAVERSAL":
                findings.append(Finding(
                    ftype="path_traversal_detected",
                    path=path,
                    severity="HIGH",
                    detail=f"Path traversal sequence detected in value at {path}"
                ))
                if obj not in seen_values:
                    seen_values.add(obj)
                    d = make_det("SECRET", obj, path)
                    detections.append(d)
                    return d.token
                else:
                    tok = make_token("SECRET", obj, salt)
                    return tok

            # JWT — tokenise and check for alg:none
            if vtype == "JWT":
                try:
                    import base64 as _b64
                    header_b64 = obj.split('.')[0]
                    padding = 4 - len(header_b64) % 4
                    header_json = _b64.urlsafe_b64decode(header_b64 + '=' * padding).decode('utf-8', errors='replace')
                    if '"alg":"none"' in header_json or '"alg": "none"' in header_json:
                        findings.append(Finding(
                            ftype="jwt_alg_none",
                            path=path,
                            severity="HIGH",
                            detail="JWT uses alg:none — signature validation is disabled"
                        ))
                    findings.append(Finding(
                        ftype="jwt_present",
                        path=path,
                        severity="MEDIUM",
                        detail=f"JWT token found at {path}"
                    ))
                except Exception:
                    pass
                if obj not in seen_values:
                    seen_values.add(obj)
                    d = make_det("JWT", obj, path)
                    detections.append(d)
                    return d.token
                return make_token("JWT", obj, salt)

            # Hash — tokenise and note plaintext storage context
            if vtype == "HASH":
                if obj not in seen_values:
                    seen_values.add(obj)
                    d = make_det("HASH", obj, path)
                    detections.append(d)
                return make_token("HASH", obj, salt)

            # Password — tokenise and generate plaintext_password finding
            if vtype == "PASSWORD":
                # A plaintext password is one that isn't a hash
                if not any(obj.startswith(p) for p in _HASH_PREFIXES):
                    findings.append(Finding(
                        ftype="plaintext_password",
                        path=path,
                        severity="HIGH",
                        detail=f"Plaintext password stored at {path}"
                    ))
                if obj not in seen_values:
                    seen_values.add(obj)
                    d = make_det("PASSWORD", obj, path)
                    detections.append(d)
                    return d.token
                return make_token("PASSWORD", obj, salt)

            # Session token
            if vtype == "SESSION":
                if obj not in seen_values:
                    seen_values.add(obj)
                    d = make_det("SESSION", obj, path)
                    detections.append(d)
                    return d.token
                return make_token("SESSION", obj, salt)

            # Generic secret (key-matched but not a specific subtype)
            if vtype == "SECRET":
                if obj not in seen_values:
                    seen_values.add(obj)
                    d = make_det("SECRET", obj, path)
                    detections.append(d)
                    return d.token
                return make_token("SECRET", obj, salt)

            # File path
            if vtype == "FILE_PATH":
                if obj not in seen_values:
                    seen_values.add(obj)
                    d = make_det("FILE_PATH", obj, path)
                    detections.append(d)
                    return d.token
                return make_token("FILE_PATH", obj, salt)

            # SAFE — check for weak session config indicators
            if k_lower == "alg" and obj.lower() == "none":
                findings.append(Finding(
                    ftype="jwt_alg_none",
                    path=path,
                    severity="HIGH",
                    detail="JWT algorithm set to 'none' — signature validation disabled"
                ))

            return obj  # Safe — pass through

        else:
            return obj  # Non-string leaf — always safe

    sanitised_obj = walk_and_sanitise(parsed)

    # Re-serialise preserving formatting
    try:
        sanitised_text = json.dumps(sanitised_obj, indent=2, ensure_ascii=False)
    except Exception:
        sanitised_text = text

    return sanitised_text, detections, findings


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

# ── JSON structured detection ───────────────────────────────────────────────

# Keys whose values must always be tokenised regardless of value content.
# Checked case-insensitively against the leaf key name.
_JSON_SENSITIVE_KEYS = {
    "password", "passwd", "pass", "pwd",
    "secret", "secret_key", "secretkey",
    "token", "session", "session_token", "sessiontoken",
    "api_key", "apikey", "api_secret",
    "auth", "auth_token", "authtoken",
    "access_token", "accesstoken", "refresh_token",
    "private_key", "privatekey",
    "db_pass", "db_password", "db_user",
    "jwt", "bearer",
    "key",          # catch-all for short key names in auth contexts
}

# Top-level or nested block keys whose entire subtree should be
# replaced with [REDACTED_BLOCK] — these blocks are never useful
# to an LLM as raw values; their presence is the finding.
_JSON_REDACT_BLOCK_KEYS = {
    "debug", "env", "environment_vars", "secrets",
    "stack_trace", "stacktrace", "traceback",
    "config", "credentials",
}

# JWT pattern — three base64url segments separated by dots
_RE_JWT = re.compile(
    r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*'
)

# Known password hash prefixes
_RE_PASS_HASH = re.compile(
    r'^\$(?:2[ayb]\$|1\$|5\$|6\$|apr1\$|sha1\$)[A-Za-z0-9./+$]{20,}'
)

# Path traversal sequences
_RE_PATH_TRAVERSAL = re.compile(r'\.\.[\\/]')


def _classify_json_value(key: str, value: str, path: str) -> tuple[str, str | None]:
    """
    Classify a JSON leaf value.
    Returns (classification, finding_type_or_None).
    Classifications: PASSWORD, HASH, JWT, PATH_TRAVERSAL, SECRET, SAFE, REDACT_BLOCK
    """
    key_lower = key.lower().strip('"')

    # Key-based: always sensitive regardless of value
    if key_lower in _JSON_SENSITIVE_KEYS:
        # Sub-classify the value for better token type and findings
        if _RE_PASS_HASH.match(value):
            return "HASH", None
        if _RE_JWT.match(value):
            # Check for alg:none — critical vulnerability
            try:
                import base64 as _b64
                header_b64 = value.split('.')[0]
                padded = header_b64 + '=' * (-len(header_b64) % 4)
                header = json.loads(_b64.urlsafe_b64decode(padded).decode('utf-8', errors='replace'))
                alg = header.get('alg', '').lower()
                if alg in ('none', ''):
                    return "JWT", "jwt_alg_none"
            except Exception:
                pass
            return "JWT", None
        return "PASSWORD", None

    # Value-based: JWT anywhere
    if _RE_JWT.match(value):
        try:
            import base64 as _b64
            header_b64 = value.split('.')[0]
            padded = header_b64 + '=' * (-len(header_b64) % 4)
            header = json.loads(_b64.urlsafe_b64decode(padded).decode('utf-8', errors='replace'))
            if header.get('alg', '').lower() in ('none', ''):
                return "JWT", "jwt_alg_none"
        except Exception:
            pass
        return "JWT", None

    # Value-based: password hash
    if _RE_PASS_HASH.match(value):
        return "HASH", None

    # Value-based: path traversal
    if _RE_PATH_TRAVERSAL.search(value):
        return "PATH_TRAVERSAL", "path_traversal_detected"

    return "SAFE", None


def run_json_detections(
    text: str, salt: bytes
) -> tuple[str, list[Detection], list[Finding]]:
    """
    JSON-specific structured traversal.
    Returns (sanitised_json, detections, findings).

    Handles:
    - Key-based sensitive value tokenisation
    - Block-level redaction of debug/env/secrets subtrees
    - JWT alg:none detection
    - Path traversal detection
    - Findings generation with path context
    """
    try:
        parsed = json.loads(text.strip())
    except Exception:
        return text, [], []

    detections: list[Detection] = []
    findings: list[Finding] = []
    seen_values: set[str] = set()

    def make_det(dtype: str, value: str, context: str = "") -> Detection:
        token = make_token(dtype, value, salt)
        d = Detection(dtype=dtype, value=value, token=token, confidence=1.0, context=context)
        detections.append(d)
        seen_values.add(value)
        return d

    def sanitise_node(obj: Any, path: str = "") -> Any:
        """Recursively walk and sanitise. Returns sanitised version of obj."""
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                child_path = f"{path}.{k}" if path else k
                key_lower  = k.lower()

                # Block-level redaction
                if key_lower in _JSON_REDACT_BLOCK_KEYS:
                    findings.append(Finding(
                        ftype=f"{key_lower}_block_redacted",
                        path=child_path,
                        severity="HIGH",
                        detail=f"Sensitive block '{k}' fully redacted"
                    ))
                    result[k] = "[REDACTED_BLOCK]"
                    continue

                # Recurse
                result[k] = sanitise_node(v, child_path)
            return result

        elif isinstance(obj, list):
            return [sanitise_node(item, f"{path}[{i}]") for i, item in enumerate(obj)]

        elif isinstance(obj, str) and obj:
            leaf_key = path.split(".")[-1].split("[")[0].strip('"')
            classification, finding_type = _classify_json_value(leaf_key, obj, path)

            if classification == "SAFE":
                return obj

            if classification == "PATH_TRAVERSAL":
                if finding_type:
                    findings.append(Finding(
                        ftype=finding_type,
                        path=path,
                        severity="HIGH",
                        detail=f"Path traversal sequence in '{leaf_key}': {obj[:80]}"
                    ))
                # Tokenise as SECRET
                if obj not in seen_values:
                    d = make_det("SECRET", obj, f"path_traversal@{path}")
                return d.token if obj in seen_values else make_det("SECRET", obj, f"path_traversal@{path}").token

            # All other sensitive classifications → tokenise
            dtype_map = {
                "PASSWORD": "SECRET",
                "HASH":     "HASH",
                "JWT":      "JWT",
                "SECRET":   "SECRET",
            }
            dtype = dtype_map.get(classification, "SECRET")

            # Generate finding for plaintext passwords
            if classification == "PASSWORD" and not _RE_PASS_HASH.match(obj):
                findings.append(Finding(
                    ftype="plaintext_credential",
                    path=path,
                    severity="HIGH",
                    detail=f"Plaintext credential under key '{leaf_key}'"
                ))

            if finding_type == "jwt_alg_none":
                findings.append(Finding(
                    ftype="jwt_alg_none",
                    path=path,
                    severity="HIGH",
                    detail=f"JWT with alg:none at '{path}' — signature not verified"
                ))

            if obj not in seen_values:
                make_det(dtype, obj, f"json_key:{leaf_key}@{path}")
            # Find existing token
            existing = next((d for d in detections if d.value == obj), None)
            return existing.token if existing else obj

        else:
            return obj

    sanitised_obj = sanitise_node(parsed)

    # Check debug.enabled = true specifically
    def check_debug(obj: Any, path: str = ""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                child_path = f"{path}.{k}" if path else k
                if k.lower() == "enabled" and v is True and "debug" in path.lower():
                    findings.append(Finding(
                        ftype="debug_mode_enabled",
                        path=child_path,
                        severity="HIGH",
                        detail="Debug mode is enabled in production context"
                    ))
                check_debug(v, child_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                check_debug(item, f"{path}[{i}]")

    check_debug(parsed)

    try:
        sanitised_str = json.dumps(sanitised_obj, indent=2)
    except Exception:
        sanitised_str = text

    return sanitised_str, detections, findings

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

# Public CDN and well-known URL patterns — never sensitive regardless of entropy.
# Applied to both the KV secret detector (value side) and the entropy detector.
_PUBLIC_URL_WHITELIST = re.compile(
    r'(?:https?://)?(?:'
    r'cdnjs\.cloudflare\.com'
    r'|cdn\.jsdelivr\.net'
    r'|unpkg\.com'
    r'|ajax\.googleapis\.com'
    r'|fonts\.googleapis\.com'
    r'|fonts\.gstatic\.com'
    r'|stackpath\.bootstrapcdn\.com'
    r'|maxcdn\.bootstrapcdn\.com'
    r'|code\.jquery\.com'
    r'|cdn\.datatables\.net'
    r'|cdn\.cloudflare\.com'
    r'|static\.cloudflareinsights\.com'
    r'|www\.google-analytics\.com'
    r'|www\.googletagmanager\.com'
    r'|connect\.facebook\.net'
    r'|platform\.twitter\.com'
    r')',
    re.IGNORECASE
)

# IPs that are never client-identifying regardless of context.
# Loopback, broadcast, unspecified, and documentation ranges.
_SAFE_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255", "255.255.255.0",
    "255.255.0.0", "255.0.0.0",
    # Documentation ranges (RFC 5737)
    "192.0.2.1", "198.51.100.1", "203.0.113.1",
}

# Standard HTTP request/response headers whose names or values are
# never sensitive. The KV secret regex fires on these because they
# contain words like "Insecure", "Auth" etc. in the header name.
_SAFE_HTTP_HEADERS = {
    # Request headers
    "upgrade-insecure-requests",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "content-type", "content-length", "content-encoding", "content-language",
    "accept", "accept-language", "accept-encoding", "accept-charset",
    "cache-control", "pragma", "connection", "keep-alive",
    "x-requested-with", "te", "trailers", "transfer-encoding",
    "origin", "referer", "host", "user-agent",
    "if-modified-since", "if-none-match", "if-match",
    "dnt", "priority",
    # Response headers — version info is useful context for LLM, not sensitive
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-frame-options", "x-content-type-options", "x-xss-protection",
    "strict-transport-security", "content-security-policy",
    "access-control-allow-origin", "access-control-allow-methods",
    "vary", "etag", "last-modified", "date", "expires",
}

# Filesystem paths that are tool infrastructure, not client data.
# Values starting with these prefixes are never sensitive.
_SAFE_PATH_PREFIXES = (
    "/usr/share/wordlists/",
    "/usr/share/seclists/",
    "/usr/share/metasploit-framework/",
    "/opt/metasploit/",
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
    "/usr/local/bin/",
    "/var/www/html/",          # web roots being discussed as targets
    "/etc/passwd", "/etc/hosts", "/etc/shadow", "/etc/group",
)

# Query parameter keys that are never sensitive — analytics, pagination,
# display parameters. The value side is also safe by implication.
_SAFE_QUERY_PARAMS = {
    "biw", "bih", "opi", "ved", "uact", "sa", "source", "ei", "hl",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "page", "limit", "offset", "per_page", "sort", "order", "direction",
    "format", "locale", "lang", "currency",
    "hs_static_app", "hs_static_app_version",
}

# Known-safe value patterns for the KV detector —
# ping/traceroute output fields, version strings, etc.
_SAFE_KV_VALUE_RE = re.compile(
    r'^(?:'
    r'\d+\.\d+\.\d+\.\d+\s*\([^)]*\)'       # IP with hostname in parens
    r'|\d+\s*bytes\s+from'                    # ping output
    r'|icmp_seq=\d+'                          # ping sequence
    r'|ttl=\d+'                               # ping TTL
    r'|time=[\d.]+\s*ms'                      # ping time
    r'|Apache/[\d.]+'                         # server version strings
    r'|nginx/[\d.]+'
    r'|PHP/[\d.]+'
    r'|OpenSSL/[\d.]+'
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


def detect_high_entropy(text: str, is_peas: bool = False, cdn_spans: list | None = None) -> list[tuple[str, float]]:
    """Find high-entropy strings (≥20 chars, mixed charset, entropy ≥3.6).

    is_peas: when True, applies an additional whitelist pass to suppress
    architecture triplets, shared library names, and system paths that
    are structurally common in PEAS output but not client-identifying.
    cdn_spans: list of (start, end) spans of known-public CDN URLs to skip.
    """
    hits = []
    cdn_spans = cdn_spans or []
    uuid_spans = {m.span() for m in _RE_UUID.finditer(text)}

    for match in re.finditer(r"\b[A-Za-z0-9+/=_\-\.]{20,}\b", text):
        val = match.group()
        if val.lower() in _COMMON_FALSE_POSITIVES:
            continue
        if len(val) < 20:
            continue
        # Skip if within a UUID span
        if any(s <= match.start() and match.end() <= e for s, e in uuid_spans):
            continue
        # Skip if within a CDN URL span
        if any(s <= match.start() and match.end() <= e for s, e in cdn_spans):
            continue
        if not has_mixed_charset(val):
            continue
        entropy = compute_entropy(val)
        if entropy < 3.6:
            continue
        # Skip strings that look like HTTP header names —
        # e.g. "Upgrade-Insecure-Requests", "X-HubSpot-Static-App-Info"
        # Header names contain only letters, digits, and hyphens — and always
        # have at least one hyphen (distinguishes from base64/fingerprint values)
        if '-' in val and re.match(r'^[A-Za-z][A-Za-z0-9\-]{18,}$', val):
            continue
        # Skip filesystem paths that are tool infrastructure
        if '/' in val and any(
            val.startswith(p.lstrip('/')) or val.startswith(p)
            for p in _SAFE_PATH_PREFIXES
        ):
            continue
        # Skip key=value strings where key is a safe query param or
        # where value side is a safe filesystem path
        if '=' in val:
            eq_idx = val.index('=')
            k = val[:eq_idx].lower().lstrip('_').lstrip('-')
            v = val[eq_idx + 1:]
            if k in _SAFE_QUERY_PARAMS:
                continue
            if '/' in v and any(
                v.startswith(p.lstrip('/')) or v.startswith(p)
                for p in _SAFE_PATH_PREFIXES
            ):
                continue
        # PEAS mode: suppress known-benign architecture/library strings
        if is_peas and _PEAS_ENTROPY_WHITELIST.match(val):
            continue
        # Always suppress public CDN / analytics URLs
        if _PUBLIC_URL_WHITELIST.search(val):
            continue
        # Boost confidence if near a sensitivity keyword
        context_start = max(0, match.start() - 30)
        context = text[context_start: match.start()]
        if _SENSITIVITY_KEYWORDS.search(context):
            hits.append((val, entropy * 1.2))
        else:
            hits.append((val, entropy))
    return hits


def run_detections(text: str, formats: list[str] | None = None, custom_keywords: list[str] | None = None) -> list[Detection]:
    """
    Run all heuristic detectors. Return ordered list of Detections.
    formats: if supplied, enables format-specific detector adjustments.
    custom_keywords: per-engagement sensitive terms to always tokenise.
    """
    formats = formats or []
    custom_keywords = custom_keywords or []
    is_peas = "peas_linux" in formats or "peas_windows" in formats
    is_peas_win = "peas_windows" in formats

    detections = []
    seen_values = set()

    # Pre-collect spans of public CDN/analytics URLs so detectors can skip
    # matches that fall entirely within those spans. This prevents path
    # fragments like "5.0/dist/css/bootstrap.min.css" being flagged as secrets.
    _RE_FULL_URL = re.compile(
        r'(?:https?://|//)?(?:'
        r'cdnjs\.cloudflare\.com'
        r'|cdn\.jsdelivr\.net'
        r'|unpkg\.com'
        r'|ajax\.googleapis\.com'
        r'|fonts\.googleapis\.com'
        r'|fonts\.gstatic\.com'
        r'|stackpath\.bootstrapcdn\.com'
        r'|maxcdn\.bootstrapcdn\.com'
        r'|code\.jquery\.com'
        r'|cdn\.datatables\.net'
        r'|cdn\.cloudflare\.com'
        r'|static\.cloudflareinsights\.com'
        r'|www\.google-analytics\.com'
        r'|www\.googletagmanager\.com'
        r'|connect\.facebook\.net'
        r'|platform\.twitter\.com'
        r')[^\s\'"<>]*',
        re.IGNORECASE
    )
    cdn_spans = [m.span() for m in _RE_FULL_URL.finditer(text)]

    def in_cdn_span(start: int, end: int) -> bool:
        return any(s <= start and end <= e for s, e in cdn_spans)

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

    # KV secrets — skip if the value side is a public URL or within a CDN span,
    # and skip known-safe header names, filesystem tool paths, and analytics params
    for m in _RE_KV_SECRET.finditer(text):
        if in_cdn_span(m.start(), m.end()):
            continue
        val = m.group()
        parts = re.split(r'[=:]\s*', val, maxsplit=1)
        key_part   = parts[0].strip().lower().lstrip('-').lstrip('x-')
        value_part = parts[-1].strip() if len(parts) > 1 else ''

        # Skip standard HTTP headers
        if key_part in _SAFE_HTTP_HEADERS:
            continue
        # Also check with X- prefix stripped
        if key_part.replace('x-', '', 1) in _SAFE_HTTP_HEADERS:
            continue
        # Skip known-safe query parameter keys
        base_key = key_part.split('[')[0].split('.')[0]  # handle array params
        if base_key in _SAFE_QUERY_PARAMS:
            continue
        # Skip public URLs in value
        if _PUBLIC_URL_WHITELIST.search(value_part):
            continue
        if value_part.startswith(('http://', 'https://', '//')):
            continue
        # Skip tool filesystem paths in value
        if any(value_part.startswith(p) or ('/' + value_part).startswith(p)
               for p in _SAFE_PATH_PREFIXES):
            continue
        # Skip known-safe value patterns
        if _SAFE_KV_VALUE_RE.match(value_part):
            continue
        add("SECRET", val, 0.95)

    # Emails
    for m in _RE_EMAIL.finditer(text):
        add("EMAIL", m.group(), 0.95)

    # Private IPs
    for m in _RE_PRIV_IP.finditer(text):
        add("PRIV_IP", m.group(), 0.99)

    # Public IPs — skip safe/loopback/broadcast addresses and anything
    # already inside a tokenised cookie span (version numbers in CF tokens)
    cookie_spans = [m.span() for m in _RE_COOKIE.finditer(text)]
    for m in _RE_PUB_IP.finditer(text):
        ip = m.group()
        if ip in _SAFE_IPS:
            continue
        if _RE_PRIV_IP.match(ip):
            continue
        # Skip IPs embedded inside cookie values — they're version segments
        if any(s <= m.start() and m.end() <= e for s, e in cookie_spans):
            continue
        add("PUB_IP", ip, 0.7)

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

    # Domains — skip public CDN and analytics domains
    for m in _RE_DOMAIN.finditer(text):
        if in_cdn_span(m.start(), m.end()):
            continue
        val = m.group()
        if _PUBLIC_URL_WHITELIST.search(val):
            continue
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
    for val, entropy in detect_high_entropy(text, is_peas=is_peas, cdn_spans=cdn_spans):
        if not any(d.value == val for d in detections):
            add("SECRET", val, min(entropy / 6.0, 1.0), f"entropy={entropy:.2f}")

    # ── Custom engagement keywords ────────────────────────────────────────────
    # Per-engagement sensitive terms — always tokenised when found, case-insensitive.
    # Applied last so they can catch anything the standard detectors missed.
    for keyword in custom_keywords:
        if not keyword or len(keyword) < 2:
            continue
        # Case-insensitive search — use word boundary where possible
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        for m in pattern.finditer(text):
            val = m.group()  # preserve original casing from text
            if val not in seen_values and val.lower() not in _COMMON_FALSE_POSITIVES:
                add("CUSTOM", val, 1.0, f"custom_keyword:{keyword}")

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
    "JWT":         "JWT",
    "PATH_TRAV":   "PATH_TRAV",
    # JSON structured processor types
    "PASSWORD":    "PASSWORD",
    "SESSION":     "SESSION",
    "FILE_PATH":   "FILE_PATH",
    # Per-engagement custom keywords
    "CUSTOM":      "CUSTOM",
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
# FINDINGS GENERATOR — ALL FORMATS
# ─────────────────────────────────────────────

# Nmap: ports that should always trigger a finding
_FINDING_PORTS = {
    21:   ("ftp_exposed",          "MEDIUM", "FTP exposed — cleartext protocol, credentials sent unencrypted"),
    23:   ("telnet_exposed",       "HIGH",   "Telnet exposed — cleartext remote access, replace with SSH"),
    25:   ("smtp_exposed",         "LOW",    "SMTP exposed — verify relay configuration"),
    80:   ("http_no_tls",          "LOW",    "HTTP without TLS — verify redirect to HTTPS exists"),
    110:  ("pop3_exposed",         "MEDIUM", "POP3 exposed — cleartext mail protocol"),
    135:  ("rpc_exposed",          "MEDIUM", "RPC endpoint mapper exposed — common lateral movement vector"),
    139:  ("netbios_exposed",      "MEDIUM", "NetBIOS exposed — legacy Windows file sharing"),
    143:  ("imap_exposed",         "MEDIUM", "IMAP exposed — cleartext mail protocol"),
    389:  ("ldap_exposed",         "MEDIUM", "LDAP exposed — directory service, check for anonymous bind"),
    445:  ("smb_exposed",          "HIGH",   "SMB exposed — high-value target for lateral movement and ransomware"),
    512:  ("rexec_exposed",        "HIGH",   "rexec exposed — legacy cleartext remote execution"),
    513:  ("rlogin_exposed",       "HIGH",   "rlogin exposed — legacy cleartext remote login"),
    514:  ("rsh_exposed",          "HIGH",   "rsh/syslog exposed — legacy cleartext remote shell or logging"),
    1433: ("mssql_exposed",        "HIGH",   "MSSQL exposed directly — database should not be internet-facing"),
    1521: ("oracle_exposed",       "HIGH",   "Oracle DB exposed directly — database should not be internet-facing"),
    2049: ("nfs_exposed",          "HIGH",   "NFS exposed — check for world-readable/writable exports"),
    3306: ("mysql_exposed",        "HIGH",   "MySQL exposed directly — database should not be internet-facing"),
    3389: ("rdp_exposed",          "HIGH",   "RDP exposed — high-value target for brute force and exploitation"),
    4444: ("reverse_shell_port",   "HIGH",   "Port 4444 open — common reverse shell/Metasploit default"),
    5432: ("postgres_exposed",     "HIGH",   "PostgreSQL exposed directly — database should not be internet-facing"),
    5900: ("vnc_exposed",          "HIGH",   "VNC exposed — check authentication strength"),
    6379: ("redis_exposed",        "HIGH",   "Redis exposed — often unauthenticated, check for remote code execution"),
    8080: ("alt_http_exposed",     "LOW",    "Alt-HTTP on 8080 — often dev/admin interface"),
    8443: ("alt_https_exposed",    "LOW",    "Alt-HTTPS on 8443 — often admin interface"),
    9200: ("elasticsearch_exposed","HIGH",   "Elasticsearch exposed — often unauthenticated, check for data exposure"),
    27017:("mongodb_exposed",      "HIGH",   "MongoDB exposed — often unauthenticated, check for data exposure"),
}

# HTTP: security response headers that should be present
_EXPECTED_SECURITY_HEADERS = {
    "x-frame-options":           ("missing_xframe_options",   "MEDIUM", "X-Frame-Options missing — clickjacking risk"),
    "x-content-type-options":    ("missing_xcto",             "LOW",    "X-Content-Type-Options missing — MIME sniffing risk"),
    "strict-transport-security": ("missing_hsts",             "MEDIUM", "HSTS missing — downgrade attack risk"),
    "content-security-policy":   ("missing_csp",              "MEDIUM", "Content-Security-Policy missing — XSS/injection risk"),
    "x-xss-protection":          ("missing_xss_protection",   "LOW",    "X-XSS-Protection missing"),
    "referrer-policy":           ("missing_referrer_policy",  "LOW",    "Referrer-Policy missing — may leak sensitive URLs"),
}

# PEAS: patterns in sanitised output that indicate specific findings
_RE_SUID      = re.compile(r'(?i)suid\s+(?:binary|found|bit|executable)', )
_RE_NOPASSWD  = re.compile(r'NOPASSWD')
_RE_WRITABLE_CRON = re.compile(r'(?i)writable.*cron|cron.*writable')
_RE_SSH_KEY_FOUND = re.compile(r'(?i)(id_rsa|id_ecdsa|id_ed25519|\.pem)\s*$', re.MULTILINE)
_RE_SUDO_L    = re.compile(r'\(ALL\s*:\s*ALL\)\s*ALL')
_RE_PEAS_PASS = re.compile(r'(?i)password[s]?\s*(?:found|in|:)', )
_RE_ALWAYS_ELEVATED = re.compile(r'(?i)AlwaysInstallElevated.*(?:1|enabled)', re.DOTALL)
_RE_UNQUOTED_SVC    = re.compile(r'(?i)unquoted\s+(?:service|path)')
_RE_WEAK_SVC_PERM   = re.compile(r'(?i)(?:weak|modifiable)\s+service')


def generate_findings(
    text: str,
    sanitised: str,
    formats: list[str],
    detections: list[Detection],
) -> list[Finding]:
    """
    Generate security findings from sanitised output for all formats.
    Runs after tokenisation so it works on the sanitised text — sensitive
    values are already replaced with tokens but structure is preserved.
    """
    findings: list[Finding] = []
    det_types = {d.dtype for d in detections}

    # ── Nmap findings ────────────────────────────────────────────────────────
    if "nmap" in formats:
        # Extract open ports from sanitised output
        for m in re.finditer(r'(\d+)/tcp\s+open', sanitised, re.IGNORECASE):
            port = int(m.group(1))
            if port in _FINDING_PORTS:
                ftype, severity, detail = _FINDING_PORTS[port]
                findings.append(Finding(ftype=ftype, path=f"port/{port}", severity=severity, detail=detail))

        # SSH version check
        for m in re.finditer(r'SSH-1\.\d', sanitised):
            findings.append(Finding(
                ftype="ssh_v1_detected", path="ssh/version", severity="HIGH",
                detail="SSHv1 detected — obsolete, vulnerable to MITM and other attacks"
            ))

        # Large attack surface
        open_ports = re.findall(r'\d+/tcp\s+open', sanitised, re.IGNORECASE)
        if len(open_ports) > 15:
            findings.append(Finding(
                ftype="large_attack_surface", path="nmap/ports", severity="MEDIUM",
                detail=f"{len(open_ports)} open TCP ports — large attack surface, verify firewall rules"
            ))

    # ── HTTP findings ─────────────────────────────────────────────────────────
    if "http_request" in formats or "http_pair" in formats:
        # Basic auth in request
        for d in detections:
            if d.dtype == "AUTH_HEADER" and "Basic" in d.value:
                findings.append(Finding(
                    ftype="basic_auth_used", path="headers/Authorization", severity="MEDIUM",
                    detail="HTTP Basic authentication — credentials base64-encoded, not encrypted"
                ))
                break

        # Token/credential in query string
        if re.search(r'\?[^#\s]*(?:token|key|secret|password|auth|session)[=][^\s&]+', text, re.IGNORECASE):
            findings.append(Finding(
                ftype="credential_in_url", path="request/url", severity="HIGH",
                detail="Credential or token in URL query string — logged by proxies, servers, and browser history"
            ))

        # NTLM auth exposure
        for d in detections:
            if d.dtype == "AUTH_HEADER" and "NTLM" in d.value:
                findings.append(Finding(
                    ftype="ntlm_auth_exposed", path="headers/Authorization", severity="MEDIUM",
                    detail="NTLM authentication in use — susceptible to relay attacks and hash capture"
                ))
                break

    if "http_response" in formats or "http_pair" in formats:
        # Check for missing security headers
        response_part = sanitised
        if "http_pair" in formats and "━━━ RESPONSE" in sanitised:
            response_part = sanitised.split("━━━ RESPONSE")[1]

        present_headers = set(
            re.findall(r'^([a-zA-Z0-9\-]+):', response_part, re.MULTILINE)
        )
        present_lower = {h.lower() for h in present_headers}

        for header, (ftype, severity, detail) in _EXPECTED_SECURITY_HEADERS.items():
            if header not in present_lower:
                findings.append(Finding(ftype=ftype, path=f"headers/{header}", severity=severity, detail=detail))

        # Cookie without security attributes
        for m in re.finditer(r'(?i)set-cookie:\s*[^\r\n]+', response_part):
            cookie_line = m.group().lower()
            if "httponly" not in cookie_line:
                findings.append(Finding(
                    ftype="cookie_no_httponly", path="headers/Set-Cookie", severity="MEDIUM",
                    detail="Cookie set without HttpOnly — accessible via JavaScript, XSS risk"
                ))
                break
        for m in re.finditer(r'(?i)set-cookie:\s*[^\r\n]+', response_part):
            cookie_line = m.group().lower()
            if "secure" not in cookie_line:
                findings.append(Finding(
                    ftype="cookie_no_secure", path="headers/Set-Cookie", severity="MEDIUM",
                    detail="Cookie set without Secure flag — transmitted over HTTP"
                ))
                break

        # Server version disclosure
        for m in re.finditer(r'(?i)^server:\s*(.+)$', response_part, re.MULTILINE):
            val = m.group(1).strip()
            if re.search(r'\d+\.\d+', val):  # has version number
                findings.append(Finding(
                    ftype="server_version_disclosed", path="headers/Server", severity="LOW",
                    detail=f"Server header reveals version — aids fingerprinting and CVE matching"
                ))
                break

    # ── PEAS findings (Linux) ─────────────────────────────────────────────────
    if "peas_linux" in formats:
        if _RE_SUID.search(sanitised):
            findings.append(Finding(
                ftype="suid_binary_found", path="peas/suid", severity="HIGH",
                detail="SUID binary detected — potential privilege escalation vector, verify it is expected"
            ))
        if _RE_NOPASSWD.search(sanitised):
            findings.append(Finding(
                ftype="sudo_nopasswd", path="peas/sudo", severity="HIGH",
                detail="NOPASSWD sudo rule found — can execute commands as root without password"
            ))
        if _RE_WRITABLE_CRON.search(sanitised):
            findings.append(Finding(
                ftype="writable_cron_job", path="peas/cron", severity="HIGH",
                detail="Writable cron job or cron directory — can inject commands for privileged execution"
            ))
        if _RE_SSH_KEY_FOUND.search(sanitised):
            findings.append(Finding(
                ftype="ssh_private_key_found", path="peas/ssh", severity="HIGH",
                detail="SSH private key file found — may allow lateral movement or persistence"
            ))
        if _RE_SUDO_L.search(sanitised):
            findings.append(Finding(
                ftype="unrestricted_sudo", path="peas/sudo", severity="HIGH",
                detail="User has unrestricted sudo (ALL:ALL) — trivial privilege escalation"
            ))
        if _RE_PEAS_PASS.search(sanitised):
            findings.append(Finding(
                ftype="plaintext_creds_in_file", path="peas/files", severity="HIGH",
                detail="Credentials found in file — plaintext secrets in configuration or history"
            ))

    # ── PEAS findings (Windows) ───────────────────────────────────────────────
    if "peas_windows" in formats:
        if _RE_ALWAYS_ELEVATED.search(sanitised):
            findings.append(Finding(
                ftype="always_install_elevated", path="peas/registry", severity="HIGH",
                detail="AlwaysInstallElevated enabled — can install MSI packages as SYSTEM"
            ))
        if _RE_UNQUOTED_SVC.search(sanitised):
            findings.append(Finding(
                ftype="unquoted_service_path", path="peas/services", severity="HIGH",
                detail="Unquoted service path found — potential privilege escalation via path hijacking"
            ))
        if _RE_WEAK_SVC_PERM.search(sanitised):
            findings.append(Finding(
                ftype="weak_service_permissions", path="peas/services", severity="HIGH",
                detail="Weak service permissions — service binary or config may be modifiable"
            ))
        if _RE_PEAS_PASS.search(sanitised):
            findings.append(Finding(
                ftype="plaintext_creds_in_registry", path="peas/registry", severity="HIGH",
                detail="Credentials found — possible plaintext passwords in registry or config files"
            ))

    # ── secretsdump / NTLM findings ───────────────────────────────────────────
    if "secretsdump" in formats:
        ntlm_dets = [d for d in detections if d.dtype == "NTLM_HASH"]
        if ntlm_dets:
            # Check for null/empty hashes (known hash values for empty passwords)
            null_hashes = {"31d6cfe0d16ae931b73c59d7e0c089c0", "aad3b435b51404eeaad3b435b51404ee"}
            for d in ntlm_dets:
                parts = d.value.split(":")
                if len(parts) >= 4 and parts[3].lower() in null_hashes:
                    findings.append(Finding(
                        ftype="null_ntlm_hash", path="secretsdump/hashes", severity="HIGH",
                        detail=f"Null/empty NTLM hash for account — account has no password set"
                    ))
                    break
            # Check for admin accounts
            for d in ntlm_dets:
                account = d.value.split(":")[0].lower()
                if account in ("administrator", "admin", "domain admins"):
                    findings.append(Finding(
                        ftype="admin_hash_obtained", path="secretsdump/hashes", severity="HIGH",
                        detail=f"Administrative account hash obtained — Pass-the-Hash attack possible"
                    ))
                    break

    # ── Any format — JWT findings from sanitised text ─────────────────────────
    for d in detections:
        if d.dtype == "JWT":
            # alg:none check — token was already identified as JWT type
            findings.append(Finding(
                ftype="jwt_present", path=d.context or "jwt", severity="MEDIUM",
                detail="JWT token present in traffic — verify algorithm, expiry, and signature validation"
            ))

    # ── Any format — path traversal in sanitised text ─────────────────────────
    if _RE_PATH_TRAVERSAL.search(text):
        findings.append(Finding(
            ftype="path_traversal_detected", path="general", severity="HIGH",
            detail="Path traversal sequence (../) detected — potential directory traversal attack"
        ))

    # Deduplicate by ftype (keep first occurrence)
    seen_ftypes: set[str] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = f"{f.ftype}:{f.path}"
        if key not in seen_ftypes:
            seen_ftypes.add(key)
            deduped.append(f)

    return deduped

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
    r"|SECRET|LDAP|MAC|SSH_FP|KERNEL|JWT|PATH_TRAV|PASSWORD|SESSION|FILE_PATH"
    r"|REDACTED_BLOCK)_[0-9a-f]{8}\]"
    r"|\[REDACTED_BLOCK\]"
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
        if ip in _SAFE_IPS:
            continue
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

def run_pipeline(raw_text: str, salt: bytes, custom_keywords: list[str] | None = None) -> PipelineResult:
    custom_keywords = custom_keywords or []
    result = PipelineResult(sanitised="")

    # Stage 1: Pre-processing
    text, actions = preprocess(raw_text)
    result.actions.extend(actions)

    # Stage 2: Structured parsing / format detection
    result.formats_detected = detect_formats(text)

    # ── HTTP pair handling ──────────────────────────────────────────────────
    # If we detected a request+response pair, process each half separately
    # with the same salt so tokens are consistent across both sides, then
    # reassemble into a clearly labelled combined output.
    if "http_pair" in result.formats_detected:
        pair = split_http_pair(text)
        if pair:
            req_text, resp_text = pair
            result.actions.append("http_pair_split")

            # Check if response body is JSON — route through structured processor
            resp_body_match = re.search(r'\r?\n\r?\n(.+)$', resp_text, re.DOTALL)
            resp_body = resp_body_match.group(1).strip() if resp_body_match else ""
            resp_json_dets: list[Detection] = []
            resp_json_findings: list[Finding] = []
            if resp_body.startswith(('{', '[')):
                try:
                    json.loads(resp_body)
                    resp_san_body, resp_json_dets, resp_json_findings = process_json_structure(resp_body, salt)
                    resp_text = resp_text[:resp_body_match.start(1)] + resp_san_body
                    result.actions.append("http_pair_response_body_json_processed")
                except Exception:
                    pass

            # Process request half
            req_dets = run_detections(req_text, formats=result.formats_detected, custom_keywords=custom_keywords)
            req_san, req_dets = tokenise(req_text, req_dets, salt)

            # Process response half
            resp_dets = run_detections(resp_text, formats=result.formats_detected, custom_keywords=custom_keywords)
            req_values = {d.value for d in req_dets} | {d.value for d in resp_json_dets}
            resp_dets_new = [d for d in resp_dets if d.value not in req_values]
            resp_shared = [d for d in resp_dets if d.value in req_values]
            for d in resp_shared:
                matching = next((r for r in req_dets if r.value == d.value), None)
                if matching:
                    d.token = matching.token
            resp_san, resp_dets_new = tokenise(resp_text, resp_dets_new, salt)
            for d in resp_shared:
                resp_san = resp_san.replace(d.value, d.token)

            sanitised = (
                "━━━ REQUEST ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                + req_san
                + "\n\n━━━ RESPONSE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                + resp_san
            )

            all_detections = req_dets + resp_dets_new + resp_shared + resp_json_dets
            seen_tokens: set[str] = set()
            deduped = []
            for d in all_detections:
                if d.token not in seen_tokens:
                    seen_tokens.add(d.token)
                    deduped.append(d)

            result.detections  = deduped
            result.token_count = len(deduped)

            # Stage 5: Safety gate — runs before findings so risk scoring
            # is never influenced by the analytical layer
            risk, reasons, residual = residual_risk(sanitised, formats=result.formats_detected)
            result.risk_score      = risk
            result.risk_reasons    = reasons
            result.residual_findings = residual

            if risk == "HIGH":
                result.blocked = True
                result.actions.append("BLOCKED:high_residual_risk")

            result.sanitised = sanitised

            # Stage 6: Findings — post-sanitisation analytical pass
            # Separate from the safety determination above. Answers "what is
            # interesting here?" not "is this safe to send?".
            result.findings = (
                generate_findings(text, sanitised, result.formats_detected, deduped)
                + resp_json_findings
            )

            return result
    # ── End pair handling ───────────────────────────────────────────────────

    # Stage 3: Heuristic detection (format-aware)
    # ── JSON structured processing — runs before regex for JSON format ──────
    # For JSON input, use the structured processor which understands key context
    # and generates security findings. The regex pipeline then runs on the
    # already-sanitised JSON to catch anything in the surrounding text.
    if "json" in result.formats_detected:
        json_san, json_dets, json_findings = process_json_structure(text, salt)
        if json_dets or json_findings:
            regex_dets = run_detections(json_san, formats=result.formats_detected, custom_keywords=custom_keywords)
            json_seen  = {d.value for d in json_dets}
            new_regex  = [d for d in regex_dets if d.value not in json_seen]
            sanitised, new_regex = tokenise(json_san, new_regex, salt)
            all_dets = json_dets + new_regex
            result.detections  = all_dets
            result.token_count = len(all_dets)
            result.actions.append(f"json_structured_processing:{len(json_dets)}_structured")

            # Stage 5: Safety gate
            risk, reasons, residual = residual_risk(sanitised, formats=result.formats_detected)
            result.risk_score      = risk
            result.risk_reasons    = reasons
            result.residual_findings = residual
            if risk == "HIGH":
                result.blocked = True
                result.actions.append("BLOCKED:high_residual_risk")
            result.sanitised = sanitised

            # Stage 6: Findings — post-sanitisation analytical pass
            result.findings = json_findings + generate_findings(
                text, sanitised, result.formats_detected, all_dets
            )
            result.actions.append(f"findings_generated:{len(result.findings)}")
            return result

    detections = run_detections(text, formats=result.formats_detected, custom_keywords=custom_keywords)

    # Stage 4: Tokenisation
    sanitised, detections = tokenise(text, detections, salt)
    result.detections  = detections
    result.token_count = len(detections)

    # Stage 5: Residual risk analysis — safety gate
    # This runs before findings so risk scoring is never influenced
    # by the analytical layer. "Is this safe to send?" is answered here.
    risk, reasons, residual = residual_risk(sanitised, formats=result.formats_detected)
    result.risk_score      = risk
    result.risk_reasons    = reasons
    result.residual_findings = residual

    if risk == "HIGH":
        result.blocked = True
        result.actions.append("BLOCKED:high_residual_risk")

    result.sanitised = sanitised

    # Stage 6: Findings — post-sanitisation analytical pass
    # Answers "what is interesting here?" separately from the safety gate above.
    # Runs regardless of block status so findings are available for review
    # even when output is blocked.
    result.findings = generate_findings(text, sanitised, result.formats_detected, detections)

    return result
