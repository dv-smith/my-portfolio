"""
Local encrypted token store + audit log.
Raw input is NEVER persisted.
"""

import json
import hashlib
import os
import sqlite3
import time
from pathlib import Path
from cryptography.fernet import Fernet


_HERE     = Path(__file__).parent
DB_PATH   = _HERE / "data" / "sanitiser.db"
KEY_PATH  = _HERE / "data" / "sanitiser.key"
SALT_PATH = _HERE / "data" / "sanitiser.salt"


def _ensure_dirs():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────
# KEY MANAGEMENT
# ─────────────────────────────────────────────

def load_or_create_key() -> bytes:
    """Load Fernet key from disk or generate new one. File is 0600."""
    _ensure_dirs()
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    KEY_PATH.write_bytes(key)
    KEY_PATH.chmod(0o600)
    return key


def load_or_create_salt(engagement_id: str) -> bytes:
    """Per-engagement HMAC salt. Different engagements → different tokens."""
    _ensure_dirs()
    salt_file = SALT_PATH.parent / f"salt_{engagement_id}.bin"
    if salt_file.exists():
        return salt_file.read_bytes()
    salt = os.urandom(32)
    salt_file.write_bytes(salt)
    salt_file.chmod(0o600)
    return salt


# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────

def init_db():
    _ensure_dirs()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Token mappings (encrypted originals)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS token_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            dtype TEXT NOT NULL,
            encrypted_original BLOB NOT NULL,
            engagement_id TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    """)

    # Audit log — no raw data
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            input_sha256 TEXT NOT NULL,
            input_size INTEGER NOT NULL,
            formats_detected TEXT NOT NULL,
            token_count INTEGER NOT NULL,
            risk_score TEXT NOT NULL,
            risk_reasons TEXT NOT NULL,
            residual_findings TEXT NOT NULL,
            blocked INTEGER NOT NULL,
            actions TEXT NOT NULL,
            engagement_id TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# TOKEN STORE OPERATIONS
# ─────────────────────────────────────────────

def save_token_mappings(detections, engagement_id: str, fernet: Fernet):
    """Persist encrypted token → original mappings."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    now = time.time()

    for d in detections:
        encrypted = fernet.encrypt(d.value.encode("utf-8"))
        # Upsert: only insert if token not already stored for this engagement
        cur.execute("""
            INSERT OR IGNORE INTO token_mappings
            (token, dtype, encrypted_original, engagement_id, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (d.token, d.dtype, encrypted, engagement_id, now))

    conn.commit()
    conn.close()


def get_token_map(engagement_id: str, fernet: Fernet) -> list[dict]:
    """Retrieve decrypted token mappings for an engagement."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT token, dtype, encrypted_original, created_at
        FROM token_mappings WHERE engagement_id = ?
        ORDER BY created_at DESC
    """, (engagement_id,))
    rows = cur.fetchall()
    conn.close()

    result = []
    for token, dtype, enc_orig, created_at in rows:
        try:
            original = fernet.decrypt(enc_orig).decode("utf-8")
        except Exception:
            original = "[decryption error]"
        result.append({
            "token": token,
            "type": dtype,
            "original": original,
            "created_at": created_at
        })
    return result


# ─────────────────────────────────────────────
# AUDIT LOG
# ─────────────────────────────────────────────

def write_audit_log(raw_input: str, pipeline_result, engagement_id: str):
    """Write audit record. Raw input is hashed, never stored."""
    input_sha256 = hashlib.sha256(raw_input.encode("utf-8")).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audit_log
        (timestamp, input_sha256, input_size, formats_detected, token_count,
         risk_score, risk_reasons, residual_findings, blocked, actions, engagement_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        time.time(),
        input_sha256,
        len(raw_input.encode("utf-8")),
        json.dumps(pipeline_result.formats_detected),
        pipeline_result.token_count,
        pipeline_result.risk_score,
        json.dumps(pipeline_result.risk_reasons),
        json.dumps(pipeline_result.residual_findings),
        1 if pipeline_result.blocked else 0,
        json.dumps(pipeline_result.actions),
        engagement_id,
    ))
    conn.commit()
    conn.close()


def detokenise_text(text: str, engagement_id: str, fernet: Fernet) -> tuple[str, int, list[str]]:
    """
    Replace all known tokens in text with their decrypted originals.
    Returns (restored_text, substitution_count, unresolved_tokens).

    Only operates against the local encrypted store for this engagement.
    The restored output must NEVER leave the machine — caller's responsibility.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT token, encrypted_original FROM token_mappings WHERE engagement_id = ?",
        (engagement_id,)
    )
    rows = cur.fetchall()
    conn.close()

    # Build token → original map (decrypt each)
    mapping = {}
    for token, enc_orig in rows:
        try:
            original = fernet.decrypt(enc_orig).decode("utf-8")
            mapping[token] = original
        except Exception:
            pass  # Skip unmappable entries silently

    # Find all [TYPE_xxxxxxxx] patterns in the text
    import re
    token_pattern = re.compile(r"\[[A-Z_]+_[0-9a-f]{8}\]")
    found_tokens   = set(token_pattern.findall(text))
    unresolved     = [t for t in found_tokens if t not in mapping]

    # Substitute longest tokens first (safety, though all are fixed-width here)
    result = text
    count  = 0
    for token, original in sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True):
        if token in result:
            result = result.replace(token, original)
            count += 1

    return result, count, unresolved


def write_detokenise_audit(text: str, engagement_id: str, count: int, unresolved: list[str]):
    """Log a detokenisation event. Restored text is never stored."""
    import hashlib, json
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()
    # Reuse audit_log table — mark as detokenise event via a dedicated risk_score value
    cur.execute("""
        INSERT INTO audit_log
        (timestamp, input_sha256, input_size, formats_detected, token_count,
         risk_score, risk_reasons, residual_findings, blocked, actions, engagement_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        time.time(),
        hashlib.sha256(text.encode()).hexdigest(),
        len(text.encode()),
        json.dumps([]),
        count,
        "DETOKENISE",
        json.dumps(unresolved),
        json.dumps([]),
        0,
        json.dumps([f"detokenised:{count}_substitutions", f"unresolved:{len(unresolved)}"]),
        engagement_id,
    ))
    conn.commit()
    conn.close()


def get_audit_log(engagement_id: str | None = None, limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if engagement_id:
        cur.execute("""
            SELECT * FROM audit_log WHERE engagement_id = ?
            ORDER BY timestamp DESC LIMIT ?
        """, (engagement_id, limit))
    else:
        cur.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    for r in rows:
        r["formats_detected"] = json.loads(r["formats_detected"])
        r["risk_reasons"] = json.loads(r["risk_reasons"])
        r["residual_findings"] = json.loads(r["residual_findings"])
        r["actions"] = json.loads(r["actions"])

    return rows
