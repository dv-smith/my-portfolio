# Evidence Sanitisation Gateway (ESG)

A local-first tool for penetration testing consultancies that need to use external LLMs during engagements without exposing client-identifying or sensitive data.

The system accepts raw pentest artefacts, strips sensitive values through a deterministic multi-stage pipeline, and produces sanitised output safe to paste into any LLM. LLM responses referencing token placeholders can be pasted back in for local de-tokenisation, restoring real values without those values ever having left the machine.

---

## Running

**Requirements:** Python 3.11 or 3.12

```bash
cd sanitiser
pip install -r requirements.txt
./start.sh
```

On Mac/Linux make the script executable first:

```bash
chmod +x start.sh
```

Then open **http://127.0.0.1:8000** in your browser.

On Windows, or if you prefer to skip the shell script:

```bash
cd sanitiser/backend
python main.py
```

On first run `backend/data/` is created automatically (mode 700). The Fernet encryption key and per-engagement salt files are written with mode 600. Back these up if token map recovery matters for an engagement — losing the key makes all stored mappings unrecoverable.

To run the test suite:

```bash
cd sanitiser/backend
python test_pipeline.py
# 59 tests, all stages covered
```

Stop the server with `Ctrl+C`. The database and key files persist in `backend/data/` — keep these alongside the engagement materials.

---

## The problem it solves

Pentest artefacts — Nmap output, HTTP captures, LDAP dumps, LinPEAS/WinPEAS enumeration — contain hostnames, IP addresses, credentials, and account names that identify the client. Pasting these directly into a commercial LLM is a data handling violation under most consultancy contracts and many data protection regulations.

Existing approaches are unsatisfying: manually redacting before pasting is slow and error-prone; not using LLMs at all forfeits a genuine productivity gain; using a self-hosted LLM adds significant infrastructure overhead.

ESG sits in between: it processes artefacts locally, replaces sensitive values with deterministic opaque tokens, and only the tokenised text ever leaves the machine. The LLM sees `[PRIV_IP_3a7f1b9c]` rather than `192.168.1.50`. The token map stays local and encrypted.

---

## Architecture

```
RAW INPUT
    │
    ▼
┌─────────────────────┐
│  1. Pre-processing  │  ANSI stripping, UTF-8 normalise,
│                     │  strip non-printables, URL/Base64 decode
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  2. Format parsing  │  Detect Nmap / HTTP / LDAP / JSON /
│                     │  LinPEAS / WinPEAS
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  3. Heuristic       │  Regex + entropy detection across 15+
│     detection       │  entity types; format-aware; confidence scoring
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  4. Tokenisation    │  HMAC-SHA256 deterministic tokens,
│                     │  longest-match-first substitution
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  5. Residual risk   │  Rescan sanitised output; format-aware
│     analysis        │  threshold; BLOCK / WARN / ALLOW
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  6. Audit logging   │  SHA-256 of input, token count, risk
│                     │  score, actions — no raw data stored
└────────┬────────────┘
         │
         ▼
SANITISED OUTPUT  ──►  LLM
                          │
                    LLM RESPONSE
                          │
                          ▼
                    De-tokenisation
                    (local, in-memory)
                          │
                          ▼
                    RESTORED OUTPUT
                    (internal use only)
```

All processing is in-memory. Raw input is never written to disk.

---

## File structure

```
sanitiser/
├── backend/
│   ├── main.py          # FastAPI application + API endpoints
│   ├── pipeline.py      # All six pipeline stages
│   ├── store.py         # Encrypted token store + audit log (SQLite)
│   └── test_pipeline.py # 59 unit tests covering all stages
├── frontend/
│   └── index.html       # Single-page UI (no build step required)
├── requirements.txt
├── start.sh
└── README.md
```

Runtime data written to `backend/data/` on first run:

```
backend/data/
├── sanitiser.db           # SQLite: token_mappings + audit_log tables
├── sanitiser.key          # Fernet symmetric key (mode 600)
└── salt_<engagement>.bin  # Per-engagement HMAC salt (mode 600)
```

---

## Workflow

### Engagement IDs

Every sanitisation run is scoped to an engagement ID — a string you set in the header before starting work. Use a consistent ID across a single engagement (e.g. `client-acme-2025`) so the same value always produces the same token and detokenisation works across sessions.

- Token mappings, audit records, and HMAC salts are all keyed to the engagement ID
- Tokens from one engagement are meaningless in another — different salts produce different tokens for the same value
- The ID defaults to `default` — a warning is shown in the header until you set a real one
- Do not mix engagements under the same ID

### Closing an engagement

When an engagement is complete, click **Close Engagement** in the header. This:

1. Permanently deletes all token mappings for that engagement from the database
2. Deletes the engagement salt file — existing tokens can no longer be reversed
3. Writes a close-out record to the audit log

The audit log entries are retained. Do this only when you no longer need to detokenise LLM responses for that engagement. There is no undo.

### Sanitising artefacts

1. Set an engagement ID in the header
2. Paste raw artefact output into the left panel, or use the Upload button — for HTTP traffic, paste the full request and response together (Burp Suite copy as text) and the tool will detect and process them as a pair
3. Click **▶ Sanitise**
4. Review the risk score, detected formats, and token count
5. Check the **Detections** tab to see what was found and tokenised
6. If output is blocked (HIGH risk), review the reasons and provide a written justification to override — the override is logged

### Using the prompt library

After sanitising, the right panel shows a dropdown of prompt templates grouped by format. Relevant templates for the detected format are marked with `●`. Select one to load it into the composer, then:

1. Click **Preview** to see the sanitised evidence injected at `{{EVIDENCE}}`
2. Click **Copy Prompt** — the full assembled prompt goes to your clipboard
3. Paste into any LLM

All prompt templates include an instruction telling the LLM to preserve token placeholders exactly as written (e.g. `[COOKIE_95f17a67]`), so they can be resolved during detokenisation.

### Detokenising LLM responses

1. Click **← Detokenise** in the input panel to switch modes
2. Paste the LLM response — token count is shown live as you paste
3. Click **↩ Detokenise**
4. The **Restored ⚠** tab shows real values restored inline — green for resolved, red for unresolved
5. A token resolution table below maps every token to its original value

Restored output contains real sensitive data and is never written to disk. Handle accordingly.

---

## Supported artefact formats

| Format | Detection signals |
|---|---|
| Nmap | `Nmap scan report for`, `PORT   STATE` headers |
| HTTP request | `GET/POST/… HTTP/x` request line |
| HTTP response | `HTTP/x.x 200` status line |
| HTTP pair | Request line + status line in same input — processed as a unit |
| JSON / API | Valid JSON object or array |
| LDAP / BloodHound | `CN=`, `OU=`, `DC=` distinguished name patterns |
| LinPEAS | `╔══╗` box headers, `[+]`/`[!]`/`[*]` markers, `Linux version` |
| WinPEAS | `╔══╗` box headers + `HKLM\`, `PowerShell`, `win32_` indicators |

Detection is additive — a single input can match multiple formats.

---

## Pipeline stages

### Stage 1 — Pre-processing

Normalises input before any detection runs. Steps execute in strict order:

- **ANSI escape stripping** — runs first. LinPEAS/WinPEAS output is heavily colour-coded; stripping `\x1b` character-by-character leaves the parameter bytes (`[1;31m`) as literal text that corrupts downstream regex. The full CSI/OSC/Fe pattern is stripped as a unit.
- **UTF-8 NFC normalisation** — consistent codepoint representation
- **Non-printable character removal** — strips control characters, preserves `\n \r \t`
- **URL decoding** — only if `%xx` patterns are present; rejected if result expands beyond 110% of original
- **Base64 decoding** — only if all four conditions hold: length ≥ 24, valid shape, ≥ 85% printable after decode, no abnormal expansion. No recursive decoding.

Each transformation is recorded in `actions[]` for the audit log.

### Stage 2 — Format detection

Identifies artefact format to guide the detection stage and surface relevant prompt templates. Detection is additive — a single input can match multiple formats.

### Stage 3 — Heuristic detection

Runs a priority-ordered set of detectors. Higher-priority patterns run first to prevent partial matches from clobbering their containing pattern.

| Type | Pattern | Confidence |
|---|---|---|
| `NTLM_HASH` | `user:RID:LM:NTLM` line | 1.00 |
| `HASH` | 64 / 40 / 32-char hex strings | 0.85–0.95 |
| `AUTH_HEADER` | `Authorization: Bearer/Basic/…` | 1.00 |
| `COOKIE` | `(Set-)Cookie:` header lines | 0.95 |
| `SECRET` | `password=`, `apikey=`, `token=` key-value pairs | 0.95 |
| `EMAIL` | RFC-ish email address | 0.95 |
| `PRIV_IP` | RFC1918 ranges (10.x, 172.16-31.x, 192.168.x) | 0.99 |
| `PUB_IP` | Public IPv4 (lower confidence — may be documentation) | 0.70 |
| `HOSTNAME` | `*.local`, `*.internal`, `*.corp`, `*.lan` etc. | 0.90 |
| `LDAP_DN` | `CN=…,OU=…,DC=…` distinguished names | 0.95 |
| `USER` | `username=` / `/home/user/` / `C:\Users\user\` | 0.80–0.92 |
| `DOMAIN` | Public TLD domain names | 0.60 |
| `MAC` | `xx:xx:xx:xx:xx:xx` interface MACs | 0.95 |
| `SSH_FP` | `SHA256:…` and `MD5:xx:xx:…` key fingerprints | 0.98 |
| `KERNEL` | Custom kernel build strings (>3 dash-separated segments) | 0.85 |
| `SECRET` (entropy) | ≥ 20 chars, mixed charset, Shannon entropy ≥ 3.6 bits/char | variable |

In PEAS mode the entropy detector applies an additional whitelist suppressing architecture triplets (`x86_64-linux-gnu`), shared library filenames, and system paths. UUIDs are skipped entirely. System accounts (`root`, `nobody`, `www-data`, `daemon`, `public`, `default` etc.) are excluded from path-embedded username detection.

### Stage 4 — Tokenisation

**Token format:** `[PREFIX_xxxxxxxx]` where `xxxxxxxx` is the first 8 hex chars of `HMAC-SHA256(engagement_salt, raw_value)`.

Example tokens: `[PRIV_IP_3a7f1b9c]`, `[USER_ab12cd34]`, `[MAC_cc3d4e5f]`, `[SSH_FP_11223344]`

- **Deterministic within an engagement** — same input always produces the same token
- **Engagement-scoped** — different engagements use different 32-byte random salts
- **Collision-resistant** — HMAC-SHA256 truncated to 32 bits
- **Substitution order** — longest value first, preventing substring clobbering

### Stage 5 — Residual risk analysis

Rescans sanitised output as an independent safety gate. Already-tokenised placeholders are masked before scanning.

| Score | Condition | Action |
|---|---|---|
| `HIGH` | Any residual hash, or ≥ 15 findings (PEAS) / ≥ 5 findings (other) | Blocked |
| `MEDIUM` | 1–4 findings (non-PEAS) / 3–14 findings (PEAS) | Allowed with warning |
| `LOW` | No findings | Allowed |

HIGH is a hard block at the API layer. Override requires explicit written justification, which is recorded in the audit log.

### Stage 6 — Audit logging

Every run writes a record to SQLite. Raw input is never stored — only its SHA-256 hash.

Stored: timestamp, input_sha256, input_size, formats_detected, token_count, risk_score, risk_reasons, residual_findings, blocked, actions, engagement_id.

---

## Prompt library

13 templates grouped by format. Relevant templates are marked with `●` after sanitisation.

| Format | Prompts |
|---|---|
| Nmap | Attack Surface Summary, Vulnerability Mapping |
| HTTP Pair | Full Transaction Analysis, Auth Flow Analysis |
| HTTP | Vulnerability Review, Auth & Session Analysis |
| JSON / API | Response Analysis |
| LDAP / BloodHound | Path Analysis |
| LinPEAS | Privilege Escalation Triage, Persistence & Lateral Movement |
| WinPEAS | Privilege Escalation Triage, Credential Harvest & Persistence |
| Generic | Findings Narrative, IoC Extraction, Executive Summary |

All templates instruct the LLM to preserve token placeholders exactly — do not shorten or modify them — so detokenisation works on the response.

---

## De-tokenisation

The `/api/detokenise` endpoint:
1. Queries all token mappings for the engagement from SQLite
2. Decrypts each original value using the Fernet key
3. Replaces all `[TYPE_xxxxxxxx]` occurrences in the text with their real values
4. Returns the restored text, substitution count, and any unresolved tokens

Uses a character-offset alignment algorithm: the tokenised input is split on the token pattern to produce interleaved `[literal, token, literal…]` segments, then the restored string is walked in parallel. Correctly handles adjacent tokens, repeated tokens, and tokens at string boundaries.

Restored text is never written to disk or the audit log.

---

## Security model

**What the system guarantees:**

- Raw input never touches disk, a database, or a network socket
- Sanitised output is the only thing the API returns for export
- HIGH-risk output is blocked at the API layer, not just the UI
- Token mappings are encrypted at rest (Fernet / AES-128-CBC + HMAC-SHA256)
- Per-engagement salts mean token values are meaningless outside their engagement context
- Every run is auditable without storing the underlying data
- Override of a HIGH block requires explicit written justification, which is logged
- De-tokenised output is never persisted anywhere
- Engagement close-out permanently purges token mappings and deletes the engagement salt

**What the system does not guarantee:**

- **Perfect anonymisation** — context, structure, and naming conventions may still allow inference of the client. The goal is removing direct identifiers, not producing formally anonymous data.
- **Complete detection coverage** — heuristic detectors handle common formats well. Novel or obfuscated output may not be fully sanitised; the residual risk gate provides a second check but is not exhaustive.
- **Protection against a compromised local machine** — the Fernet key is stored as a file. On a compromised host an attacker with filesystem access can read both the key and the encrypted mappings.

**Deployment constraints:**

The server binds to `127.0.0.1` only and has no authentication layer. This is appropriate for single-analyst local use. Do not run on a shared machine or expose over a network without adding authentication first.

---

## Cryptographic components

| Component | Algorithm | Purpose |
|---|---|---|
| Token generation | HMAC-SHA256, truncated to 32 bits | Deterministic, engagement-scoped token IDs |
| Token map encryption | Fernet (AES-128-CBC + HMAC-SHA256) | Encrypt original values at rest |
| Key storage | 32-byte random key, file mode 0600 | Local key management baseline |
| Engagement salts | 32-byte `os.urandom()`, file mode 0600 | Scope token space per engagement |
| Audit identity | SHA-256 of raw input | Identify inputs without storing them |

---

## API endpoints

All endpoints bind to `127.0.0.1:8000`. CORS is restricted to `localhost` and `127.0.0.1`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Serves the UI |
| `POST` | `/api/sanitise` | Run the full pipeline on raw input |
| `POST` | `/api/detokenise` | Restore tokens in LLM output to real values |
| `GET` | `/api/engagements` | List all engagements with token counts |
| `DELETE` | `/api/engagement/{id}` | Close engagement — purge mappings and salt |
| `GET` | `/api/token-map/{engagement_id}` | Return decrypted token→original mappings |
| `GET` | `/api/audit-log` | All audit records (latest 50) |
| `GET` | `/api/audit-log/{engagement_id}` | Audit records for one engagement |
| `GET` | `/api/health` | Liveness check |
| `GET` | `/api/docs` | Auto-generated OpenAPI docs |

### `POST /api/sanitise`

```json
{
  "text": "...",
  "engagement_id": "client-acme-2025",
  "override_block": false,
  "override_reason": null
}
```

`override_block: true` requires a non-empty `override_reason`. The justification is logged.

### `POST /api/detokenise`

```json
{
  "text": "LLM response referencing [PRIV_IP_3a7f1b9c] ...",
  "engagement_id": "client-acme-2025"
}
```

Returns `restored` text, `substitution_count`, and `unresolved_tokens`.

### `DELETE /api/engagement/{id}`

Purges all token mappings for the engagement and deletes the salt file. Audit log is retained. No request body required.

---

## Dependencies

```
fastapi          # API framework
uvicorn          # ASGI server
cryptography     # Fernet encryption
python-multipart # File upload support
pydantic         # Request/response validation
```

No LLM dependencies. No telemetry. No outbound network calls of any kind.

The frontend loads fonts from Google Fonts on startup. For air-gapped deployments, remove or replace the two `@import` font references at the top of `frontend/index.html`.
