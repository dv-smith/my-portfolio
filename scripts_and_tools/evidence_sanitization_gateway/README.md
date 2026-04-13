# Evidence Sanitisation Gateway (ESG)

A local-first tool for penetration testing consultancies that need to use external LLMs during engagements without exposing client-identifying or sensitive data.

The system accepts raw pentest artefacts, strips sensitive values through a deterministic multi-stage pipeline, and produces sanitised output safe to paste into any LLM. LLM responses referencing token placeholders can be pasted back in for local de-tokenisation, restoring real values without those values ever having left the machine.

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
│   ├── pipeline.py      # All six pipeline stages
│   ├── store.py         # Encrypted token store + audit log (SQLite)
│   ├── main.py          # FastAPI application + endpoints
│   └── test_pipeline.py # 59 unit tests covering all stages
├── frontend/
│   └── index.html       # Single-page UI (no build step)
├── requirements.txt
├── start.sh
└── README.md
```

Runtime data written to `backend/data/` (created on first run, mode 700):

```
backend/data/
├── sanitiser.db             # SQLite: token_mappings + audit_log
├── sanitiser.key            # Fernet symmetric key (mode 600)
└── salt_<engagement>.bin    # Per-engagement HMAC salt (mode 600)
```

---

## Running

```bash
pip install -r requirements.txt
./start.sh
```

Then open **http://127.0.0.1:8000**

On Windows, or if you prefer to skip the shell script:

```bash
cd backend
python main.py
```

Run tests:

```bash
cd backend
python test_pipeline.py
# 59 tests, all stages covered
```

---

## Pipeline stages

### Stage 1 — Pre-processing

Normalises input before detection runs. Key steps in order:

- **ANSI escape stripping** — runs first, before anything else. LinPEAS/WinPEAS output is heavily colour-coded; stripping `\x1b` character-by-character leaves the parameter bytes (`[1;31m`) as literal text and breaks every downstream regex. The full CSI/OSC/Fe pattern is stripped cleanly as a unit.
- **UTF-8 NFC normalisation**
- **Non-printable character removal** — strips control characters, preserves `\n \r \t`
- **URL decoding** — only if `%xx` patterns are present; rejected if result expands beyond 110% of original
- **Base64 decoding** — only if all four conditions hold: length ≥ 24, valid shape, ≥ 85% printable after decode, no abnormal expansion. No recursive decoding.

Each transformation is recorded in `actions[]` for the audit log.

### Stage 2 — Format detection

Identifies artefact format to guide the detection stage and surface relevant prompt library cards.

Recognised formats: `json`, `http_request`, `http_response`, `nmap`, `ldap`, `peas_linux`, `peas_windows`.

Detection is additive — a single input can match multiple formats (e.g. an HTTP response with a JSON body).

PEAS detection uses box-drawing characters (`╔`, `╚`, `╠`) as the primary signal, with `[+]`/`[!]`/`[*]` marker density as a fallback. Linux vs. Windows is disambiguated by content (`Linux version`/`linpeas` vs. `HKLM\`/`PowerShell`/`win32_`).

### Stage 3 — Heuristic detection

Runs a priority-ordered set of detectors. Higher-priority patterns are matched first to prevent partial matches from being tokenised before their containing pattern.

| Type | Pattern | Confidence |
|---|---|---|
| `NTLM_HASH` | `user:RID:LM:NTLM` line | 1.00 |
| `HASH` | 64 / 40 / 32-char hex strings | 0.85–0.95 |
| `AUTH_HEADER` | `Authorization: Bearer/Basic/…` | 1.00 |
| `COOKIE` | `(Set-)Cookie:` header lines | 0.95 |
| `SECRET` | `password=`, `apikey=`, `token=` key-value pairs | 0.95 |
| `EMAIL` | Standard RFC-ish email address | 0.95 |
| `PRIV_IP` | RFC1918 ranges (10.x, 172.16-31.x, 192.168.x) | 0.99 |
| `PUB_IP` | Public IPv4 (lower confidence — may be documentation) | 0.70 |
| `HOSTNAME` | `*.local`, `*.internal`, `*.corp`, `*.lan` etc. | 0.90 |
| `LDAP_DN` | `CN=…,OU=…,DC=…` distinguished names | 0.95 |
| `USER` | `username=` / `/home/user/` / `C:\Users\user\` | 0.80–0.92 |
| `DOMAIN` | Public TLD domain names | 0.60 |
| `MAC` | `xx:xx:xx:xx:xx:xx` / `xx-xx-xx-xx-xx-xx` interface MACs | 0.95 |
| `SSH_FP` | `SHA256:…` and `MD5:xx:xx:…` key fingerprints | 0.98 |
| `KERNEL` | Custom kernel build strings (>3 dash-separated segments) | 0.85 |
| `SECRET` (entropy) | ≥ 20 chars, mixed charset, Shannon entropy ≥ 3.6 bits/char | variable |

**PEAS-specific behaviour:** entropy detector applies an additional whitelist suppressing architecture triplets (`x86_64-linux-gnu`), shared library filenames, and system paths. UUIDs are skipped entirely — common in hardware/interface sections and not client-identifying.

System accounts (`root`, `nobody`, `www-data`, `daemon`, `public`, `default` etc.) are excluded from path-embedded username detection.

### Stage 4 — Tokenisation

Replaces each detected value with a deterministic opaque token.

**Token format:** `[PREFIX_xxxxxxxx]` where `xxxxxxxx` is the first 8 hex chars of `HMAC-SHA256(engagement_salt, raw_value)`.

Example tokens: `[PRIV_IP_3a7f1b9c]`, `[USER_ab12cd34]`, `[MAC_cc3d4e5f]`, `[SSH_FP_11223344]`

Properties:
- **Deterministic within an engagement** — same input always produces the same token
- **Engagement-scoped** — different engagements use different 32-byte random salts
- **Collision-resistant** — HMAC-SHA256 truncated to 32 bits
- **Substitution order** — longest value first, preventing substring clobbering

### Stage 5 — Residual risk analysis

Rescans sanitised output as an independent safety gate. Already-tokenised placeholders are masked before scanning.

Residual detectors: IP addresses, hex strings (hashes), structural hostnames (`dc1`, `web01`), client keywords (`corp`, `internal`, `staging`), MAC addresses.

| Score | Condition | Action |
|---|---|---|
| `HIGH` | Any residual hash, or ≥ 15 findings (PEAS) / ≥ 5 findings (other) | Blocked |
| `MEDIUM` | 1–4 findings (non-PEAS) / 3–14 findings (PEAS) | Allowed with warning |
| `LOW` | No findings | Allowed |

HIGH is a hard block at the API layer. Override requires explicit written justification, which is recorded in the audit log.

### Stage 6 — Audit logging

Every run writes a record to SQLite. Raw input text is never stored — only its SHA-256 hash.

Stored: timestamp, input_sha256, input_size, formats_detected, token_count, risk_score, risk_reasons, residual_findings, blocked, actions, engagement_id.

---

## Prompt library

The UI includes 13 purpose-built prompt templates that surface automatically based on the detected format. After sanitising, the relevant cards are highlighted and can be loaded into the prompt composer, which injects the sanitised evidence at the `{{EVIDENCE}}` placeholder and copies the assembled prompt to clipboard.

| Format | Prompts |
|---|---|
| Nmap | Attack Surface Summary, Vulnerability Mapping |
| HTTP | Vulnerability Review, Auth & Session Analysis |
| JSON / API | Response Analysis |
| LDAP / BloodHound | Path Analysis |
| LinPEAS | Privilege Escalation Triage, Persistence & Lateral Movement |
| WinPEAS | Privilege Escalation Triage, Credential Harvest & Persistence |
| Generic | Findings Narrative, IoC Extraction, Executive Summary |

---

## De-tokenisation

When the LLM returns a response referencing token placeholders, switch to **← Detokenise** mode, paste the response, and hit **↩ Detokenise**. The app restores real values from the local encrypted store and renders the result with green highlights for resolved tokens and red for any that couldn't be matched (wrong engagement ID, or token not generated by this instance).

The restored output is never written to disk or the audit log.

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

### `POST /api/detokenise`

```json
{
  "text": "LLM response referencing [PRIV_IP_3a7f1b9c] ...",
  "engagement_id": "client-acme-2025"
}
```

Returns `restored` text, `substitution_count`, and `unresolved_tokens`.

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


A local-first tool for penetration testing consultancies that need to use external LLMs during engagements without exposing client-identifying or sensitive data.

The system accepts raw pentest artefacts, strips sensitive values through a deterministic multi-stage pipeline, and produces sanitised output safe to paste into any LLM. LLM responses referencing token placeholders can be pasted back in for local de-tokenisation, restoring real values without those values ever having left the machine.

---

## The problem it solves

Pentest artefacts — Nmap output, secretsdump hashes, HTTP captures, LDAP dumps, LinPEAS/WinPEAS enumeration — contain hostnames, IP addresses, credentials, and account names that identify the client. Pasting these directly into a commercial LLM is a data handling violation under most consultancy contracts and many data protection regulations.

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
│  2. Format parsing  │  Detect Nmap / secretsdump / HTTP /
│                     │  LDAP / JSON / LinPEAS / WinPEAS
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
│     analysis        │  scoring LOW / MEDIUM / HIGH; hard-block on HIGH
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  6. Audit log       │  SHA-256 of input, token count, risk
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

## Running

### Requirements

Python 3.11 or 3.12.

```bash
python3 --version
```

### Install and start

```bash
cd sanitiser
pip install -r requirements.txt
./start.sh
```

On Mac/Linux make the script executable first:

```bash
chmod +x start.sh
./start.sh
```

Open **http://127.0.0.1:8000** in your browser.

On first run, `backend/data/` is created automatically (mode 700). The Fernet encryption key and per-engagement salt files are written with mode 600. Back these up if token map recovery matters for an engagement — losing the key makes all stored mappings unrecoverable.

### Run tests

```bash
cd sanitiser/backend
python test_pipeline.py
# 59 tests, all stages covered
```

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

### Sanitising artefacts

1. Set an **engagement ID** in the header (top right) — this scopes all token mappings. Use a consistent ID across a single engagement so the same value always produces the same token.
2. Paste raw artefact output into the left panel, or use the Upload button.
3. Click **▶ Sanitise**.
4. Review the risk score, detected formats, and token count in the output panel.
5. Check the **Detections** tab to see what was found and tokenised.
6. If the output is blocked (HIGH risk), review the reasons and provide a written justification to override. The override is logged.

### Using the prompt library

After sanitising, the right panel shows format-matched prompt templates with a green relevance dot. Click a card to load it into the composer, then:

1. Click **Preview** to see the sanitised evidence injected at `{{EVIDENCE}}`.
2. Click **Copy Prompt** — the full assembled prompt goes to your clipboard.
3. Paste into any LLM.

### Detokenising LLM responses

1. Click **← Detokenise** in the top left to switch modes.
2. Paste the LLM response (it will reference tokens like `[PRIV_IP_3a7f1b9c]`).
3. Click **↩ Detokenise**.
4. The **Restored ⚠** tab appears — real values are restored with green highlights. Any tokens that couldn't be matched (wrong engagement ID, or not generated by this instance) appear in red.

The restored output contains real sensitive data and is never written to disk. Handle accordingly.

---

## Supported artefact formats

| Format | Detection signals |
|---|---|
| Nmap | `Nmap scan report for`, `PORT   STATE` headers |
| secretsdump | `user:RID:LM:NTLM` line structure |
| HTTP request | `GET/POST/… HTTP/1.x` request line |
| HTTP response | `HTTP/1.x 200` status line |
| JSON / API | Valid JSON object or array |
| LDAP / BloodHound | `CN=`, `OU=`, `DC=` distinguished name patterns |
| LinPEAS | `╔══╗` box headers, `[+]`/`[!]`/`[*]` markers, `Linux version` |
| WinPEAS | `╔══╗` box headers + `HKLM\`, `PowerShell`, `win32_` indicators |

Detection is additive — a single input can match multiple formats.

---

## Pipeline stages

### Stage 1 — Pre-processing

Normalises input before any detection runs.

- **ANSI escape stripping** — runs first. LinPEAS/WinPEAS output is heavily colour-coded; stripping `\x1b[...m` sequences before anything else ensures the `[1;31m` parameter bytes don't survive as literal text that would corrupt downstream regex matching.
- **UTF-8 NFC normalisation** — consistent codepoint representation.
- **Non-printable character removal** — strips control characters, preserves `\n \r \t`.
- **URL decoding** — only if `%xx` patterns are present; rejected if result expands beyond 110% of original.
- **Base64 decoding** — only if all four conditions hold: length ≥ 24, valid shape, ≥ 85% printable after decode, no abnormal expansion. No recursive decoding.

Each transformation is recorded in `actions[]` for the audit log.

### Stage 2 — Format detection

Identifies artefact format to guide the detection stage and surface relevant prompt library cards.

Detection is additive — a single input can match multiple formats (e.g. an HTTP response with a JSON body, or a secretsdump output mixed with Nmap).

### Stage 3 — Heuristic detection

Runs a priority-ordered set of detectors. Higher-priority patterns are matched first to prevent partial matches from being tokenised before their containing pattern.

| Type | Pattern | Confidence |
|---|---|---|
| `NTLM_HASH` | `user:RID:LM:NTLM` secretsdump line | 1.00 |
| `HASH` | 64 / 40 / 32-char hex strings | 0.85–0.95 |
| `AUTH_HEADER` | `Authorization: Bearer/Basic/…` | 1.00 |
| `COOKIE` | `(Set-)Cookie:` header lines | 0.95 |
| `SECRET` | `password=`, `apikey=`, `token=` key-value pairs | 0.95 |
| `EMAIL` | Standard RFC-ish email address | 0.95 |
| `PRIV_IP` | RFC1918 ranges (10.x, 172.16-31.x, 192.168.x) | 0.99 |
| `PUB_IP` | Public IPv4 (lower confidence — may be documentation) | 0.70 |
| `HOSTNAME` | `*.local`, `*.internal`, `*.corp`, `*.lan` etc. | 0.90 |
| `LDAP_DN` | `CN=…,OU=…,DC=…` distinguished names | 0.95 |
| `USER` | `username=` / `/home/user/` / `C:\Users\user\` | 0.80–0.92 |
| `DOMAIN` | Public TLD domain names | 0.60 |
| `MAC` | `xx:xx:xx:xx:xx:xx` / `xx-xx-xx-xx-xx-xx` interface MACs | 0.95 |
| `SSH_FP` | `SHA256:…` and `MD5:xx:xx:…` key fingerprints | 0.98 |
| `KERNEL` | Custom kernel build strings (>3 dash-separated segments) | 0.85 |
| `SECRET` (entropy) | High-entropy strings ≥ 20 chars, mixed charset, H ≥ 3.6 bits/char | variable |

**PEAS-specific behaviour:** in LinPEAS/WinPEAS mode, the entropy detector applies an additional whitelist pass suppressing architecture triplets (`x86_64-linux-gnu`), shared library filenames, and system paths that structurally resemble secrets but are not client-identifying. UUIDs are also skipped entirely — they appear frequently in hardware/interface sections and are not sensitive in isolation.

System accounts (`root`, `nobody`, `www-data`, `daemon`, `public`, `default`, etc.) are excluded from path-embedded username detection.

### Stage 4 — Tokenisation

Replaces each detected value with a deterministic opaque token.

**Token format:** `[PREFIX_xxxxxxxx]` where `xxxxxxxx` is the first 8 hex chars of `HMAC-SHA256(engagement_salt, raw_value)`.

Example tokens: `[PRIV_IP_3a7f1b9c]`, `[USER_ab12cd34]`, `[NTLM_ff00aa11]`, `[MAC_cc3d4e5f]`

Properties:
- **Deterministic within an engagement** — same input value always produces the same token, so the LLM sees consistent references across a session.
- **Engagement-scoped** — different engagements use different 32-byte random salts, so tokens from one engagement are meaningless in another.
- **Collision-resistant** — HMAC-SHA256 truncated to 32 bits; collision probability across typical engagement token counts is negligible.
- **Substitution order** — detections sorted by value length descending before substitution, preventing a shorter value that is a substring of a longer one from partially clobbering it.

Token mappings are persisted to SQLite with the original value Fernet-encrypted at rest.

### Stage 5 — Residual risk analysis

Rescans the sanitised output as an independent safety gate, catching anything the detection stage missed. Already-tokenised `[TYPE_xxxxxxxx]` placeholders are masked before scanning.

Residual detectors: IP addresses, 32–64 char hex strings (hashes), structural hostname patterns (`dc1`, `web01`, `sql03`), client-identifying keywords (`corp`, `internal`, `staging`), MAC addresses.

**Risk scoring:**

| Score | Condition | Action |
|---|---|---|
| `HIGH` | Any residual hash, or ≥ 15 findings (PEAS) / ≥ 5 findings (other formats) | Blocked by default |
| `MEDIUM` | 1–4 findings (non-PEAS) / 3–14 findings (PEAS) | Allowed with warning |
| `LOW` | No findings | Allowed |

The HIGH threshold is raised to 15 for LinPEAS/WinPEAS output, which is inherently dense and will produce more structural findings than targeted captures like HTTP traffic. Residual hashes trigger HIGH regardless of format.

HIGH is a hard block at the API layer. Override requires explicit written justification, which is recorded in the audit log.

### Stage 6 — Audit logging

Every sanitisation and de-tokenisation run writes a record to the `audit_log` SQLite table. Raw input text is never stored — only its SHA-256 hash for identity.

Stored fields: timestamp, input_sha256, input_size, formats_detected, token_count, risk_score, risk_reasons, residual_findings, blocked, actions, engagement_id.

---

## De-tokenisation

When the LLM returns a response referencing token placeholders, ESG can restore the real values locally.

The `/api/detokenise` endpoint:
1. Queries all token mappings for the engagement from SQLite
2. Decrypts each original value using the Fernet key
3. Replaces all `[TYPE_xxxxxxxx]` occurrences in the text with their real values
4. Returns the restored text, substitution count, and any unresolved tokens

The restoration uses a character-offset alignment algorithm: the tokenised input is split on the token pattern to produce interleaved `[literal, token, literal…]` segments, then the restored string is walked in parallel to precisely extract each replacement. This correctly handles adjacent tokens, repeated tokens, and tokens at string boundaries.

The UI renders resolved tokens in green and unresolved tokens in red, with a full token resolution table below the annotated text. Restored text is never written to disk or the audit log.

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

**What the system does not guarantee:**

- **Perfect anonymisation** — context, structure, and naming conventions in the artefact may still allow a reader to infer the client. The goal is removing direct identifiers, not producing formally anonymous data.
- **Complete detection coverage** — the heuristic detectors handle common pentest artefact formats well. Novel or obfuscated output may not be fully sanitised; the residual risk gate provides a second check but is not exhaustive.
- **Protection against a compromised local machine** — the Fernet key is stored as a file. On a compromised host, an attacker with filesystem access can read both the key and the encrypted mappings.

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

Fernet is a pragmatic baseline. For higher-assurance or team deployments, replace with OS keychain integration or HSM-backed key storage.

---

## API endpoints

All endpoints bind to `127.0.0.1:8000`. CORS is restricted to `localhost` and `127.0.0.1`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Serves the UI |
| `POST` | `/api/sanitise` | Run the full pipeline on raw input |
| `POST` | `/api/detokenise` | Restore tokens in LLM output to real values |
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

Returns `restored` text, `substitution_count`, and `unresolved_tokens` (tokens present in the text but not in the local store for this engagement).

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

The frontend loads fonts from Google Fonts on startup. For air-gapped deployments, remove or replace the two `@import` font references at the top of `frontend/index.html` with locally-hosted equivalents.
