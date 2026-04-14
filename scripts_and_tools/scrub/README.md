# scrub

> **This tool provides risk reduction, not anonymisation.** scrub removes direct identifiers such as hostnames, IPs, credentials, and account names. It does not prevent a capable LLM from inferring context from structure or content that remains after sanitisation. Use it to reduce accidental exposure of client data, not as a guarantee of complete confidentiality.

---

## TL;DR

scrub is a local-first sanitisation layer for LLM-assisted pentest reporting. It tokenises sensitive data (IPs, creds, hostnames, etc.), sends only safe output to the LLM, then detokenises responses locally — producing ready-to-use findings without exposing client data.

---

## Why this exists

LLMs are becoming part of the pentest workflow, especially for report writing. They save time, improve structure, and help standardise output.

The problem is that pentest artefacts contain sensitive client data. Pasting raw output into an external LLM risks exposing IPs, credentials, internal infrastructure, and other identifying details.

In practice, people already do this. The trade-off is speed versus risk.

scrub exists to remove that trade-off. It allows you to use LLMs for reporting without sending real client data outside your machine.

---

## What it does

**scrub sits between your raw artefacts and the LLM.** Paste your input — Nmap output, HTTP captures, secretsdump, LinPEAS, LDAP dumps, JSON responses — and sensitive values are stripped locally before anything leaves the machine. IPs, hostnames, credentials, hashes, and account names are replaced with deterministic opaque tokens. The token map stays local and encrypted.

The primary use case is **report writing**. After sanitisation, the built-in prompt composer assembles a structured prompt targeting your report format — description, recommendation, and suggested field values — ready to copy into your LLM. Paste the response back into scrub to detokenise and restore real values locally before adding it to your report.

There is also a **query mode** for free-form questions against the sanitised artefact — useful for triage or lateral movement analysis without structuring it as a finding.

**What scrub is not:** a prompt library, an analysis engine, or an LLM wrapper. It is a sanitisation layer with a prompt export step. The LLM call happens in your own tool.

---

## Quick start

**Requirements:** Python 3.11 or 3.12

```bash
cd sanitiser
pip install -r requirements.txt
./start.sh
```

Open **http://127.0.0.1:8000**

```bash
# Mac/Linux — make executable first
chmod +x start.sh

# Windows, or skip the script
cd sanitiser/backend && python main.py
```

On first run `backend/data/` is created automatically (mode 700). The Fernet encryption key and per-engagement salt files are written with mode 600. Back these up if token map recovery matters for an active engagement — losing the key makes all stored mappings unrecoverable.

---

## Workflow in three steps

1. Set an engagement ID in the header. Click **Client** to enter client details — name variations are registered as keywords automatically and the report context field is pre-filled. Add any additional keywords via **Keywords**.
2. Paste a raw artefact → **▶ Sanitise** → review the risk score and detections.
3. Switch to **Report** or **Query** mode in the right panel → add context → **Copy Prompt** → paste into your LLM.

When the LLM response returns, switch to **← Detokenise**, paste it in, and real values are restored locally from the encrypted token store.

When the engagement is complete, click **Close** to permanently purge all token mappings and the engagement salt.

---

## How it works

### Pipeline

Every sanitisation run passes through five stages in sequence.

```
RAW INPUT
    │
    ▼
┌─────────────────────┐
│  1. Pre-processing  │  ANSI stripping, UTF-8 NFC normalise,
│                     │  non-printable removal, URL/Base64 decode
│                     │  (Base64 skipped if input is valid JSON
│                     │   — prevents JWT corruption)
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  2. Format detect   │  Nmap, HTTP request/response/pair,
│                     │  secretsdump, LDAP, JSON, LinPEAS, WinPEAS
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  3. Detection       │  Regex + entropy heuristics (all formats)
│                     │  + structured JSON tree traversal
│                     │  + per-engagement custom keywords
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  4. Tokenisation    │  HMAC-SHA256 deterministic tokens
│                     │  [TYPE_xxxxxxxx], longest-match-first
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  5. Residual risk   │  Rescan sanitised output (safety gate)
│     (safety gate)   │  HIGH → blocked  MEDIUM → warning  LOW → clear
└────────┬────────────┘
         │
         ▼
   SANITISED OUTPUT
         │
         ▼
   Prompt composer → copy → paste into LLM
         │
   LLM response → paste into Detokenise tab
         │
         ▼
   RESTORED OUTPUT (local only, never persisted)
```

### Detection types

Priority-ordered within stage 3. Earlier types suppress later ones on the same span.

| Token prefix | What it catches |
|---|---|
| `NTLM` | NTLM hash strings |
| `HASH` | MD5, SHA-1, SHA-256, bcrypt, other hash formats |
| `AUTH` | Authorization headers (Bearer, Basic, NTLM, Negotiate) |
| `COOKIE` | Cookie header values |
| `SECRET` | Key-value secrets (`api_key=`, `password=`, etc.) |
| `EMAIL` | Email addresses |
| `PRIV_IP` | RFC 1918 private IP addresses |
| `PUB_IP` | Public IP addresses |
| `HOST` | Hostnames and FQDNs |
| `LDAP` | LDAP distinguished names |
| `USER` | Username patterns |
| `DOMAIN` | Windows domain names |
| `MAC` | MAC addresses |
| `SSH_FP` | SSH fingerprints |
| `KERNEL` | Kernel version strings |
| `SECRET` | High-entropy strings (entropy detector, runs last) |
| `CUSTOM` | Per-engagement keywords |

**JSON structured processor** runs alongside stage 3 for JSON input. It walks the full tree with dot-path context (`auth.jwt.token`, `users[0].password`) and applies key-based redaction — any value under a sensitive key (`password`, `api_key`, `token`, `session`, etc.) is tokenised regardless of its format. Block-level keys (`debug`, `env`, `stack_trace`) redact the entire subtree to `[REDACTED_BLOCK]`.

**HTTP pair handling** — when input contains both a request line and an HTTP status line, scrub splits them, processes each half independently, then reassembles with `━━━ REQUEST ━━━` / `━━━ RESPONSE ━━━` dividers. Shared values produce the same token (HMAC is deterministic). The response body is routed through the JSON processor if it is valid JSON.

**False positive suppressions** — CDN URLs, safe IPs (127.0.0.1, 0.0.0.0, RFC 5737 ranges), standard HTTP headers, safe filesystem paths, safe query parameters, and header-name-shaped strings are all suppressed before detection runs.

### Tokenisation

```
[PREFIX_xxxxxxxx]
```

Tokens are HMAC-SHA256(engagement_salt, original_value), truncated to 32 bits (8 hex chars). The salt is a 32-byte random value generated once per engagement and stored at `backend/data/salt_<engagement>.bin` (mode 600).

Deterministic within an engagement: the same value always produces the same token. Meaningless across engagements: different salts produce different tokens for the same value. Substitution is longest-match-first to prevent partial replacements.

### Safety gate (stage 5)

Rescans the sanitised output as an independent check after tokenisation. Already-tokenised placeholders are masked before scanning so they do not contribute to the score.

| Score | Condition | Outcome |
|---|---|---|
| `HIGH` | Any residual hash, or ≥ 15 findings (PEAS) / ≥ 5 findings (other) | Hard block |
| `MEDIUM` | 1–4 findings (non-PEAS) / 3–14 (PEAS) | Allowed with warning |
| `LOW` | Nothing found | Allowed |

HIGH is a hard block at the API layer — not just the UI. Override requires explicit written justification, which is written to the audit log.

### Prompt composer

Two modes, both export a plain text prompt for copy-paste. No LLM calls are made from scrub.

**Report mode** — assembles a structured prompt targeting a three-part finding format:

```
---DESCRIPTION START---
[Generic description of the vulnerability type]
[Specific description in context, including reproduction steps]
[Business impact]
---DESCRIPTION END---

---RECOMMENDATION START---
[Specific remediation advice]
---RECOMMENDATION END---

---SUGGESTED VALUES START---
Title:
Category:
Overall Risk:
Impact:
Exploitability:
---SUGGESTED VALUES END---

Context: [your assessment context]

Evidence:
[sanitised artefact]
```

**Query mode** — free-form question + sanitised artefact appended. No structure imposed.

Both modes display a live preview with the evidence block highlighted. Copy sends the real sanitised output, not the preview placeholder.

### Detokenisation

Paste an LLM response containing `[TYPE_xxxxxxxx]` placeholders into the Detokenise tab. scrub queries the encrypted token store for the engagement, decrypts each original value, and substitutes in-place. Uses a character-offset alignment algorithm — correctly handles adjacent tokens, repeated tokens, and tokens at string boundaries.

Restored output is never written to disk or the audit log.

### Engagement management

**Engagement ID** — set in the header before starting work. Use a consistent ID for the full engagement (e.g. `client-acme-2025`). All token mappings, audit records, and the HMAC salt are scoped to this ID. Tokens from one engagement cannot be detokenised under another.

**Client profile** — click the Client button to set identifying information for the engagement: full legal name, short/trading name, domain, NetBIOS, assessment type, assessor/firm, and period. On save, name variations are automatically registered as custom keywords and the report context field is pre-filled if empty. Stored per-engagement and purged on close.

**Custom keywords** — client-specific terms added via the Keywords button. Applied to every sanitise run for that engagement. Useful for internal application names, service account prefixes, codenames, or anything that identifies the client but would not match a generic pattern. Stored per-engagement in the local database.

**Close engagement** — permanently deletes all token mappings, the client profile, custom keywords, and the engagement salt for that ID. Audit log is retained. No undo.

---

### File structure

```
sanitiser/
├── backend/
│   ├── main.py          # FastAPI application + all API endpoints
│   ├── pipeline.py      # All five pipeline stages
│   ├── store.py         # Encrypted token store + audit log (SQLite)
│   └── test_pipeline.py # 107 tests covering all stages
├── frontend/
│   └── index.html       # Single-page UI — no build step
├── requirements.txt
├── start.sh
└── README.md
```

Runtime data written to `backend/data/` on first run:

```
backend/data/
├── sanitiser.db           # SQLite: token_mappings, audit_log, custom_keywords, client_profile
├── sanitiser.key          # Fernet symmetric key (mode 600)
└── salt_<engagement>.bin  # Per-engagement HMAC salt (mode 600)
```

These files are excluded from git via `.gitignore`. Do not commit them. Back up the key and salt files if token map recovery matters for an active engagement — losing the key makes all stored mappings unrecoverable.

---

### Security model

**What scrub guarantees:**

- Raw input never touches disk, the database, or a network socket
- Sanitised output is the only thing returned for export
- HIGH-risk output is blocked at the API layer, not just the UI
- Token mappings are Fernet-encrypted at rest (AES-128-CBC + HMAC-SHA256)
- Per-engagement salts scope the token space — tokens are meaningless outside their engagement
- Every run is auditable without storing the underlying data (SHA-256 hash only)
- Override of a HIGH block requires written justification, logged
- Detokenised output is never persisted anywhere
- Engagement close-out permanently purges mappings, client profile, keywords, and the engagement salt

**What scrub does not guarantee:**

- **Anonymisation** — direct identifiers are removed. Context, structure, and naming conventions in the artefact may still allow inference of the client.
- **Complete detection coverage** — heuristic detectors handle common pentest artefact formats well. Novel or obfuscated output may not be fully sanitised. The safety gate provides a second check but is not exhaustive.
- **Protection against a compromised local machine** — the Fernet key is a file on disk. An attacker with filesystem access can read both the key and the encrypted mappings.

**Deployment:** The server binds to `127.0.0.1` only and has no authentication layer. Appropriate for single-analyst local use. Do not expose over a network or run on a shared machine without adding authentication.

---

### Cryptographic components

| Component | Algorithm | Purpose |
|---|---|---|
| Token generation | HMAC-SHA256, truncated to 32 bits | Deterministic engagement-scoped token IDs |
| Token map encryption | Fernet (AES-128-CBC + HMAC-SHA256) | Encrypt original values at rest |
| Key storage | 32-byte random key, mode 0600 | Local key management baseline |
| Engagement salts | 32-byte `os.urandom()`, mode 0600 | Scope token space per engagement |
| Audit identity | SHA-256 of raw input | Identify runs without storing input |

---

### API endpoints

All endpoints bind to `127.0.0.1:8000`. CORS restricted to `localhost` and `127.0.0.1`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Serves the UI |
| `POST` | `/api/sanitise` | Run the full pipeline on raw input |
| `POST` | `/api/detokenise` | Restore tokens in LLM output to real values |
| `GET` | `/api/engagements` | List engagements with token counts |
| `DELETE` | `/api/engagement/{id}` | Close engagement — purge mappings, profile, keywords, and salt |
| `GET` | `/api/engagement/{id}/keywords` | List custom keywords |
| `POST` | `/api/engagement/{id}/keywords` | Add a custom keyword |
| `DELETE` | `/api/engagement/{id}/keywords/{keyword}` | Remove a custom keyword |
| `GET` | `/api/engagement/{id}/client` | Get client profile |
| `POST` | `/api/engagement/{id}/client` | Save client profile |
| `GET` | `/api/token-map/{engagement_id}` | Decrypted token → original mappings |
| `GET` | `/api/audit-log` | All audit records (latest 50) |
| `GET` | `/api/audit-log/{engagement_id}` | Audit records for one engagement |
| `GET` | `/api/health` | Liveness check |
| `GET` | `/api/docs` | Auto-generated OpenAPI docs |

---

### Dependencies

```
fastapi          # API framework
uvicorn          # ASGI server
cryptography     # Fernet encryption
python-multipart # File upload support
pydantic         # Request/response validation
```

No LLM dependencies. No telemetry. No outbound network calls.

The frontend loads IBM Plex Mono, IBM Plex Sans, and Architects Daughter from Google Fonts on startup. For air-gapped deployments, remove the font import line at the top of `frontend/index.html` and substitute local font references or system fonts.
