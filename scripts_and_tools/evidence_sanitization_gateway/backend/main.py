"""
Evidence Sanitisation Gateway — FastAPI application.
Fully local. No external network calls.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from cryptography.fernet import Fernet
from pathlib import Path
import time

from pipeline import run_pipeline, PipelineResult
from store import (
    init_db, load_or_create_key, load_or_create_salt,
    save_token_mappings, get_token_map,
    write_audit_log, get_audit_log,
    detokenise_text, write_detokenise_audit,
)

# ─── Init ────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Evidence Sanitisation Gateway",
    description="Local-first pentest artefact sanitiser. No data leaves this machine.",
    version="1.0.0",
    docs_url="/api/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()
FERNET_KEY = load_or_create_key()
_fernet = Fernet(FERNET_KEY)


# ─── Request / Response Models ───────────────────────────────────────────────

class SanitiseRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=500_000)
    engagement_id: str = Field(default="default", min_length=1, max_length=64)
    override_block: bool = Field(default=False)
    override_reason: Optional[str] = Field(default=None, max_length=500)


class DetectionOut(BaseModel):
    type: str
    token: str
    confidence: float
    context: str


class SanitiseResponse(BaseModel):
    sanitised: str
    blocked: bool
    risk_score: str
    risk_reasons: list[str]
    residual_findings: list[str]
    formats_detected: list[str]
    token_count: int
    actions: list[str]
    detections: list[DetectionOut]
    override_applied: bool = False


class TokenMapResponse(BaseModel):
    engagement_id: str
    mappings: list[dict]


class DetokeniseRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=500_000)
    engagement_id: str = Field(default="default", min_length=1, max_length=64)


class DetokeniseResponse(BaseModel):
    restored: str
    substitution_count: int
    unresolved_tokens: list[str]
    engagement_id: str


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    """Serve the single-page frontend."""
    html_path = Path(__file__).parent.parent / "frontend" / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>UI not found. Run from project root.</h1>", status_code=404)


@app.post("/api/sanitise", response_model=SanitiseResponse)
async def sanitise(req: SanitiseRequest):
    """
    Main sanitisation endpoint.
    HIGH risk output is BLOCKED unless override_block=True with reason.
    """
    if req.override_block and not req.override_reason:
        raise HTTPException(
            status_code=400,
            detail="override_reason is required when override_block=True"
        )

    # Load per-engagement salt
    salt = load_or_create_salt(req.engagement_id)

    # Run the pipeline
    result: PipelineResult = run_pipeline(req.text, salt)

    # Override gate
    override_applied = False
    if result.blocked and req.override_block:
        result.blocked = False
        result.actions.append(f"OVERRIDE_APPLIED by user: {req.override_reason}")
        override_applied = True

    # Persist token mappings (encrypted)
    save_token_mappings(result.detections, req.engagement_id, _fernet)

    # Write audit log (no raw input stored)
    write_audit_log(req.text, result, req.engagement_id)

    # Never return the sanitised text if still blocked
    sanitised_out = result.sanitised if not result.blocked else "[OUTPUT BLOCKED — HIGH RISK]"

    return SanitiseResponse(
        sanitised=sanitised_out,
        blocked=result.blocked,
        risk_score=result.risk_score,
        risk_reasons=result.risk_reasons,
        residual_findings=result.residual_findings,
        formats_detected=result.formats_detected,
        token_count=result.token_count,
        actions=result.actions,
        detections=[
            DetectionOut(
                type=d.dtype,
                token=d.token,
                confidence=d.confidence,
                context=d.context,
            )
            for d in result.detections
        ],
        override_applied=override_applied,
    )


@app.post("/api/detokenise", response_model=DetokeniseResponse)
async def detokenise(req: DetokeniseRequest):
    """
    Reverse a tokenised LLM response back to real values using the local
    encrypted store for this engagement.

    The restored output contains real sensitive data.
    It is returned to the local UI only — never logged or persisted.
    """
    restored, count, unresolved = detokenise_text(req.text, req.engagement_id, _fernet)

    # Audit the event (no restored content stored)
    write_detokenise_audit(req.text, req.engagement_id, count, unresolved)

    return DetokeniseResponse(
        restored=restored,
        substitution_count=count,
        unresolved_tokens=unresolved,
        engagement_id=req.engagement_id,
    )


@app.get("/api/token-map/{engagement_id}", response_model=TokenMapResponse)
async def token_map(engagement_id: str):
    """
    Return the decrypted token → original mapping for an engagement.
    Sensitive — local access only by design.
    """
    mappings = get_token_map(engagement_id, _fernet)
    return TokenMapResponse(engagement_id=engagement_id, mappings=mappings)


@app.get("/api/audit-log")
async def audit_log_all(limit: int = 50):
    return get_audit_log(limit=min(limit, 200))


@app.get("/api/audit-log/{engagement_id}")
async def audit_log_engagement(engagement_id: str, limit: int = 50):
    return get_audit_log(engagement_id=engagement_id, limit=min(limit, 200))


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "local_only": True,
        "telemetry": False,
        "timestamp": time.time(),
    }


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
