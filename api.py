"""
api.py  (OPTIONAL)
------------------
The Streamlit app does NOT need this server — it calls
services/verification_service.py directly.

Run this only if another system (mobile app, partner, etc.) needs to verify
evidence over HTTP:
    pip install -r requirements-api.txt
    uvicorn api:app --port 8000

Both paths use the same verification code, so results are identical.
"""

import logging
from functools import lru_cache

import uvicorn
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool

from config import AIDetectionSettings, load_ai_detection_settings
from services.ai_detection_service import AIDetectionService
from services.verification_service import (
    MAX_IMAGE_BYTES,
    EvidenceInputError,
    detect_ai_standalone,
    verify_evidence,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(
    title="TrustCap Verification API",
    description="Optional HTTP wrapper around the TrustCap verification service.",
    version="1.2.0",
)


@lru_cache
def get_ai_settings() -> AIDetectionSettings:
    return load_ai_detection_settings()


@lru_cache
def get_ai_detection_service() -> AIDetectionService:
    return AIDetectionService(get_ai_settings())


async def read_image_limited(image: UploadFile) -> bytes:
    image_bytes = await image.read(MAX_IMAGE_BYTES + 1)
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail=f"Image exceeds {MAX_IMAGE_BYTES // (1024 * 1024)} MB limit.")
    return image_bytes


@app.get("/")
def root():
    return {"service": "TrustCap Verification API", "status": "running"}


@app.get("/health")
def health(settings: AIDetectionSettings = Depends(get_ai_settings)):
    return {
        "status": "ok",
        "ai_detection": {
            "provider": "resemble",
            "enabled": settings.enabled,
            "configured": settings.is_configured,
            "review_threshold": settings.review_threshold,
            "reject_threshold": settings.reject_threshold,
        },
    }


@app.post("/detect-ai")
async def detect_ai(
    image: UploadFile = File(...),
    detector: AIDetectionService = Depends(get_ai_detection_service),
):
    image_bytes = await read_image_limited(image)
    try:
        return await run_in_threadpool(detect_ai_standalone, image_bytes, detector)
    except EvidenceInputError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/verify")
async def verify(
    image: UploadFile = File(...),
    manifest: str = Form(...),
    signature: str = Form(...),
    public_key: str = Form(...),
    run_ai_check: bool = Form(True),
    detector: AIDetectionService = Depends(get_ai_detection_service),
    settings: AIDetectionSettings = Depends(get_ai_settings),
):
    image_bytes = await read_image_limited(image)
    try:
        return await run_in_threadpool(
            verify_evidence, image_bytes, manifest, signature, public_key, detector, settings, run_ai_check
        )
    except EvidenceInputError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


if __name__ == "__main__":
    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)
