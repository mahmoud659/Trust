"""
api.py
------
TrustCap FastAPI Verification Backend.

Responsibilities (FastAPI only):
  - Manifest field validation
  - SHA-256 recalculation from received image bytes
  - Image hash comparison against manifest
  - Digital signature verification using the submitted public key
  - Final authoritative VERIFIED / FAILED decision

Streamlit must NOT make verification decisions on its own.
All final results come from this endpoint.
"""

import base64
import hashlib
import json
from io import BytesIO

import uvicorn
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from services.manifest_service import ManifestService

app = FastAPI(
    title="TrustCap Verification API",
    description="Independent evidence verification service for the TrustCap prototype.",
    version="1.0.0",
)

# Allow requests from Streamlit (localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"service": "TrustCap Verification API", "status": "running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/verify")
async def verify_evidence(
    image: UploadFile = File(..., description="The captured image file"),
    manifest: str = Form(..., description="Manifest JSON string"),
    signature: str = Form(..., description="Base64-encoded ECDSA signature"),
    public_key: str = Form(..., description="PEM-encoded EC public key"),
):
    """
    Independently verify a TrustCap evidence package.

    Steps performed (in order):
    1. Parse and validate Manifest JSON structure.
    2. Recalculate SHA-256 from received image bytes.
    3. Compare server-calculated hash to manifest image_hash.
    4. Load provided public key and verify digital signature over canonical manifest.
    5. Return granular results for each check and a final VERIFIED flag.
    """
    errors = []
    manifest_valid = False
    hash_valid = False
    signature_valid = False
    server_hash = ""
    manifest_image_hash = ""
    claim_id = ""
    capture_id = ""
    key_id = ""

    # ── Step 1: Parse Manifest ──────────────────────────────────────────────
    try:
        manifest_dict = json.loads(manifest)
    except json.JSONDecodeError as e:
        errors.append(f"Manifest JSON parse error: {e}")
        return JSONResponse(
            status_code=200,
            content={
                "manifest_valid": False,
                "hash_valid": False,
                "signature_valid": False,
                "verified": False,
                "server_calculated_hash": "",
                "manifest_image_hash": "",
                "claim_id": "",
                "capture_id": "",
                "key_id": "",
                "errors": errors,
            },
        )

    manifest_valid = ManifestService.validate(manifest_dict)
    if not manifest_valid:
        errors.append(
            f"Manifest missing required fields. Required: {ManifestService.REQUIRED_FIELDS}"
        )

    claim_id = manifest_dict.get("claim_id", "")
    capture_id = manifest_dict.get("capture_id", "")
    manifest_image_hash = manifest_dict.get("image_hash", "")
    key_id = manifest_dict.get("key_id", "")

    # ── Step 2: Recalculate image SHA-256 ───────────────────────────────────
    try:
        image_bytes = await image.read()
        server_hash = hashlib.sha256(image_bytes).hexdigest()
    except Exception as e:
        errors.append(f"Failed to read image: {e}")
        server_hash = ""

    # ── Step 3: Compare hashes ──────────────────────────────────────────────
    if manifest_valid and server_hash:
        hash_valid = server_hash == manifest_image_hash
        if not hash_valid:
            errors.append(
                f"Image hash mismatch. "
                f"Server calculated: {server_hash[:16]}… | "
                f"Manifest contains: {manifest_image_hash[:16]}…"
            )

    # ── Step 4: Verify digital signature ────────────────────────────────────
    if manifest_valid:
        try:
            pub_key_obj = serialization.load_pem_public_key(public_key.encode("utf-8"))
        except Exception as e:
            errors.append(f"Failed to load public key: {e}")
            pub_key_obj = None

        if pub_key_obj is not None:
            try:
                canonical_bytes = ManifestService.canonicalize(manifest_dict)
                sig_bytes = base64.b64decode(signature)
                pub_key_obj.verify(sig_bytes, canonical_bytes, ec.ECDSA(hashes.SHA256()))
                signature_valid = True
            except InvalidSignature:
                signature_valid = False
                errors.append("Digital signature verification FAILED — manifest was tampered or wrong key used.")
            except Exception as e:
                signature_valid = False
                errors.append(f"Signature verification error: {e}")

    # ── Step 5: Final decision ───────────────────────────────────────────────
    verified = manifest_valid and hash_valid and signature_valid

    return JSONResponse(
        status_code=200,
        content={
            "manifest_valid": manifest_valid,
            "hash_valid": hash_valid,
            "signature_valid": signature_valid,
            "verified": verified,
            "server_calculated_hash": server_hash,
            "manifest_image_hash": manifest_image_hash,
            "claim_id": claim_id,
            "capture_id": capture_id,
            "key_id": key_id,
            "errors": errors,
        },
    )


if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
