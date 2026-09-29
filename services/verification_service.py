"""
verification_service.py
-----------------------
The single source of truth for evidence verification. Used directly by the
Streamlit app (no server needed) and, optionally, wrapped by api.py.

Steps:
  1. Parse and validate the manifest JSON.
  2. Recalculate SHA-256 from the image bytes.
  3. Compare it to manifest.image_hash.
  4. Verify the ECDSA signature over the canonical manifest.
  5. Integrity decision (`verified`).
  6. AI-generation check — only when integrity passed (a tampered package is
     rejected anyway, so no API call is spent on it).
  7. Overall `trust_verdict`: TRUSTED / REVIEW / REJECTED.

The returned dict keeps the exact shape of the original /verify response,
plus `ai_detection`, `trust_verdict` and `trust_reasons`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from config import AIDetectionSettings
from services.ai_detection_service import STATUS_SKIPPED, AIDetectionResult, AIDetectionService
from services.manifest_service import ManifestService
from services.trust_policy import decide_trust

MAX_IMAGE_BYTES = 20 * 1024 * 1024  # 20 MB — evidence photos are far smaller


class EvidenceInputError(ValueError):
    """Raised for inputs that cannot be processed at all (e.g. oversized image)."""


def _check_image_size(image_bytes: bytes) -> None:
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise EvidenceInputError(f"Image exceeds {MAX_IMAGE_BYTES // (1024 * 1024)} MB limit.")


def verify_evidence(
    image_bytes: bytes,
    manifest_json: str,
    signature_b64: str,
    public_key_pem: str,
    detector: AIDetectionService,
    settings: AIDetectionSettings,
    run_ai_check: bool = True,
) -> dict[str, Any]:
    _check_image_size(image_bytes)

    errors: list[str] = []
    manifest_valid = hash_valid = signature_valid = False
    server_hash = manifest_image_hash = claim_id = capture_id = key_id = ""

    # ── Step 1: Parse manifest ──────────────────────────────────────────────
    try:
        manifest = json.loads(manifest_json)
        if not isinstance(manifest, dict):
            raise ValueError("Manifest must be a JSON object.")
    except (json.JSONDecodeError, ValueError) as error:
        errors.append(f"Manifest JSON parse error: {error}")
        manifest = None

    if manifest is not None:
        manifest_valid = ManifestService.validate(manifest)
        if not manifest_valid:
            errors.append(f"Manifest missing required fields. Required: {ManifestService.REQUIRED_FIELDS}")
        claim_id = str(manifest.get("claim_id", ""))
        capture_id = str(manifest.get("capture_id", ""))
        manifest_image_hash = str(manifest.get("image_hash", ""))
        key_id = str(manifest.get("key_id", ""))

    # ── Step 2: Recalculate image SHA-256 ───────────────────────────────────
    if image_bytes:
        server_hash = hashlib.sha256(image_bytes).hexdigest()
    else:
        errors.append("Received an empty image.")

    # ── Step 3: Compare hashes ──────────────────────────────────────────────
    if manifest_valid and server_hash:
        hash_valid = server_hash == manifest_image_hash
        if not hash_valid:
            errors.append(
                "Image hash mismatch. "
                f"Calculated: {server_hash[:16]}… | Manifest contains: {manifest_image_hash[:16]}…"
            )

    # ── Step 4: Verify digital signature ────────────────────────────────────
    if manifest_valid:
        signature_valid = _verify_signature(manifest, signature_b64, public_key_pem, errors)

    # ── Step 5: Integrity decision ──────────────────────────────────────────
    verified = manifest_valid and hash_valid and signature_valid

    # ── Step 6: AI-generation check ─────────────────────────────────────────
    if manifest is None:
        ai_result = AIDetectionResult(status=STATUS_SKIPPED, reason="Manifest could not be parsed.")
    elif not verified:
        ai_result = AIDetectionResult(status=STATUS_SKIPPED, reason="Skipped because cryptographic integrity failed.")
    elif not run_ai_check:
        ai_result = AIDetectionResult(status=STATUS_SKIPPED, reason="AI check was not requested.")
    else:
        ai_result = detector.analyze(image_bytes)

    # ── Step 7: Overall trust verdict ───────────────────────────────────────
    decision = decide_trust(verified, ai_result, settings)

    return {
        "manifest_valid": manifest_valid,
        "hash_valid": hash_valid,
        "signature_valid": signature_valid,
        "verified": verified,
        "server_calculated_hash": server_hash,
        "manifest_image_hash": manifest_image_hash,
        "claim_id": claim_id,
        "capture_id": capture_id,
        "key_id": key_id,
        "ai_detection": ai_result.to_dict(),
        "trust_verdict": decision.verdict,
        "trust_reasons": decision.reasons,
        "errors": errors,
    }


def _verify_signature(manifest: dict, signature_b64: str, public_key_pem: str, errors: list[str]) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.strip().encode("utf-8"))
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Public key is not an EC key.")
    except (ValueError, TypeError) as error:
        errors.append(f"Failed to load public key: {error}")
        return False

    try:
        signature_bytes = base64.b64decode(signature_b64.strip(), validate=True)
    except (binascii.Error, ValueError):
        errors.append("Signature is not valid Base64.")
        return False

    try:
        public_key.verify(signature_bytes, ManifestService.canonicalize(manifest), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        errors.append("Digital signature verification FAILED — manifest was tampered or wrong key used.")
        return False


def detect_ai_standalone(image_bytes: bytes, detector: AIDetectionService) -> dict[str, Any]:
    """AI-generation check for any image, without manifest or signature."""
    _check_image_size(image_bytes)
    return {
        "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "ai_detection": detector.analyze(image_bytes).to_dict(),
    }
