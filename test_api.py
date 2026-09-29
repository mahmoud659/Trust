"""
Live end-to-end check — no server needed.

Runs the real verification service on image.jpg / image2.jpg with the REAL
Resemble API (reads RESEMBLE_API_KEY from .env), using the demo key pair.

    python test_api.py
"""

import hashlib
import json

from config import load_ai_detection_settings
from demo_keys import KEY_ID, get_or_create_keys
from services.ai_detection_service import AIDetectionService
from services.manifest_service import ManifestService
from services.signature_service import SignatureService
from services.verification_service import verify_evidence

settings = load_ai_detection_settings()
detector = AIDetectionService(settings)
private_key, _, public_pem = get_or_create_keys()

with open("image.jpg", "rb") as file:
    image_bytes = file.read()
with open("image2.jpg", "rb") as file:
    image2_bytes = file.read()

manifest = {
    "claim_id": "CLM-TEST-001",
    "capture_id": "CAP-ABCD1234",
    "image_hash": hashlib.sha256(image_bytes).hexdigest(),
    "key_id": KEY_ID,
}
signature = SignatureService.sign(ManifestService.canonicalize(manifest), private_key)


def run(title: str, image: bytes, manifest_dict: dict) -> dict:
    result = verify_evidence(image, json.dumps(manifest_dict), signature, public_pem, detector, settings)
    print(f"=== {title} ===")
    for field in ("manifest_valid", "hash_valid", "signature_valid", "verified", "trust_verdict"):
        print(f"  {field:<16} {result[field]}")
    print(f"  ai_detection     {result['ai_detection']}")
    print(f"  reasons          {'; '.join(result['trust_reasons'])}")
    return result


# TEST 1: clean evidence — integrity must pass; verdict depends on the real AI score
r1 = run("TEST 1: CLEAN EVIDENCE", image_bytes, manifest)
assert r1["verified"], "FAIL: clean evidence should pass integrity"
if settings.is_configured:
    assert r1["ai_detection"]["status"] == "completed", f"FAIL: Resemble call failed: {r1['ai_detection']['reason']}"
print("  -> PASS\n")

# TEST 2: tampered manifest
r2 = run("TEST 2: TAMPERED MANIFEST", image_bytes, dict(manifest, claim_id="CLM-999"))
assert r2["hash_valid"] and not r2["signature_valid"] and r2["trust_verdict"] == "REJECTED", "FAIL"
print("  -> PASS\n")

# TEST 3: image swapped + hash updated in manifest, original signature kept
r3 = run("TEST 3: ADVANCED TAMPERING", image2_bytes,
         dict(manifest, image_hash=hashlib.sha256(image2_bytes).hexdigest()))
assert r3["hash_valid"] and not r3["signature_valid"] and r3["trust_verdict"] == "REJECTED", "FAIL"
print("  -> PASS\n")

print("ALL TESTS PASSED ✅")
