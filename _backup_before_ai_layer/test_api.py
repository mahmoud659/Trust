"""End-to-end API test for TrustCap verification."""
import hashlib
import json
import time

import requests

from demo_keys import KEY_ID, get_or_create_keys
from services.manifest_service import ManifestService
from services.signature_service import SignatureService

# Wait for server to be ready
time.sleep(2)

# Load keys
private_key, _, pub_pem = get_or_create_keys()

# Simulate capturing an image
image_bytes = open("image.jpg", "rb").read()
img_hash = hashlib.sha256(image_bytes).hexdigest()

# Build manifest
manifest = {
    "claim_id": "CLM-TEST-001",
    "capture_id": "CAP-ABCD1234",
    "image_hash": img_hash,
    "key_id": KEY_ID,
}

# Sign
canonical = ManifestService.canonicalize(manifest)
signature = SignatureService.sign(canonical, private_key)

# ── TEST 1: Clean evidence ───────────────────────────────────────────────────
resp = requests.post(
    "http://localhost:8000/verify",
    files={"image": ("image.jpg", image_bytes, "image/jpeg")},
    data={
        "manifest": json.dumps(manifest),
        "signature": signature,
        "public_key": pub_pem,
    },
)
r = resp.json()
print("=== TEST 1: CLEAN EVIDENCE ===")
print(f"  manifest_valid:   {r['manifest_valid']}")
print(f"  hash_valid:       {r['hash_valid']}")
print(f"  signature_valid:  {r['signature_valid']}")
print(f"  verified:         {r['verified']}")
assert r["manifest_valid"] and r["hash_valid"] and r["signature_valid"] and r["verified"], "FAIL"
print("  -> PASS\n")

# ── TEST 2: Tamper manifest (change claim_id) ────────────────────────────────
manifest2 = dict(manifest)
manifest2["claim_id"] = "CLM-999"
resp2 = requests.post(
    "http://localhost:8000/verify",
    files={"image": ("image.jpg", image_bytes, "image/jpeg")},
    data={
        "manifest": json.dumps(manifest2),
        "signature": signature,
        "public_key": pub_pem,
    },
)
r2 = resp2.json()
print("=== TEST 2: TAMPERED MANIFEST ===")
print(f"  manifest_valid:   {r2['manifest_valid']}")
print(f"  hash_valid:       {r2['hash_valid']}")
print(f"  signature_valid:  {r2['signature_valid']}")
print(f"  verified:         {r2['verified']}")
assert r2["manifest_valid"] and r2["hash_valid"] and not r2["signature_valid"] and not r2["verified"], "FAIL"
print("  -> PASS\n")

# ── TEST 3: Advanced — tamper image + update hash in manifest ────────────────
image2_bytes = open("image2.jpg", "rb").read()
new_hash = hashlib.sha256(image2_bytes).hexdigest()
manifest3 = dict(manifest)
manifest3["image_hash"] = new_hash  # updated hash, but keep original sig
resp3 = requests.post(
    "http://localhost:8000/verify",
    files={"image": ("image2.jpg", image2_bytes, "image/jpeg")},
    data={
        "manifest": json.dumps(manifest3),
        "signature": signature,
        "public_key": pub_pem,
    },
)
r3 = resp3.json()
print("=== TEST 3: ADVANCED TAMPERING (image swapped + hash updated in manifest) ===")
print(f"  manifest_valid:   {r3['manifest_valid']}")
print(f"  hash_valid:       {r3['hash_valid']}")
print(f"  signature_valid:  {r3['signature_valid']}")
print(f"  verified:         {r3['verified']}")
assert r3["manifest_valid"] and r3["hash_valid"] and not r3["signature_valid"] and not r3["verified"], "FAIL"
print("  -> PASS\n")

print("ALL TESTS PASSED ✅")
