"""
Tests for the OPTIONAL FastAPI wrapper (api.py). Skipped automatically when
FastAPI is not installed (pip install -r requirements-dev.txt to run them).
"""

import base64
import hashlib
import importlib.util
import json
import unittest

from cryptography.hazmat.primitives import serialization

if importlib.util.find_spec("fastapi") is None or importlib.util.find_spec("httpx") is None:
    raise unittest.SkipTest("FastAPI/httpx not installed — optional API tests skipped.")

from fastapi.testclient import TestClient  # noqa: E402

import api  # noqa: E402
from services.ai_detection_service import AIDetectionResult
from services.manifest_service import ManifestService
from services.signature_service import SignatureService
from tests.test_ai_detection_service import make_settings

IMAGE_BYTES = b"\xff\xd8\xff\xe0" + b"original-image"
OTHER_IMAGE_BYTES = b"\xff\xd8\xff\xe0" + b"modified-image"


class FakeDetector:
    def __init__(self, result: AIDetectionResult):
        self.result = result
        self.calls = 0

    def analyze(self, image_bytes: bytes) -> AIDetectionResult:
        self.calls += 1
        return self.result


class VerifyEndpointTests(unittest.TestCase):
    def setUp(self):
        self.private_key, public_key = SignatureService.generate_keys()
        self.public_pem = public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.manifest = {"claim_id": "CLM-1", "capture_id": "CAP-1",
                         "image_hash": hashlib.sha256(IMAGE_BYTES).hexdigest(), "key_id": "k1"}
        self.signature = SignatureService.sign(ManifestService.canonicalize(self.manifest), self.private_key)
        self.use_detector(AIDetectionResult(status="completed", label="real", score=0.1))
        api.app.dependency_overrides[api.get_ai_settings] = lambda: make_settings()
        self.client = TestClient(api.app)

    def tearDown(self):
        api.app.dependency_overrides.clear()

    def use_detector(self, result: AIDetectionResult) -> None:
        self.detector = FakeDetector(result)
        api.app.dependency_overrides[api.get_ai_detection_service] = lambda: self.detector

    def post_verify(self, image=IMAGE_BYTES, manifest=None, signature=None, **extra):
        return self.client.post("/verify", files={"image": ("image.jpg", image, "image/jpeg")}, data={
            "manifest": json.dumps(manifest or self.manifest),
            "signature": signature or self.signature,
            "public_key": self.public_pem,
            **extra,
        }).json()

    def test_clean_evidence_real_image_is_trusted(self):
        body = self.post_verify()
        self.assertTrue(body["verified"])
        self.assertEqual(body["trust_verdict"], "TRUSTED")
        self.assertEqual(body["ai_detection"]["status"], "completed")
        self.assertEqual(self.detector.calls, 1)

    def test_clean_evidence_ai_image_is_rejected(self):
        self.use_detector(AIDetectionResult(status="completed", label="fake", score=0.97))
        body = self.post_verify()
        self.assertTrue(body["verified"])  # integrity still reported independently
        self.assertEqual(body["trust_verdict"], "REJECTED")

    def test_borderline_score_goes_to_review(self):
        self.use_detector(AIDetectionResult(status="completed", label="fake", score=0.6))
        self.assertEqual(self.post_verify()["trust_verdict"], "REVIEW")

    def test_tampered_manifest_skips_ai(self):
        tampered = dict(self.manifest, claim_id="CLM-999")
        body = self.post_verify(manifest=tampered)
        self.assertFalse(body["signature_valid"])
        self.assertEqual(body["trust_verdict"], "REJECTED")
        self.assertEqual(body["ai_detection"]["status"], "skipped")
        self.assertEqual(self.detector.calls, 0)

    def test_tampered_image(self):
        body = self.post_verify(image=OTHER_IMAGE_BYTES)
        self.assertFalse(body["hash_valid"])
        self.assertFalse(body["verified"])

    def test_advanced_tampering(self):
        manifest = dict(self.manifest, image_hash=hashlib.sha256(OTHER_IMAGE_BYTES).hexdigest())
        body = self.post_verify(image=OTHER_IMAGE_BYTES, manifest=manifest)
        self.assertTrue(body["hash_valid"])
        self.assertFalse(body["signature_valid"])
        self.assertEqual(body["trust_verdict"], "REJECTED")

    def test_ai_check_can_be_disabled_per_request(self):
        body = self.post_verify(run_ai_check="false")
        self.assertEqual(body["ai_detection"]["status"], "skipped")
        self.assertEqual(body["trust_verdict"], "REVIEW")
        self.assertEqual(self.detector.calls, 0)

    def test_invalid_json_and_non_object_manifest(self):
        for bad in ("{not json", "[1, 2]"):
            response = self.client.post("/verify", files={"image": ("i.jpg", IMAGE_BYTES, "image/jpeg")},
                                        data={"manifest": bad, "signature": "x", "public_key": "y"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["trust_verdict"], "REJECTED")

    def test_bad_signature_base64(self):
        body = self.post_verify(signature=base64.b64encode(b"garbage").decode())
        self.assertFalse(body["signature_valid"])

    def test_detect_ai_endpoint(self):
        self.use_detector(AIDetectionResult(status="completed", label="fake", score=0.9, detection_id="d1"))
        response = self.client.post("/detect-ai", files={"image": ("x.jpg", IMAGE_BYTES, "image/jpeg")})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["ai_detection"]["score"], 0.9)
        self.assertEqual(body["image_sha256"], hashlib.sha256(IMAGE_BYTES).hexdigest())

    def test_health_reports_ai_configuration(self):
        body = self.client.get("/health").json()
        self.assertTrue(body["ai_detection"]["configured"])
        self.assertNotIn("api_key", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
