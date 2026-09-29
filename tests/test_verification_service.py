"""Verification service tests — the same logic the Streamlit app runs (no server needed)."""

import base64
import hashlib
import json
import unittest

from cryptography.hazmat.primitives import serialization

from services.ai_detection_service import AIDetectionResult
from services.manifest_service import ManifestService
from services.signature_service import SignatureService
from services.verification_service import (
    MAX_IMAGE_BYTES,
    EvidenceInputError,
    detect_ai_standalone,
    verify_evidence,
)
from tests.test_ai_detection_service import make_settings

IMAGE_BYTES = b"\xff\xd8\xff\xe0" + b"original-image"
OTHER_IMAGE_BYTES = b"\xff\xd8\xff\xe0" + b"modified-image"
SETTINGS = make_settings()


class FakeDetector:
    def __init__(self, result=None):
        self.result = result or AIDetectionResult(status="completed", label="real", score=0.1)
        self.calls = 0

    def analyze(self, image_bytes):
        self.calls += 1
        return self.result


class VerifyEvidenceTests(unittest.TestCase):
    def setUp(self):
        private_key, public_key = SignatureService.generate_keys()
        self.public_pem = public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.manifest = {"claim_id": "CLM-1", "capture_id": "CAP-1",
                         "image_hash": hashlib.sha256(IMAGE_BYTES).hexdigest(), "key_id": "k1"}
        self.signature = SignatureService.sign(ManifestService.canonicalize(self.manifest), private_key)
        self.detector = FakeDetector()

    def verify(self, image=IMAGE_BYTES, manifest=None, signature=None, public_key=None, run_ai_check=True):
        manifest_json = manifest if isinstance(manifest, str) else json.dumps(manifest or self.manifest)
        return verify_evidence(image, manifest_json, signature or self.signature, public_key or self.public_pem,
                               self.detector, SETTINGS, run_ai_check)

    def test_clean_real_image_is_trusted(self):
        result = self.verify()
        self.assertTrue(result["verified"])
        self.assertEqual(result["trust_verdict"], "TRUSTED")
        self.assertEqual(self.detector.calls, 1)

    def test_response_keeps_original_fields(self):
        expected = {"manifest_valid", "hash_valid", "signature_valid", "verified", "server_calculated_hash",
                    "manifest_image_hash", "claim_id", "capture_id", "key_id", "errors",
                    "ai_detection", "trust_verdict", "trust_reasons"}
        self.assertEqual(set(self.verify()), expected)

    def test_ai_generated_image_is_rejected(self):
        self.detector = FakeDetector(AIDetectionResult(status="completed", label="fake", score=0.95))
        result = self.verify()
        self.assertTrue(result["verified"])
        self.assertEqual(result["trust_verdict"], "REJECTED")

    def test_borderline_goes_to_review(self):
        self.detector = FakeDetector(AIDetectionResult(status="completed", label="fake", score=0.6))
        self.assertEqual(self.verify()["trust_verdict"], "REVIEW")

    def test_tampered_image(self):
        result = self.verify(image=OTHER_IMAGE_BYTES)
        self.assertFalse(result["hash_valid"])
        self.assertTrue(result["signature_valid"])
        self.assertEqual(result["trust_verdict"], "REJECTED")
        self.assertEqual(self.detector.calls, 0)

    def test_tampered_manifest(self):
        result = self.verify(manifest=dict(self.manifest, claim_id="CLM-999"))
        self.assertTrue(result["hash_valid"])
        self.assertFalse(result["signature_valid"])
        self.assertEqual(result["ai_detection"]["status"], "skipped")

    def test_advanced_tampering(self):
        manifest = dict(self.manifest, image_hash=hashlib.sha256(OTHER_IMAGE_BYTES).hexdigest())
        result = self.verify(image=OTHER_IMAGE_BYTES, manifest=manifest)
        self.assertTrue(result["hash_valid"])
        self.assertFalse(result["signature_valid"])
        self.assertEqual(result["trust_verdict"], "REJECTED")

    def test_attacker_key_is_still_accepted_known_limitation(self):
        """Documents the open issue: the public key comes from the caller."""
        attacker_private, attacker_public = SignatureService.generate_keys()
        manifest = dict(self.manifest, image_hash=hashlib.sha256(OTHER_IMAGE_BYTES).hexdigest())
        signature = SignatureService.sign(ManifestService.canonicalize(manifest), attacker_private)
        attacker_pem = attacker_public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        result = self.verify(image=OTHER_IMAGE_BYTES, manifest=manifest, signature=signature, public_key=attacker_pem)
        self.assertTrue(result["verified"])

    def test_ai_check_can_be_turned_off(self):
        result = self.verify(run_ai_check=False)
        self.assertEqual(result["trust_verdict"], "REVIEW")
        self.assertEqual(self.detector.calls, 0)

    def test_bad_inputs_do_not_crash(self):
        cases = [
            dict(manifest="{not json"),
            dict(manifest="[1, 2]"),
            dict(manifest=json.dumps({"claim_id": "x"})),
            dict(signature="%%%not-base64%%%"),
            dict(signature=base64.b64encode(b"garbage").decode()),
            dict(public_key="not a pem"),
            dict(image=b""),
        ]
        for case in cases:
            result = self.verify(**case)
            self.assertFalse(result["verified"], case)
            self.assertEqual(result["trust_verdict"], "REJECTED", case)
            self.assertTrue(result["errors"], case)

    def test_oversized_image_is_refused(self):
        with self.assertRaises(EvidenceInputError):
            self.verify(image=b"\xff\xd8\xff" + b"0" * MAX_IMAGE_BYTES)

    def test_standalone_detection(self):
        result = detect_ai_standalone(IMAGE_BYTES, self.detector)
        self.assertEqual(result["image_sha256"], hashlib.sha256(IMAGE_BYTES).hexdigest())
        self.assertEqual(result["ai_detection"]["score"], 0.1)


if __name__ == "__main__":
    unittest.main()
