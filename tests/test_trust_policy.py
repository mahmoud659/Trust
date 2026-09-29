"""Unit tests for the TRUSTED / REVIEW / REJECTED decision."""

import os
import unittest
from unittest import mock

from config import load_ai_detection_settings
from services.ai_detection_service import AIDetectionResult
from services.trust_policy import VERDICT_REJECTED, VERDICT_REVIEW, VERDICT_TRUSTED, decide_trust
from tests.test_ai_detection_service import make_settings

SETTINGS = make_settings(review_threshold=0.5, reject_threshold=0.85)


def completed(score, label=None):
    return AIDetectionResult(status="completed", score=score, label=label)


class TrustPolicyTests(unittest.TestCase):
    def test_integrity_failure_always_rejects(self):
        self.assertEqual(decide_trust(False, completed(0.01), SETTINGS).verdict, VERDICT_REJECTED)

    def test_score_bands(self):
        self.assertEqual(decide_trust(True, completed(0.10), SETTINGS).verdict, VERDICT_TRUSTED)
        self.assertEqual(decide_trust(True, completed(0.50), SETTINGS).verdict, VERDICT_REVIEW)
        self.assertEqual(decide_trust(True, completed(0.84), SETTINGS).verdict, VERDICT_REVIEW)
        self.assertEqual(decide_trust(True, completed(0.85), SETTINGS).verdict, VERDICT_REJECTED)
        self.assertEqual(decide_trust(True, completed(1.0), SETTINGS).verdict, VERDICT_REJECTED)

    def test_unavailable_ai_goes_to_review(self):
        for status in ("error", "not_configured", "disabled", "skipped"):
            decision = decide_trust(True, AIDetectionResult(status=status, reason="x"), SETTINGS)
            self.assertEqual(decision.verdict, VERDICT_REVIEW, status)

    def test_label_only_never_auto_rejects(self):
        self.assertEqual(decide_trust(True, completed(None, "fake"), SETTINGS).verdict, VERDICT_REVIEW)
        self.assertEqual(decide_trust(True, completed(None, "real"), SETTINGS).verdict, VERDICT_TRUSTED)


class ConfigTests(unittest.TestCase):
    def test_invalid_threshold_order_is_rejected(self):
        with mock.patch.dict(os.environ, {"AI_REVIEW_THRESHOLD": "0.9", "AI_REJECT_THRESHOLD": "0.5"}):
            with self.assertRaises(ValueError):
                load_ai_detection_settings()

    def test_defaults(self):
        with mock.patch.dict(os.environ, {"RESEMBLE_API_KEY": "k", "AI_REVIEW_THRESHOLD": "",
                                          "AI_REJECT_THRESHOLD": "", "AI_DETECTION_ENABLED": ""}):
            settings = load_ai_detection_settings()
        self.assertTrue(settings.is_configured)
        self.assertEqual((settings.review_threshold, settings.reject_threshold), (0.5, 0.85))


if __name__ == "__main__":
    unittest.main()
