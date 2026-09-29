"""Unit tests for the Resemble AI detection client (HTTP is mocked — no API key needed)."""

import unittest
from unittest import mock

import requests

from config import AIDetectionSettings
from services.ai_detection_service import (
    STATUS_COMPLETED,
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_NOT_CONFIGURED,
    AIDetectionService,
    detect_image_mime_type,
)

JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"fake-jpeg-body"
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"fake-png-body"


def make_settings(**overrides) -> AIDetectionSettings:
    values = dict(
        enabled=True, api_key="test-key", base_url="https://resemble.test/api/v2",
        request_timeout_seconds=5, max_wait_seconds=5, zero_retention_mode=True,
        review_threshold=0.5, reject_threshold=0.85,
    )
    values.update(overrides)
    return AIDetectionSettings(**values)


def make_response(status_code: int, json_body=None, text: str = "") -> mock.Mock:
    response = mock.Mock(spec=requests.Response)
    response.status_code = status_code
    response.text = text
    if json_body is None:
        response.json.side_effect = ValueError("no json")
    else:
        response.json.return_value = json_body
    return response


def completed_image_body(label="Fake", score=0.93, uuid="det-1") -> dict:
    return {"success": True, "item": {
        "uuid": uuid, "status": "completed", "media_type": "image",
        "image_metrics": {"type": "FinalResult", "label": label, "score": score},
    }}


class DetectMimeTypeTests(unittest.TestCase):
    def test_known_formats(self):
        self.assertEqual(detect_image_mime_type(JPEG_BYTES), "image/jpeg")
        self.assertEqual(detect_image_mime_type(PNG_BYTES), "image/png")
        self.assertEqual(detect_image_mime_type(b"RIFF\x00\x00\x00\x00WEBPVP8 "), "image/webp")
        self.assertEqual(detect_image_mime_type(b"GIF89a..."), "image/gif")

    def test_unknown_format(self):
        self.assertIsNone(detect_image_mime_type(b"%PDF-1.7"))


class AIDetectionServiceTests(unittest.TestCase):
    def setUp(self):
        self.session = mock.Mock()
        self.service = AIDetectionService(make_settings(), http_session=self.session)

    def test_completed_fake_image_is_parsed(self):
        self.session.post.return_value = make_response(200, completed_image_body("Fake", 0.93))

        result = self.service.analyze(JPEG_BYTES)

        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(result.label, "fake")
        self.assertAlmostEqual(result.score, 0.93)
        self.assertEqual(result.detection_id, "det-1")

    def test_request_shape_matches_resemble_api(self):
        self.session.post.return_value = make_response(200, completed_image_body())

        self.service.analyze(JPEG_BYTES)

        args, kwargs = self.session.post.call_args
        self.assertEqual(args[0], "https://resemble.test/api/v2/detect")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-key")
        self.assertEqual(kwargs["headers"]["Prefer"], "wait")
        file_name, file_bytes, mime_type = kwargs["files"]["file"]
        self.assertEqual((file_name, mime_type), ("evidence.jpg", "image/jpeg"))
        self.assertEqual(file_bytes, JPEG_BYTES)
        self.assertEqual(kwargs["data"]["zero_retention_mode"], "true")

    def test_string_score_is_converted(self):
        self.session.post.return_value = make_response(200, completed_image_body("Real", "0.12"))
        result = self.service.analyze(PNG_BYTES)
        self.assertEqual(result.label, "real")
        self.assertAlmostEqual(result.score, 0.12)

    def test_result_is_cached_by_image_hash(self):
        self.session.post.return_value = make_response(200, completed_image_body())

        first = self.service.analyze(JPEG_BYTES)
        second = self.service.analyze(JPEG_BYTES)

        self.assertEqual(self.session.post.call_count, 1)
        self.assertFalse(first.cached)
        self.assertTrue(second.cached)
        self.assertEqual(second.score, first.score)

    @mock.patch("services.ai_detection_service.time.sleep", return_value=None)
    def test_processing_item_is_polled_until_completed(self, _sleep):
        self.session.post.return_value = make_response(
            200, {"success": True, "item": {"uuid": "det-9", "status": "processing"}})
        self.session.get.side_effect = [
            make_response(200, {"success": True, "item": {"uuid": "det-9", "status": "processing"}}),
            make_response(200, completed_image_body("Real", 0.05, uuid="det-9")),
        ]

        result = self.service.analyze(JPEG_BYTES)

        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(self.session.get.call_count, 2)
        self.assertEqual(self.session.get.call_args[0][0], "https://resemble.test/api/v2/detect/det-9")
        self.assertEqual(self.session.post.call_count, 1)  # POST never retried

    def test_invalid_api_key_returns_error_without_leaking_key(self):
        self.session.post.return_value = make_response(401, {"success": False}, text="unauthorized")
        result = self.service.analyze(JPEG_BYTES)
        self.assertEqual(result.status, STATUS_ERROR)
        self.assertIn("API key", result.reason)
        self.assertNotIn("test-key", result.reason)

    def test_rate_limit_returns_error(self):
        self.session.post.return_value = make_response(429, {"success": False})
        result = self.service.analyze(JPEG_BYTES)
        self.assertEqual(result.status, STATUS_ERROR)
        self.assertIn("429", result.reason)

    def test_timeout_is_not_retried(self):
        self.session.post.side_effect = requests.Timeout()
        result = self.service.analyze(JPEG_BYTES)
        self.assertEqual(result.status, STATUS_ERROR)
        self.assertEqual(self.session.post.call_count, 1)

    def test_errors_are_not_cached(self):
        self.session.post.side_effect = [requests.ConnectionError(), make_response(200, completed_image_body())]
        self.assertEqual(self.service.analyze(JPEG_BYTES).status, STATUS_ERROR)
        self.assertEqual(self.service.analyze(JPEG_BYTES).status, STATUS_COMPLETED)

    def test_failed_detection_status(self):
        self.session.post.return_value = make_response(
            200, {"success": True, "item": {"uuid": "x", "status": "failed"}})
        self.assertEqual(self.service.analyze(JPEG_BYTES).status, STATUS_ERROR)

    def test_success_false_is_error(self):
        self.session.post.return_value = make_response(200, {"success": False, "message": "bad file"})
        result = self.service.analyze(JPEG_BYTES)
        self.assertEqual(result.status, STATUS_ERROR)
        self.assertIn("bad file", result.reason)

    def test_unsupported_format_does_not_call_api(self):
        result = self.service.analyze(b"%PDF-1.7 not an image")
        self.assertEqual(result.status, STATUS_ERROR)
        self.session.post.assert_not_called()

    def test_missing_key_and_disabled(self):
        no_key = AIDetectionService(make_settings(api_key=""), http_session=self.session)
        disabled = AIDetectionService(make_settings(enabled=False), http_session=self.session)
        self.assertEqual(no_key.analyze(JPEG_BYTES).status, STATUS_NOT_CONFIGURED)
        self.assertEqual(disabled.analyze(JPEG_BYTES).status, STATUS_DISABLED)
        self.session.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
