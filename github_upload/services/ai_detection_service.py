"""
ai_detection_service.py
-----------------------
Detects whether an image is AI-generated using the Resemble AI Detect API.

API reference (verified against https://docs.resemble.ai/detect):
  POST {base_url}/detect            multipart field `file`, header `Prefer: wait`
  GET  {base_url}/detect/{uuid}     poll while status == "processing"
  Image result lives in item.image_metrics -> {label: "Fake"|"Real", score: 0..1}
  (higher score = more likely fake)

Design notes:
  - The POST is never retried automatically: a retry after a timeout could
    create (and bill) a second detection. Only the GET polling is repeated.
  - Completed results are cached in memory by image SHA-256, so verifying the
    same evidence several times (e.g. in the Tampering Lab) costs one API call.
  - The API key is never logged or returned to callers.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from typing import Any

import requests

from config import AIDetectionSettings

logger = logging.getLogger("trustcap.ai_detection")

PROVIDER_NAME = "resemble"
POLL_INTERVAL_SECONDS = 2.0
CACHE_MAX_ENTRIES = 256

# Status values returned in AIDetectionResult.status
STATUS_COMPLETED = "completed"
STATUS_ERROR = "error"
STATUS_DISABLED = "disabled"
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_SKIPPED = "skipped"


@dataclass
class AIDetectionResult:
    status: str
    provider: str = PROVIDER_NAME
    label: str | None = None          # "fake" | "real" (normalized to lowercase)
    score: float | None = None        # 0.0 (real) .. 1.0 (fake)
    detection_id: str | None = None
    reason: str | None = None         # human-readable explanation for non-completed states
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AIDetectionError(Exception):
    """Raised internally when the provider call fails; converted to an error result."""


def detect_image_mime_type(image_bytes: bytes) -> str | None:
    """Identify the image format from its magic bytes (file extensions can lie)."""
    if image_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if image_bytes[:4] == b"RIFF" and image_bytes[8:12] == b"WEBP":
        return "image/webp"
    if image_bytes[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    return None


_FILE_EXTENSIONS = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif"}


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        numbers = [number for number in (_to_float(item) for item in value) if number is not None]
        return sum(numbers) / len(numbers) if numbers else None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class AIDetectionService:
    def __init__(self, settings: AIDetectionSettings, http_session: requests.Session | None = None):
        self.settings = settings
        self.http_session = http_session or requests.Session()
        self._cache: OrderedDict[str, AIDetectionResult] = OrderedDict()
        self._cache_lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────────────────────
    def analyze(self, image_bytes: bytes) -> AIDetectionResult:
        if not self.settings.enabled:
            return AIDetectionResult(status=STATUS_DISABLED, reason="AI detection is disabled (AI_DETECTION_ENABLED=false).")
        if not self.settings.api_key:
            return AIDetectionResult(status=STATUS_NOT_CONFIGURED, reason="RESEMBLE_API_KEY is not set on the API server.")
        if not image_bytes:
            return AIDetectionResult(status=STATUS_ERROR, reason="Image is empty.")

        mime_type = detect_image_mime_type(image_bytes)
        if mime_type is None:
            return AIDetectionResult(status=STATUS_ERROR, reason="Unsupported image format (expected JPEG, PNG, WEBP or GIF).")

        image_hash = hashlib.sha256(image_bytes).hexdigest()
        cached_result = self._get_cached(image_hash)
        if cached_result is not None:
            return cached_result

        try:
            result = self._run_detection(image_bytes, mime_type)
        except AIDetectionError as error:
            logger.warning("AI detection failed: %s", error)
            return AIDetectionResult(status=STATUS_ERROR, reason=str(error))

        self._store_cached(image_hash, result)
        return result

    # ── Provider calls ──────────────────────────────────────────────────────
    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.settings.api_key}"}

    def _run_detection(self, image_bytes: bytes, mime_type: str) -> AIDetectionResult:
        file_name = f"evidence.{_FILE_EXTENSIONS[mime_type]}"
        form_fields = {"zero_retention_mode": "true" if self.settings.zero_retention_mode else "false"}

        try:
            response = self.http_session.post(
                f"{self.settings.base_url}/detect",
                headers={**self._auth_headers(), "Prefer": "wait"},
                files={"file": (file_name, image_bytes, mime_type)},
                data=form_fields,
                timeout=self.settings.request_timeout_seconds,
            )
        except requests.Timeout as error:
            raise AIDetectionError(
                f"Resemble API did not respond within {self.settings.request_timeout_seconds:.0f}s."
            ) from error
        except requests.RequestException as error:
            raise AIDetectionError(f"Could not reach Resemble API: {error.__class__.__name__}.") from error

        item = self._extract_item(response)
        started_at = time.monotonic()

        # `Prefer: wait` normally returns a completed item, but handle async answers too.
        while item.get("status") == "processing":
            if time.monotonic() - started_at > self.settings.max_wait_seconds:
                raise AIDetectionError(
                    f"Detection {item.get('uuid')} still processing after {self.settings.max_wait_seconds:.0f}s."
                )
            detection_id = item.get("uuid")
            if not detection_id:
                raise AIDetectionError("Resemble returned a processing item without a uuid.")
            time.sleep(POLL_INTERVAL_SECONDS)
            item = self._fetch_detection(detection_id)

        if item.get("status") == "failed":
            raise AIDetectionError(f"Resemble reported the detection as failed ({item.get('uuid')}).")

        return self._parse_completed_item(item)

    def _fetch_detection(self, detection_id: str) -> dict[str, Any]:
        try:
            response = self.http_session.get(
                f"{self.settings.base_url}/detect/{detection_id}",
                headers=self._auth_headers(),
                timeout=self.settings.request_timeout_seconds,
            )
        except requests.RequestException as error:
            raise AIDetectionError(f"Polling Resemble failed: {error.__class__.__name__}.") from error
        return self._extract_item(response)

    @staticmethod
    def _extract_item(response: requests.Response) -> dict[str, Any]:
        if response.status_code in (401, 403):
            raise AIDetectionError("Resemble rejected the API key (HTTP %d). Check RESEMBLE_API_KEY." % response.status_code)
        if response.status_code == 429:
            raise AIDetectionError("Resemble rate limit reached (HTTP 429). Try again later.")
        if response.status_code >= 400:
            raise AIDetectionError(f"Resemble API error HTTP {response.status_code}: {response.text[:200]}")

        try:
            body = response.json()
        except ValueError as error:
            raise AIDetectionError("Resemble returned a non-JSON response.") from error

        if not body.get("success", False):
            raise AIDetectionError(f"Resemble reported failure: {body.get('message', 'unknown error')}")

        item = body.get("item")
        if not isinstance(item, dict):
            raise AIDetectionError("Resemble response is missing the `item` object.")
        return item

    @staticmethod
    def _parse_completed_item(item: dict[str, Any]) -> AIDetectionResult:
        # Images report in `image_metrics`; `metrics` is the generic/audio shape.
        metrics = item.get("image_metrics") or item.get("metrics") or {}
        if not isinstance(metrics, dict):
            raise AIDetectionError("Resemble response has unexpected metrics format.")

        score = _to_float(metrics.get("aggregated_score"))
        if score is None:
            score = _to_float(metrics.get("score"))

        raw_label = metrics.get("label")
        label = str(raw_label).strip().lower() if raw_label else None

        if score is None and label is None:
            raise AIDetectionError("Resemble response contains neither a label nor a score.")

        return AIDetectionResult(
            status=STATUS_COMPLETED,
            label=label,
            score=round(score, 4) if score is not None else None,
            detection_id=item.get("uuid"),
        )

    # ── Cache ───────────────────────────────────────────────────────────────
    def _get_cached(self, image_hash: str) -> AIDetectionResult | None:
        with self._cache_lock:
            result = self._cache.get(image_hash)
            if result is None:
                return None
            self._cache.move_to_end(image_hash)
            return AIDetectionResult(**{**result.to_dict(), "cached": True})

    def _store_cached(self, image_hash: str, result: AIDetectionResult) -> None:
        if result.status != STATUS_COMPLETED:
            return
        with self._cache_lock:
            self._cache[image_hash] = result
            self._cache.move_to_end(image_hash)
            while len(self._cache) > CACHE_MAX_ENTRIES:
                self._cache.popitem(last=False)
