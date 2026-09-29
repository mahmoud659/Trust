"""
config.py
---------
Central configuration for TrustCap, loaded from environment
variables (and from a local `.env` file when present).

The Resemble API key is read on the server side (the machine running the app)
and never sent to the browser.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Load `.env` from the project folder regardless of the current working directory.
load_dotenv(Path(__file__).parent / ".env")


def _read_bool(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None or raw_value.strip() == "":
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _read_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None or raw_value.strip() == "":
        return default
    try:
        return float(raw_value)
    except ValueError as error:
        raise ValueError(f"Environment variable {name} must be a number, got {raw_value!r}") from error


@dataclass(frozen=True)
class AIDetectionSettings:
    enabled: bool
    api_key: str
    base_url: str
    request_timeout_seconds: float
    max_wait_seconds: float
    zero_retention_mode: bool
    # Score thresholds (Resemble score: 0 = real, 1 = fake).
    review_threshold: float
    reject_threshold: float

    @property
    def is_configured(self) -> bool:
        return self.enabled and bool(self.api_key)


def load_ai_detection_settings() -> AIDetectionSettings:
    review_threshold = _read_float("AI_REVIEW_THRESHOLD", 0.50)
    reject_threshold = _read_float("AI_REJECT_THRESHOLD", 0.85)

    if not (0.0 <= review_threshold <= reject_threshold <= 1.0):
        raise ValueError(
            "AI thresholds must satisfy 0 <= AI_REVIEW_THRESHOLD <= AI_REJECT_THRESHOLD <= 1 "
            f"(got review={review_threshold}, reject={reject_threshold})"
        )

    return AIDetectionSettings(
        enabled=_read_bool("AI_DETECTION_ENABLED", True),
        api_key=os.getenv("RESEMBLE_API_KEY", "").strip(),
        base_url=os.getenv("RESEMBLE_BASE_URL", "https://app.resemble.ai/api/v2").rstrip("/"),
        request_timeout_seconds=_read_float("RESEMBLE_TIMEOUT_SECONDS", 60.0),
        max_wait_seconds=_read_float("RESEMBLE_MAX_WAIT_SECONDS", 90.0),
        zero_retention_mode=_read_bool("RESEMBLE_ZERO_RETENTION", True),
        review_threshold=review_threshold,
        reject_threshold=reject_threshold,
    )
