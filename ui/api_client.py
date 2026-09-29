"""
ui/api_client.py
----------------
Thin HTTP client used by the Streamlit UI to talk to the FastAPI backend.
It contains no verification logic — it only sends data and returns the JSON.
"""

from __future__ import annotations

import os
from typing import Any

import requests

API_BASE_URL = os.getenv("TRUSTCAP_API_URL", "http://localhost:8000").rstrip("/")

# The AI check waits for Resemble synchronously, so /verify can take a while.
VERIFY_TIMEOUT_SECONDS = 120
HEALTH_TIMEOUT_SECONDS = 3


class ApiClientError(Exception):
    """Raised with a user-facing message when the backend call fails."""


def _guess_image_mime(image_bytes: bytes) -> tuple[str, str]:
    if image_bytes.startswith(b"\x89PNG"):
        return "image.png", "image/png"
    if image_bytes[:4] == b"RIFF" and image_bytes[8:12] == b"WEBP":
        return "image.webp", "image/webp"
    return "image.jpg", "image/jpeg"


def _post(path: str, **kwargs: Any) -> dict:
    url = f"{API_BASE_URL}{path}"
    try:
        response = requests.post(url, timeout=VERIFY_TIMEOUT_SECONDS, **kwargs)
    except requests.exceptions.ConnectionError as error:
        raise ApiClientError(
            f"Cannot connect to the FastAPI backend at {API_BASE_URL}. "
            "Start it with: uvicorn api:app --reload --port 8000"
        ) from error
    except requests.exceptions.Timeout as error:
        raise ApiClientError(f"The backend did not respond within {VERIFY_TIMEOUT_SECONDS}s.") from error

    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise ApiClientError(f"Backend returned HTTP {response.status_code}: {detail}")

    try:
        return response.json()
    except ValueError as error:
        raise ApiClientError("Backend returned an invalid (non-JSON) response.") from error


def verify_evidence(
    image_bytes: bytes,
    manifest_json: str,
    signature_b64: str,
    public_key_pem: str,
    run_ai_check: bool = True,
) -> dict:
    file_name, mime_type = _guess_image_mime(image_bytes)
    return _post(
        "/verify",
        files={"image": (file_name, image_bytes, mime_type)},
        data={
            "manifest": manifest_json,
            "signature": signature_b64,
            "public_key": public_key_pem,
            "run_ai_check": "true" if run_ai_check else "false",
        },
    )


def detect_ai(image_bytes: bytes) -> dict:
    file_name, mime_type = _guess_image_mime(image_bytes)
    return _post("/detect-ai", files={"image": (file_name, image_bytes, mime_type)})


def get_health() -> dict | None:
    """Returns the /health payload, or None when the backend is unreachable."""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=HEALTH_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError):
        return None
