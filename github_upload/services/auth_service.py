"""
auth_service.py
---------------
Email + password login for the TrustCap demo.

- The password is never stored in plain text: `.env` holds a PBKDF2-SHA256
  hash (generate one with `python create_password_hash.py`).
- Comparisons are constant-time.
- After MAX_FAILED_ATTEMPTS wrong passwords for an email, that email is locked
  for LOCKOUT_SECONDS. The counter is shared by all browser sessions of the
  running app (in memory), so opening a new tab does not reset it.

This is demo-grade access control for a single account. For multiple users or
public deployment, use a real identity provider (e.g. Streamlit's st.login with OIDC).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

HASH_ALGORITHM = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 600_000
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60


# ── Password hashing ────────────────────────────────────────────────────────
def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Returns 'pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>'."""
    if not password:
        raise ValueError("Password must not be empty.")
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join([
        HASH_ALGORITHM,
        str(iterations),
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(derived).decode("ascii"),
    ])


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_text, salt_b64, hash_b64 = stored_hash.split("$")
        if algorithm != HASH_ALGORITHM:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        iterations = int(iterations_text)
    except (ValueError, TypeError):
        return False
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(derived, expected)


# ── Configuration ───────────────────────────────────────────────────────────
@dataclass(frozen=True)
class AuthSettings:
    email: str
    password_hash: str
    session_minutes: int

    @property
    def is_configured(self) -> bool:
        return bool(self.email) and self.password_hash.startswith(HASH_ALGORITHM + "$")


def load_auth_settings() -> AuthSettings:
    session_minutes_text = os.getenv("AUTH_SESSION_MINUTES", "60").strip() or "60"
    try:
        session_minutes = int(session_minutes_text)
    except ValueError as error:
        raise ValueError(f"AUTH_SESSION_MINUTES must be an integer, got {session_minutes_text!r}") from error
    return AuthSettings(
        email=os.getenv("AUTH_EMAIL", "").strip().lower(),
        password_hash=os.getenv("AUTH_PASSWORD_HASH", "").strip(),
        session_minutes=max(session_minutes, 1),
    )


# ── Login with lockout ──────────────────────────────────────────────────────
@dataclass
class LoginResult:
    success: bool
    message: str
    locked_seconds_remaining: int = 0


@dataclass
class _AttemptRecord:
    failures: int = 0
    locked_until: float = 0.0


@dataclass
class Authenticator:
    settings: AuthSettings
    clock: Callable[[], float] = time.monotonic
    _attempts: dict[str, _AttemptRecord] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def login(self, email: str, password: str) -> LoginResult:
        if not self.settings.is_configured:
            return LoginResult(False, "Login is not configured. Set AUTH_EMAIL and AUTH_PASSWORD_HASH in .env.")

        normalized_email = email.strip().lower()
        if not normalized_email or not password:
            return LoginResult(False, "Enter your email and password.")

        with self._lock:
            record = self._attempts.setdefault(normalized_email, _AttemptRecord())
            now = self.clock()
            if record.locked_until > now:
                remaining = int(record.locked_until - now) + 1
                return LoginResult(False, f"Too many failed attempts. Try again in {remaining} seconds.", remaining)

        # Always run the (slow) hash check so response time does not reveal whether the email exists.
        password_ok = verify_password(password, self.settings.password_hash)
        email_ok = hmac.compare_digest(normalized_email.encode(), self.settings.email.encode())

        with self._lock:
            if email_ok and password_ok:
                self._attempts.pop(normalized_email, None)
                return LoginResult(True, "Signed in.")

            record.failures += 1
            if record.failures >= MAX_FAILED_ATTEMPTS:
                record.failures = 0
                record.locked_until = self.clock() + LOCKOUT_SECONDS
                return LoginResult(False, f"Too many failed attempts. Locked for {LOCKOUT_SECONDS // 60} minutes.",
                                   LOCKOUT_SECONDS)
            attempts_left = MAX_FAILED_ATTEMPTS - record.failures
            return LoginResult(False, f"Invalid email or password. {attempts_left} attempt(s) left.")
