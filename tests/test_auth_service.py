"""Unit tests for login, password hashing and lockout."""

import unittest

from services.auth_service import (
    LOCKOUT_SECONDS,
    MAX_FAILED_ATTEMPTS,
    Authenticator,
    AuthSettings,
    hash_password,
    verify_password,
)

PASSWORD = "Correct-Horse-9"
STORED_HASH = hash_password(PASSWORD, iterations=1_000)  # low iterations keep tests fast


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_authenticator(email="demo@trustcap.local", password_hash=STORED_HASH):
    clock = FakeClock()
    return Authenticator(AuthSettings(email, password_hash, 60), clock=clock), clock


class PasswordHashTests(unittest.TestCase):
    def test_round_trip(self):
        self.assertTrue(verify_password(PASSWORD, STORED_HASH))
        self.assertFalse(verify_password("wrong", STORED_HASH))

    def test_same_password_gets_different_salt(self):
        self.assertNotEqual(hash_password("abc", 1_000), hash_password("abc", 1_000))

    def test_malformed_hash_is_rejected(self):
        for bad in ("", "plaintext", "md5$1$a$b", "pbkdf2_sha256$x$y$z"):
            self.assertFalse(verify_password(PASSWORD, bad), bad)

    def test_empty_password_cannot_be_hashed(self):
        with self.assertRaises(ValueError):
            hash_password("")


class AuthenticatorTests(unittest.TestCase):
    def test_success_is_case_insensitive_on_email(self):
        authenticator, _ = make_authenticator()
        self.assertTrue(authenticator.login("  Demo@TrustCap.local ", PASSWORD).success)

    def test_wrong_password_and_wrong_email(self):
        authenticator, _ = make_authenticator()
        self.assertFalse(authenticator.login("demo@trustcap.local", "nope").success)
        self.assertFalse(authenticator.login("other@x.com", PASSWORD).success)

    def test_same_message_for_wrong_email_and_wrong_password(self):
        authenticator, _ = make_authenticator()
        wrong_email = authenticator.login("a@x.com", PASSWORD).message
        wrong_password = authenticator.login("b@x.com", "nope").message
        self.assertEqual(wrong_email.split(".")[0], wrong_password.split(".")[0])

    def test_lockout_after_max_failures_blocks_even_correct_password(self):
        authenticator, clock = make_authenticator()
        for _ in range(MAX_FAILED_ATTEMPTS):
            authenticator.login("demo@trustcap.local", "nope")

        locked = authenticator.login("demo@trustcap.local", PASSWORD)
        self.assertFalse(locked.success)
        self.assertGreater(locked.locked_seconds_remaining, 0)

        clock.now += LOCKOUT_SECONDS + 1
        self.assertTrue(authenticator.login("demo@trustcap.local", PASSWORD).success)

    def test_success_resets_failure_counter(self):
        authenticator, _ = make_authenticator()
        for _ in range(MAX_FAILED_ATTEMPTS - 1):
            authenticator.login("demo@trustcap.local", "nope")
        self.assertTrue(authenticator.login("demo@trustcap.local", PASSWORD).success)
        for _ in range(MAX_FAILED_ATTEMPTS - 1):
            authenticator.login("demo@trustcap.local", "nope")
        self.assertTrue(authenticator.login("demo@trustcap.local", PASSWORD).success)

    def test_not_configured_refuses_login(self):
        authenticator, _ = make_authenticator(password_hash="")
        result = authenticator.login("demo@trustcap.local", PASSWORD)
        self.assertFalse(result.success)
        self.assertIn("not configured", result.message)

    def test_empty_input(self):
        authenticator, _ = make_authenticator()
        self.assertFalse(authenticator.login("", "").success)


if __name__ == "__main__":
    unittest.main()
