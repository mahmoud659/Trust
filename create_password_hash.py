"""
create_password_hash.py
-----------------------
Generates the AUTH_PASSWORD_HASH line for .env, so the real password is
never written to disk.

Usage:
    python create_password_hash.py
"""

import getpass

from services.auth_service import hash_password


def main() -> None:
    password = getpass.getpass("New password: ")
    confirmation = getpass.getpass("Repeat password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    if len(password) < 10:
        raise SystemExit("Use at least 10 characters.")
    print("\nAdd this line to .env (replace the old AUTH_PASSWORD_HASH):\n")
    print(f"AUTH_PASSWORD_HASH={hash_password(password)}")


if __name__ == "__main__":
    main()
