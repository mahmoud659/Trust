"""
demo_keys.py
------------
Manages a persistent ECDSA P-256 demo key pair for the TrustCap prototype.

Keys are stored in the 'keys/' subdirectory.
On first call to get_or_create_keys(), keys are generated and saved.
Subsequent calls load from disk.

The demo Private Key exists ONLY to simulate client-side signing.
In production, the private key must remain on the client device
and must never be transmitted anywhere.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

KEY_ID = "demo-key-001"
KEYS_DIR = Path(__file__).parent / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"


def get_or_create_keys():
    """
    Returns (private_key_object, public_key_object, public_key_pem_str).
    Generates and persists keys on first call; loads from disk thereafter.
    """
    KEYS_DIR.mkdir(exist_ok=True)

    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        # Load from disk
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key_pem = f.read()
        public_key = serialization.load_pem_public_key(public_key_pem)
        return private_key, public_key, public_key_pem.decode("utf-8")

    # Generate new key pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_pem)
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_pem)

    return private_key, public_key, public_pem.decode("utf-8")


def get_public_key_pem() -> str:
    """Convenience helper — returns the public key PEM string."""
    _, _, pem = get_or_create_keys()
    return pem
