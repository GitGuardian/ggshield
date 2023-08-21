"""The primitives used for encryption and hashing"""

import secrets
from hashlib import sha256

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# Publicly available pepper used in our protocol with HasMySecretLeaked
_PEPPER = sha256(b"GitGuardian").digest()


class DecryptionError(Exception):
    """Raised when a message couldn't be decrypted,
    for instance because it wasn't encrypted with the same key."""


def hash_string(text: str) -> str:
    return (
        Scrypt(salt=_PEPPER, n=2048, r=8, p=1, length=32)
        .derive(text.encode("utf-8"))
        .hex()
    )


def make_hint(key_as_hex: str) -> str:
    """Make a hint from a key, to be used
    so that users can know which payload to decrypt."""
    return sha256(bytes.fromhex(key_as_hex)).hexdigest()


def encrypt(message: str, key: bytes) -> bytes:
    """Encrypt a message using AES-GCM with a random nonce.

    Key must be 32 bytes long.
    """
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(
        nonce=nonce, data=message.encode("utf-8"), associated_data=None
    )


def decrypt(payload: bytes, key: bytes) -> str:
    """Decrypt a message using AES-GCM. Key must be 32 bytes long."""
    try:
        cleartext = AESGCM(key).decrypt(
            nonce=payload[:12], data=payload[12:], associated_data=None
        )
        return cleartext.decode()
    except InvalidTag as exc:
        raise DecryptionError from exc
