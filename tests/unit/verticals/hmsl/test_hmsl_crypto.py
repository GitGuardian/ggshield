import secrets

import pytest

from ggshield.verticals.hmsl.crypto import (
    DecryptionError,
    decrypt,
    encrypt,
    hash_string,
)


@pytest.fixture
def key():
    return secrets.token_bytes(32)


def test_hash_string():
    string = "test"
    expected_hash = "bdbfe17c6018147f07ce79f8ec415a075d761ccacc14803e7d645155bf21a75f"
    assert hash_string(string) == expected_hash


def test_encrypt_decrypt(key):
    message = "Hello, world!"
    encrypted = encrypt(message, key)
    decrypted = decrypt(encrypted, key)
    assert decrypted == message


def test_encrypt_decrypt_invalid_key(key):
    message = "Hello, world!"
    key2 = secrets.token_bytes(32)

    encrypted = encrypt(message, key)
    with pytest.raises(DecryptionError):
        decrypt(encrypted, key2)


def test_decrypt_invalid_payload(key):
    invalid_payload = b"invalid_payload"

    with pytest.raises(DecryptionError):
        decrypt(invalid_payload, key)
