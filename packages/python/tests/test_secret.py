"""Tests for the redaction wrapper and the error taxonomy."""

from gitguardian import (
    AuthenticationError,
    FieldNotFoundError,
    PermissionDeniedError,
    Secret,
    SecretError,
    SecretNotFoundError,
    UnsupportedOperationError,
)


def test_secret_hides_the_value_but_expose_reveals_it():
    secret = Secret("value-from-provider")

    assert secret.expose() == "value-from-provider"
    # repr / str / f-strings / logging all show the redaction stamp.
    assert "value-from-provider" not in repr(secret)
    assert "value-from-provider" not in f"logged: {secret}"
    assert repr(secret) == "Secret([REDACTED])"
    assert str(secret) == "[REDACTED]"


def test_exception_hierarchy():
    for subclass in (
        SecretNotFoundError,
        AuthenticationError,
        PermissionDeniedError,
        FieldNotFoundError,
        UnsupportedOperationError,
    ):
        assert issubclass(subclass, SecretError)
    assert issubclass(SecretError, Exception)
