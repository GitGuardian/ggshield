"""Exception hierarchy for secret-store failures.

Mirrors the ``SecretError`` taxonomy of ``gitguardian-core`` so the Rust CLI
and this SDK report the same failures the same way.
"""

from __future__ import annotations


class SecretError(Exception):
    """Base error for all secret-store failures."""


class SecretNotFoundError(SecretError):
    """No secret exists at the requested path."""


class AuthenticationError(SecretError):
    """The provider rejected our credentials."""


class PermissionDeniedError(SecretError):
    """The provider refused access to the requested secret."""


class FieldNotFoundError(SecretError):
    """The secret exists but does not contain the requested field(s)."""


class UnsupportedOperationError(SecretError):
    """The provider does not support this operation."""


def missing_fields_error(fields: list[str]) -> FieldNotFoundError:
    """Build the error for fields absent from a secret, deduplicated."""
    unique = list(dict.fromkeys(fields))
    if len(unique) == 1:
        return FieldNotFoundError(f"field not found in secret: {unique[0]}")
    return FieldNotFoundError(f"fields not found in secret: {', '.join(unique)}")
