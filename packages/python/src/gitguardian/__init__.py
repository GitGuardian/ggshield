"""GitGuardian secrets SDK — read secrets straight into memory.

The high-level entry point is :class:`SecretStore`: build one for a
:class:`Provider`, then read secrets directly from your application code::

    from gitguardian import Provider, SecretStore

    store = SecretStore(Provider.VAULT)
    stripe = store.get_secret("secret/myapp", "STRIPE_KEY")
    charge(api_key=stripe.expose())

Providers are declared as data in ``providers/<name>.yaml`` and exposed as the
:class:`Provider` enum. Resolved secret values are returned as :class:`Secret`
so they are not accidentally leaked through ``repr()``, ``str()``, logging, or
f-strings — callers must opt in with ``expose()`` to read them.
"""

from ._definition import Provider
from ._errors import (
    AuthenticationError,
    FieldNotFoundError,
    PermissionDeniedError,
    SecretError,
    SecretNotFoundError,
    UnsupportedOperationError,
)
from ._secret import Secret
from ._store import SecretStore

__all__ = [
    "AuthenticationError",
    "FieldNotFoundError",
    "PermissionDeniedError",
    "Provider",
    "Secret",
    "SecretError",
    "SecretNotFoundError",
    "SecretStore",
    "UnsupportedOperationError",
]
