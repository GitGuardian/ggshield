"""The redacted-by-default secret value wrapper."""

from __future__ import annotations

from ._constants import REDACTION_PLACEHOLDER


class Secret:
    """A secret value, redacted by default.

    ``repr()``, ``str()`` and therefore logging and f-strings all show
    ``[REDACTED]``; call :meth:`expose` to read the real value at the point
    of use.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def expose(self) -> str:
        """Return the secret value as a plain string.

        This is the explicit reveal boundary — keep the returned string's
        lifetime short and never log it.
        """
        return self._value

    def __repr__(self) -> str:
        return f"Secret({REDACTION_PLACEHOLDER})"

    def __str__(self) -> str:
        return REDACTION_PLACEHOLDER
