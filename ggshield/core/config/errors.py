from typing import Any, Dict

import click
from marshmallow import ValidationError


class ParseError(click.ClickException):
    """
    Failed to load file
    """

    pass


class AuthError(click.ClickException):
    """
    Base exception for Auth-related configuration error
    """

    def __init__(self, instance: str, message: str):
        super(AuthError, self).__init__(message)
        self.instance = instance


class UnknownInstanceError(AuthError):
    """
    Raised when the requested instance does not exist
    """

    def __init__(self, instance: str):
        super(UnknownInstanceError, self).__init__(
            instance, f"Unknown instance: '{instance}'"
        )


class AuthExpiredError(AuthError):
    """
    Raised when authentication has expired for the given instance
    """

    def __init__(self, instance: str):
        super(AuthExpiredError, self).__init__(
            instance,
            f"Instance '{instance}' authentication expired, please authenticate again.",
        )


class MissingTokenError(AuthError):
    def __init__(self, instance: str):
        super(MissingTokenError, self).__init__(
            instance, f"No token is saved for this instance: '{instance}'"
        )


def format_validation_error(exc: ValidationError) -> str:
    """
    Take a Marshmallow ValidationError and turn it into a more user-friendly message
    """
    message_dct = exc.normalized_messages()
    lines = []

    def format_items(dct: Dict[str, Any], indent: int) -> None:
        for key, value in dct.items():
            message = " " * indent + f"{key}: "
            if isinstance(value, dict):
                lines.append(message)
                format_items(value, indent + 2)
            else:
                message += str(value)
                lines.append(message)

    format_items(message_dct, 0)

    return "\n".join(lines)
