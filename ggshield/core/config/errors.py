from enum import IntEnum
from typing import Any, Dict

import click
from marshmallow import ValidationError


class ExitCode(IntEnum):
    """
    Define constant exit codes based on their type
    """

    SUCCESS = 0
    # Scan was successful, and found problems (leaked secrets, IAC security issues...)
    SCAN_FOUND_PROBLEMS = 1
    # Error on the command-line, like a missing parameter
    USAGE_ERROR = 2
    # auth subcommand failed
    AUTHENTICATION_ERROR = 3

    # Catch all for other failures
    UNEXPECTED_ERROR = 128


class _ExitError(click.ClickException):
    """
    Base class for exceptions which must exit with an exit code as defined in ExitCode.

    This class is internal, inherit from it to create public exception classes.
    """

    def __init__(self, exit_code: ExitCode, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class ParseError(_ExitError):
    """
    Failed to load file
    """

    def __init__(self, message: str):
        super().__init__(ExitCode.UNEXPECTED_ERROR, message)


class AuthError(_ExitError):
    """
    Base exception for Auth-related configuration error
    """

    def __init__(self, instance: str, message: str):
        super().__init__(ExitCode.AUTHENTICATION_ERROR, message)
        self.instance = instance


class UnknownInstanceError(AuthError):
    """
    Raised when the requested instance does not exist
    """

    def __init__(self, instance: str):
        super().__init__(instance, f"Unknown instance: '{instance}'")


class AuthExpiredError(AuthError):
    """
    Raised when authentication has expired for the given instance
    """

    def __init__(self, instance: str):
        super().__init__(
            instance,
            f"Instance '{instance}' authentication expired, please authenticate again.",
        )


class MissingTokenError(AuthError):
    def __init__(self, instance: str):
        super().__init__(instance, f"No token is saved for this instance: '{instance}'")


class ScanFoundProblemsError(_ExitError):
    """
    Raised when problems are found during a scan
    """

    def __init__(self) -> None:
        super().__init__(ExitCode.SCAN_FOUND_PROBLEMS, "")


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
