"""
This module centralizes GGShield error handling. For more details, have a look
at doc/dev/error-handling.md.
"""

import logging
import platform
import traceback
from enum import IntEnum
from typing import Any, Dict, List

import click
from marshmallow import ValidationError
from pygitguardian.models import Detail, TokenScope

from ggshield.core.text_utils import pluralize
from ggshield.utils.git_shell import InvalidGitRefError


logger = logging.getLogger(__name__)


class ExitCode(IntEnum):
    """
    Define constant exit codes based on their type
    """

    # Everything went well
    SUCCESS = 0
    # Scan was successful, and found problems (e.g. leaked secrets)
    SCAN_FOUND_PROBLEMS = 1
    # Error on the command-line, like a missing parameter
    USAGE_ERROR = 2
    # auth subcommand failed
    AUTHENTICATION_ERROR = 3
    # GitGuardian server is not responding
    GITGUARDIAN_SERVER_UNAVAILABLE = 4

    # Add new exit codes here.
    # If you add a new exit code, make sure you also add it to the documentation.

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


class UnexpectedError(_ExitError):
    def __init__(self, message: str) -> None:
        super().__init__(ExitCode.UNEXPECTED_ERROR, message)


class ParseError(_ExitError):
    """
    Failed to load file
    """

    def __init__(self, message: str):
        super().__init__(ExitCode.UNEXPECTED_ERROR, message)


class MissingScopesError(_ExitError):
    """
    Token does not have the required scope
    """

    def __init__(self, token_scopes: List[TokenScope]):
        scopes_list = ", ".join([scope.value for scope in token_scopes])
        super().__init__(
            ExitCode.UNEXPECTED_ERROR,
            f"Token is missing the required {pluralize('scope', len(token_scopes))} {scopes_list} to perform this operation.",  # noqa
        )


class AuthError(_ExitError):
    """
    Base exception for Auth-related configuration error
    """

    def __init__(self, instance: str, message: str):
        super().__init__(ExitCode.AUTHENTICATION_ERROR, message)
        self.instance = instance


class QuotaLimitReachedError(_ExitError):
    def __init__(self):
        super().__init__(
            ExitCode.UNEXPECTED_ERROR,
            "Could not perform the requested action: no more API calls available.",
        )


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


class APIKeyCheckError(AuthError):
    """
    Raised when checking the API key fails
    """

    def __init__(self, instance: str, message: str):
        super().__init__(instance, message)


class ServiceUnavailableError(_ExitError):
    """
    Raised when the server is unavailable
    """

    def __init__(self, message: str):
        super().__init__(ExitCode.GITGUARDIAN_SERVER_UNAVAILABLE, message)


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


def handle_exception(exc: Exception) -> int:
    """
    Take an exception, print information about it and return the exit code to use
    """
    # TODO: fix this. It's required to avoid a circular import error
    from ggshield.core import ui

    if isinstance(exc, click.exceptions.Abort):
        return ExitCode.SUCCESS

    # Get exit code
    if isinstance(exc, _ExitError):
        exit_code = exc.exit_code
    elif isinstance(exc, (InvalidGitRefError, click.UsageError)):
        exit_code = ExitCode.USAGE_ERROR
    else:
        exit_code = ExitCode.UNEXPECTED_ERROR

    click.echo()
    ui.display_error(str(exc))
    if isinstance(exc, UnicodeEncodeError) and platform.system() == "Windows":
        ui.display_info(
            "\n"
            "ggshield failed to print a message because of an Unicode encoding issue."
            " To workaround that, try setting the PYTHONUTF8 environment variable to 1."
        )

    if not isinstance(exc, click.ClickException):
        click.echo()
        if ui.is_verbose():
            traceback.print_exc()
        else:
            ui.display_info("Re-run the command with --verbose to get a stack trace.")

    return exit_code


def handle_api_error(detail: Detail) -> None:
    # Use %s for status_code because it can be None. Logger is OK with an int being
    # passed for a %s placeholder.
    logger.error("status_code=%s detail=%s", detail.status_code, detail.detail)
    if detail.status_code == 401:
        raise click.UsageError(detail.detail)
    if detail.status_code is None:
        raise UnexpectedError(f"Scanning failed: {detail.detail}")
    if detail.status_code == 403 and detail.detail == "Quota limit reached.":
        raise QuotaLimitReachedError()
    if detail.status_code == 400 and "not found" in detail.detail:
        raise UnexpectedError(detail.detail)
    if 500 <= detail.status_code < 600:
        raise ServiceUnavailableError(detail.detail)
