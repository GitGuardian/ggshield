import logging
from unittest.mock import MagicMock

import pytest
from pygitguardian.models import Detail

from ggshield.core.errors import (
    ExitCode,
    ServiceUnavailableError,
    UnexpectedError,
    handle_api_error,
    handle_exception,
)
from ggshield.utils.git_shell import GitExecutableNotFound


HTML_500_PAGE = """
<html>
  <body><h1>Error</h1></body>
</html>
"""


def test_handle_api_error_logs_detail_at_debug(caplog):
    """
    GIVEN an API error with a detail message
    WHEN handle_api_error() is called
    THEN the detail text is logged at DEBUG level, not at ERROR level
    """
    detail = MagicMock()
    detail.status_code = 500
    detail.detail = "sensitive diagnostic info"

    with caplog.at_level(logging.DEBUG, logger="ggshield.core.errors"):
        with pytest.raises(Exception):
            handle_api_error(detail)

    debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
    error_msgs = [r.message for r in caplog.records if r.levelno == logging.ERROR]
    assert any("sensitive diagnostic info" in m for m in debug_msgs)
    assert not any("sensitive diagnostic info" in m for m in error_msgs)


def test_handle_api_error_html_5xx_shows_short_message(caplog):
    """
    GIVEN a 500 whose body is an HTML error page
    WHEN handle_api_error() is called
    THEN the error is one readable line and the page is only logged at DEBUG
    """
    with caplog.at_level(logging.DEBUG, logger="ggshield.core.errors"):
        with pytest.raises(ServiceUnavailableError) as exc_info:
            handle_api_error(Detail(HTML_500_PAGE, 500))

    assert str(exc_info.value) == (
        "The GitGuardian API failed with an internal error (HTTP 500)."
        " This can happen when a scan takes longer than the server allows."
        " Re-run the command with --debug to see the server response."
    )
    debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
    assert any(HTML_500_PAGE in m for m in debug_msgs)


def test_handle_api_error_plain_text_5xx_keeps_detail():
    """
    GIVEN a 503 whose body is plain text
    WHEN handle_api_error() is called
    THEN the error shows that text unchanged
    """
    with pytest.raises(ServiceUnavailableError, match="^Service is unavailable$"):
        handle_api_error(Detail("Service is unavailable", 503))


def test_handle_api_error_unknown_status_raises_unexpected_error():
    """
    GIVEN a Detail with status_code=None (e.g., malformed response from a proxy)
    WHEN handle_api_error() is called
    THEN it raises UnexpectedError, NOT ServiceUnavailableError. The
    --no-fail-on-server-error skip path is reserved for known connectivity
    failures (handled by SecretScanner._collect_results); a missing status
    code is opaque and must surface as a hard failure rather than be silently
    skipped.
    """
    detail = MagicMock()
    detail.status_code = None
    detail.detail = "Proxy returned HTML error page"

    with pytest.raises(UnexpectedError):
        handle_api_error(detail)


def test_handle_exception_renders_missing_git_actionably(capsys):
    """
    GIVEN a GitExecutableNotFound escaping a command
    WHEN handle_exception renders it
    THEN the user gets the reason and the install hint, without a --verbose hint,
    since a missing git is a problem with the machine, not a ggshield bug
    """
    exit_code = handle_exception(GitExecutableNotFound("no git anywhere"))
    out = capsys.readouterr()
    output = out.out + out.err
    assert exit_code == ExitCode.UNEXPECTED_ERROR
    assert "requires git: no git anywhere.\nInstall git and run the command again." in (
        output
    )
    assert "--verbose" not in output
