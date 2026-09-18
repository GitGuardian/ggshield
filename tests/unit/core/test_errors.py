import logging
from unittest.mock import MagicMock

import pytest
from pygitguardian.models import Detail

from ggshield.core.errors import (
    ServiceUnavailableError,
    UnexpectedError,
    handle_api_error,
)


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


def test_handle_api_error_429_raises_service_unavailable():
    """
    GIVEN a Detail with status_code=429 (the server throttled the scan and
    py-gitguardian gave up because Retry-After was missing or unparseable)
    WHEN handle_api_error() is called
    THEN it raises ServiceUnavailableError, so a throttled scan is reported as
    "the server did not scan this" rather than counted as a clean chunk.
    """
    detail = Detail("Too many requests", 429)

    with pytest.raises(ServiceUnavailableError):
        handle_api_error(detail)


def test_handle_api_error_non_transient_status_is_not_skippable():
    """
    GIVEN a 403 that is not the quota message (a token missing the scan scope,
    an instance refusing the caller's IP)
    WHEN handle_api_error() is called
    THEN it raises UnexpectedError, not ServiceUnavailableError: retrying will
    not fix it, so `--no-fail-on-server-error` must not wave it through.
    """
    with pytest.raises(UnexpectedError):
        handle_api_error(Detail("Insufficient scope", 403))
