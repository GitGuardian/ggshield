import logging
from unittest.mock import MagicMock

import pytest

from ggshield.core.errors import handle_api_error


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
