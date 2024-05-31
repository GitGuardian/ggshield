import logging
from unittest.mock import Mock

from ggshield.core import log_utils


def test_set_log_handler():
    """
    GIVEN set_log_handler() has been called with a log handler
    WHEN setup_debug_logs() is called
    THEN its log messages go to the handler passed to set_log_handler()
    """

    log_handler = Mock(logging.Handler)
    log_handler.level = logging.DEBUG

    log_utils.set_log_handler(log_handler)
    log_utils.setup_debug_logs()

    calls = log_handler.handle.call_args_list
    log_records = [x.args[0] for x in calls]

    assert log_records[0].message.startswith("args=")
    assert log_records[1].message.startswith("py-gitguardian=")
