from . import _reset_ui
from .log_utils import _reset_log_handler


def reset():
    """
    This function is only used by unit-tests to reset the UI
    """
    _reset_log_handler()
    _reset_ui()
