import logging
from typing import Optional

from . import log


FILE_LOG_FORMAT = "%(asctime)s %(levelname)s %(process)x:%(thread)x %(name)s:%(funcName)s:%(lineno)d %(message)s"


_log_handler: Optional[logging.Handler] = None


class _LogHandler(logging.Handler):
    """Implements logging.Handler to pass the log record to ui.log()"""

    def emit(self, record: logging.LogRecord) -> None:
        log(record)


def disable_logs() -> None:
    """By default, disable all logs, because when an error occurs we log an error
    message and also print a human-friendly message using display_errors(). If we don't
    disable all logs, then error logs are printed, resulting in the error being shown
    twice.
    """
    logging.disable()


def set_log_handler(filename: Optional[str] = None) -> None:
    """Configure Python logger to log to stderr if filename is None, or to filename if
    it's set.
    """
    global _log_handler

    # Re-enable logging, reverting any call to disable_logs()
    logging.disable(logging.NOTSET)

    if filename and filename != "-":
        _log_handler = logging.FileHandler(filename)
        _log_handler.setFormatter(logging.Formatter(FILE_LOG_FORMAT))
    else:
        _log_handler = _LogHandler()

    logging.basicConfig(level=logging.DEBUG, force=True, handlers=[_log_handler])


def _reset_log_handler():
    """Remove our log handler. Used by reset.reset()."""
    global _log_handler
    if _log_handler:
        logging.getLogger().removeHandler(_log_handler)
        _log_handler = None
