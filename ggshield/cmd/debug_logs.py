import logging
import sys
from typing import Optional

import pygitguardian


LOG_FORMAT = "%(asctime)s %(levelname)s %(process)x:%(thread)x %(name)s:%(funcName)s:%(lineno)d %(message)s"

logger = logging.getLogger(__name__)


def disable_logs() -> None:
    """By default, disable all logs, because when an error occurs we log an error
    message and also print a human-friendly message using display_errors(). If we don't
    disable all logs, then error logs are printed, resulting in the error being shown
    twice.
    """
    logging.disable()


def setup_debug_logs(*, filename: Optional[str]) -> None:
    """Configure Python logger to log to stderr if filename is None, or to filename if
    it's set.
    """
    # Re-enable logging, reverting the call to disable_logs()
    logging.disable(logging.NOTSET)

    logging.basicConfig(
        filename=filename, level=logging.DEBUG, format=LOG_FORMAT, force=True
    )

    # Silence charset_normalizer, its debug output does not bring much
    logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

    logger.debug("args=%s", sys.argv)
    logger.debug("py-gitguardian=%s", pygitguardian.__version__)
