import logging
import sys

import pygitguardian


LOG_FORMAT = "%(asctime)s %(levelname)s %(process)x:%(thread)x %(name)s:%(funcName)s:%(lineno)d %(message)s"

logger = logging.getLogger(__name__)


def setup_debug_logs(debug: bool) -> None:
    """Configure Python logger. Disable messages up to logging.ERROR level by default.

    The reason we disable error messages is that we call logging.error() in addition to
    showing user-friendly error messages, but we don't want the error logs to show up
    with the user-friendly error messages, unless --debug has been set.
    """
    level = logging.DEBUG if debug else logging.CRITICAL

    if sys.version_info[:2] < (3, 8):
        # Simulate logging.basicConfig() `force` argument, introduced in Python 3.8
        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            handler.close()
        logging.basicConfig(filename=None, level=level, format=LOG_FORMAT)
    else:
        logging.basicConfig(filename=None, level=level, format=LOG_FORMAT, force=True)

    if debug:
        # Silence charset_normalizer, its debug output does not bring much
        logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

    logger.debug("args=%s", sys.argv)
    logger.debug("py-gitguardian=%s", pygitguardian.__version__)
