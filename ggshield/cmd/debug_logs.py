import logging
import sys
from typing import Optional

import pygitguardian


LOG_FORMAT = "%(asctime)s %(levelname)s %(process)x:%(thread)x %(name)s:%(funcName)s:%(lineno)d %(message)s"

logger = logging.getLogger(__name__)


def setup_debug_logs(*, filename: Optional[str]) -> None:
    """Configure Python logger to log to stderr if filename is None, or to filename if
    it's set.
    """

    if sys.version_info[:2] < (3, 8):
        # Simulate logging.basicConfig() `force` argument, introduced in Python 3.8
        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            handler.close()
        logging.basicConfig(filename=filename, level=logging.DEBUG, format=LOG_FORMAT)
    else:
        logging.basicConfig(
            filename=filename, level=logging.DEBUG, format=LOG_FORMAT, force=True
        )

    # Silence charset_normalizer, its debug output does not bring much
    logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

    logger.debug("args=%s", sys.argv)
    logger.debug("py-gitguardian=%s", pygitguardian.__version__)
