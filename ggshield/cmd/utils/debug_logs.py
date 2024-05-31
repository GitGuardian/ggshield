import logging
import sys
from typing import Optional

import pygitguardian
from rich.console import Console
from rich.highlighter import RegexHighlighter
from rich.logging import RichHandler

from ggshield.utils.logger import Logger


LOG_FORMAT = "%(asctime)s %(levelname)s %(process)x:%(thread)x %(name)s:%(funcName)s:%(lineno)d %(message)s"

logger = Logger(__name__)


def disable_logs() -> None:
    """By default, disable all logs, because when an error occurs we log an error
    message and also print a human-friendly message using display_errors(). If we don't
    disable all logs, then error logs are printed, resulting in the error being shown
    twice.
    """
    logging.disable()


class GGShieldHighlighter(RegexHighlighter):
    base_style = "repr."
    highlights = [
        "|".join(
            [
                # FIXME use match groups which make sense
                r"(?P<call>(GET|POST) /[^\"]+)",
                r"(?P<url>(file|https|http|ws|wss)://[-0-9a-zA-Z$_+!`(),.?/;:&=%#~]*)",
                r"(?P<number>command=\[[^]]+\])",
                r"(?P<ipv4>\$[A-Z0-9_]+)",
            ]
        )
    ]


_log_level = logging.INFO
_console = None


def setup_debug_logs(
    *,
    level: Optional[int] = None,
    filename: Optional[str] = None,
    console: Optional[Console] = None,
) -> None:
    """Configure Python logger to log to stderr if filename is None, or to filename if
    it's set.
    """
    global _log_level
    global _console
    # Re-enable logging, reverting the call to disable_logs()
    logging.disable(logging.NOTSET)

    if level:
        _log_level = level

    if console:
        _console = console

    if _console:
        FORMAT = "%(message)s"

        handler = RichHandler(
            highlighter=GGShieldHighlighter(),
            console=_console,
            keywords=[],
        )
        logging.basicConfig(
            level=_log_level,
            format=FORMAT,
            datefmt="[%X]",
            handlers=[handler],
            force=True,
        )
    else:
        logging.basicConfig(
            filename=filename, level=_log_level, format=LOG_FORMAT, force=True
        )

    # Silence charset_normalizer, its debug output does not bring much
    logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

    logger.debug("args=%s", sys.argv)
    logger.debug("py-gitguardian=%s", pygitguardian.__version__)
