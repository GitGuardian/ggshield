"""
High level log and debug configuration.

core.ui.log_utils contains code which is independent of ggshield itself.

This module contains ggshield-specific logging code, such as logging arguments and
version numbers, or manipulating the log level of some ggshield dependencies.
"""

import logging
import sys
from typing import Optional

import pygitguardian

from ggshield.core import ui
from ggshield.core.ui import log_utils


logger = logging.getLogger(__name__)


def setup_debug_mode(*, filename: Optional[str] = None) -> None:
    """
    Enable debug mode: set up logger and set the UI level to DEBUG.
    """
    ui.set_level(ui.Level.DEBUG)

    log_utils.set_log_handler(filename)

    # Silence charset_normalizer, its debug output does not bring much
    logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

    logger.debug("args=%s", sys.argv)
    logger.debug("py-gitguardian=%s", pygitguardian.__version__)


def reset_debug_mode() -> None:
    """
    This function is used by unit-tests.
    """
    log_utils.reset_log_handler()
    ui.set_level(ui.Level.INFO)
