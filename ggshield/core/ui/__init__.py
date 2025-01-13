"""
Main entry point to produce progress output.

Keeps a GGShieldUI instance at module level and exposes the instance output methods as
plain functions.
"""

from logging import LogRecord

from .ggshield_ui import GGShieldProgress, GGShieldUI, Level
from .plain_text import PlainTextGGShieldUI


# GGShieldUI instance to which top-level functions forward their output.
# Can be changed using set_ui().
_ui: GGShieldUI = PlainTextGGShieldUI()


def set_level(level: Level) -> None:
    _ui.level = level


def get_level() -> Level:
    return _ui.level


def ensure_level(level: Level):
    """
    Make sure the verbosity level is at least set to `level`
    """
    if _ui.level < level:
        set_level(level)


def is_verbose() -> bool:
    """
    Convenient function to check if verbose messages are visible. Use this if displaying
    verbose messages is costly (for example displaying a list of files)
    """
    return _ui.level >= Level.VERBOSE


def set_ui(ui: GGShieldUI) -> None:
    """Change the GGShieldUI instance used to output messages. Takes care of
    carrying existing settings from the old instance to the new one."""
    global _ui
    ui.level = _ui.level
    _ui = ui


def get_ui() -> GGShieldUI:
    return _ui


def display_debug(message: str) -> None:
    _ui.display_debug(message)


def display_verbose(message: str) -> None:
    _ui.display_verbose(message)


def display_info(message: str) -> None:
    _ui.display_info(message)


def display_heading(message: str) -> None:
    _ui.display_heading(message)


def display_warning(message: str) -> None:
    _ui.display_warning(message)


def display_error(message: str) -> None:
    _ui.display_error(message)


def log(record: LogRecord) -> None:
    _ui.log(record)


def create_progress(total: int) -> GGShieldProgress:
    return _ui.create_progress(total)


def _reset_ui():
    """Reset the module to its startup state. Used by reset.reset()."""
    global _ui
    _ui = PlainTextGGShieldUI()
