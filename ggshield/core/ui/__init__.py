"""
Main entry point to produce progress output.

Keeps a GGShieldUI instance at module level and exposes the instance output methods as
plain functions.
"""

from logging import LogRecord

from .ggshield_ui import GGShieldProgress, GGShieldUI, Level
from .plain_text import PlainTextGGShieldUI
from .scanner_ui import ScannerUI


# GGShielUI instance to which top-level function forward their output.
# Can be changed using set_ui().
_ui: GGShieldUI = PlainTextGGShieldUI()


def set_level(level: Level) -> None:
    _ui.level = level


def set_ui(ui: GGShieldUI) -> None:
    """Change the GGShieldUI instance used to output messages. Takes care of
    carrying existing settings from the old instance to the new one."""
    global _ui
    ui.level = _ui.level
    _ui = ui


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


def create_scanner_ui(total: int, verbose: bool = False) -> ScannerUI:
    return _ui.create_scanner_ui(total, verbose=verbose)


def create_message_only_scanner_ui(verbose: bool = False) -> ScannerUI:
    return _ui.create_message_only_scanner_ui(verbose=verbose)
