import logging
import sys

from ggshield.core.ui.ggshield_ui import (
    NAME_BY_LEVEL,
    DebugInfo,
    GGShieldProgress,
    GGShieldUI,
    Level,
)


class PlainTextGGShieldProgress(GGShieldProgress):
    def advance(self, amount: int) -> None:
        pass


class PlainTextGGShieldUI(GGShieldUI):
    """
    Plain-text implementation of GGShieldUI. Suitable when output is not a TTY.
    """

    def _echo(self, level: Level, message: str) -> None:
        if self.level == Level.DEBUG:
            self._debug_echo(level, message)
        else:
            self._normal_echo(level, message)

    def _debug_echo(self, level: Level, message: str) -> None:
        name = NAME_BY_LEVEL[level][0]
        message = f"[{name}] {message}"
        err(self._prefix() + message)

    def _normal_echo(self, level: Level, message: str) -> None:
        if level <= Level.WARNING:
            name = NAME_BY_LEVEL[level]
            message = f"{name}: {message}"
        err(self._prefix() + message)

    def _echo_heading(self, message: str) -> None:
        prefix = self._prefix()
        err(prefix + message)
        err(prefix + "-" * len(message))

    def log(self, record: logging.LogRecord) -> None:
        msg = f"{record.name}:{record.lineno} {record.getMessage()}"
        level = record.levelno
        if level == logging.DEBUG:
            self.display_debug(msg)
        elif level == logging.INFO:
            self.display_info(msg)
        elif level == logging.WARNING:
            self.display_warning(msg)
        elif level == logging.ERROR:
            self.display_error(msg)
        else:
            self.display_warning(f"Unsupported log level {level}")
            self.display_error(msg)

    def create_progress(self, total: int) -> GGShieldProgress:
        return PlainTextGGShieldProgress()

    def _prefix(self) -> str:
        if self.level < Level.DEBUG:
            return ""
        info = DebugInfo.create()
        return f"{info.timestamp} {info.process_id}:{info.thread_id} "


def err(message: str) -> None:
    """Helper function to print to stderr and flush the output (if we don't flush some
    tests fail)"""
    print(message, file=sys.stderr)
    sys.stderr.flush()
