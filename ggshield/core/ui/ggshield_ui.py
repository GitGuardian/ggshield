import os
import threading
import time
from abc import ABC, abstractmethod
from enum import IntEnum, auto
from logging import LogRecord
from typing import Any, NamedTuple

from typing_extensions import Self


class Level(IntEnum):
    ERROR = auto()
    WARNING = auto()
    INFO = auto()
    VERBOSE = auto()
    DEBUG = auto()


NAME_BY_LEVEL = {
    Level.DEBUG: "Debug",
    Level.VERBOSE: "Verbose",
    Level.INFO: "Info",
    Level.WARNING: "Warning",
    Level.ERROR: "Error",
}


class GGShieldProgress(ABC):
    """
    A generic progress bar. Must be created using `GGShieldUI.create_progress()` and
    used as a context manager.
    """

    @abstractmethod
    def advance(self, amount: int) -> None:
        """
        Move the progress bar by `amount` steps.
        """
        ...

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class GGShieldUI(ABC):
    """Represents GGShield "UI", all progress-feedback code should ultimately go through
    this class.
    """

    def __init__(self):
        self.level = Level.INFO

    @abstractmethod
    def create_progress(self, total: int) -> GGShieldProgress:
        """
        Creates a generic progress bar, not tied not scannables.
        """
        ...

    def display_debug(self, message: str) -> None:
        if self.level >= Level.DEBUG:
            self._echo(Level.DEBUG, message)

    def display_verbose(self, message: str) -> None:
        if self.level >= Level.VERBOSE:
            self._echo(Level.VERBOSE, message)

    def display_heading(self, message: str) -> None:
        if self.level >= Level.INFO:
            self._echo_heading(message)

    def display_info(self, message: str) -> None:
        if self.level >= Level.INFO:
            self._echo(Level.INFO, message)

    def display_warning(self, message: str) -> None:
        if self.level >= Level.WARNING:
            self._echo(Level.WARNING, message)

    def display_error(self, message: str) -> None:
        if self.level >= Level.ERROR:
            self._echo(Level.ERROR, message)

    def log(self, record: LogRecord) -> None:
        """
        Print a log record produced by the logging package.
        Should not be called directly.
        """
        ...

    @abstractmethod
    def _echo(self, level: Level, message: str) -> None:
        """
        Format `message` according to `level` and print it.
        """
        ...

    @abstractmethod
    def _echo_heading(self, message: str) -> None:
        """
        Format `message` as a heading and print it.
        """
        ...


class DebugInfo(NamedTuple):
    """
    Helper class to gather useful information for debugging
    """

    timestamp: str
    process_id: int
    thread_id: int

    @staticmethod
    def create() -> "DebugInfo":
        return DebugInfo(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            process_id=os.getpid(),
            thread_id=threading.get_native_id(),
        )
