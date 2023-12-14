from abc import ABC, abstractmethod
from typing import Any

from typing_extensions import Self

from .scanner_ui import ScannerUI


class GGShieldProgress(ABC):
    """
    A generic progress bar. Must be created using `GGShieldUI.create_progress()` and
    used as a context manager.
    """

    def __init__(self, ui: "GGShieldUI"):
        self.ui = ui

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
    this class (this is not the case at the moment).
    """

    @abstractmethod
    def create_scanner_ui(
        self,
        total: int,
        verbose: bool = False,
    ) -> ScannerUI:
        """
        Creates a ScannerUI instance. This is used to show progress on scanning
        Scannables.
        """
        ...

    @abstractmethod
    def create_message_only_scanner_ui(
        self,
        verbose: bool = False,
    ) -> ScannerUI:
        """
        Creates a ScannerUI instance without a progress bar. This is used when the scan
        itself is part of a larger scan. For example when scanning a commit range, each
        commit gets a message-only ScannerUI. Progress of the commit range scan is
        represented by a progress bar created using `create_progress()`.
        """
        ...

    @abstractmethod
    def create_progress(self, total: int) -> GGShieldProgress:
        """
        Creates a generic progress bar, not tied not scannables.
        """
        ...

    @abstractmethod
    def display_info(self, message: str) -> None:
        """
        Display an information message. Can be called while a progress bar is visible
        without messing the display.
        """
        ...

    @abstractmethod
    def display_warning(self, message: str) -> None:
        """
        Display a warning message. Can be called while a progress bar is visible without
        messing the display.
        """
        ...

    @abstractmethod
    def display_error(self, message: str) -> None:
        """
        Display an error message. Can be called while a progress bar is visible without
        messing the display.
        """
        ...
