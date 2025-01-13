from typing import Any, Sequence

from typing_extensions import Self

from ggshield.core.scan import Scannable
from ggshield.core.scanner_ui.scanner_ui import ScannerUI
from ggshield.core.ui.ggshield_ui import GGShieldUI


class RichMessageOnlyScannerUI(ScannerUI):
    """
    Basic UI, only supports showing messages when `on_*()` methods are called
    """

    def __init__(self, ui: GGShieldUI):
        self.ui = ui

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def on_scanned(self, scannables: Sequence[Scannable]) -> None:
        for scannable in scannables:
            self.ui.display_verbose(f"Scanned {scannable.path}")

    def on_skipped(self, scannable: Scannable, reason: str) -> None:
        if reason:
            message = f"Skipped {scannable.path}: {reason}"
            self.ui.display_info(message)


class RichProgressScannerUI(RichMessageOnlyScannerUI):
    """
    Show a progress bar in addition to messages when `on_*()` methods are called
    """

    def __init__(self, ui: GGShieldUI, total: int):
        super().__init__(ui)
        self.progress = ui.create_progress(total)

    def __enter__(self) -> Self:
        self.progress.__enter__()
        return self

    def __exit__(self, *args: Any) -> None:
        self.progress.__exit__(*args)

    def on_scanned(self, scannables: Sequence[Scannable]) -> None:
        super().on_scanned(scannables)
        self.progress.advance(len(scannables))

    def on_skipped(self, scannable: Scannable, reason: str) -> None:
        super().on_skipped(scannable, reason)
        self.progress.advance(1)
