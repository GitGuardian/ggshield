from typing import TYPE_CHECKING, Any, Sequence

from typing_extensions import Self

from ggshield.core import ui
from ggshield.core.scanner_ui.scanner_ui import ScannerUI


if TYPE_CHECKING:
    from ggshield.core.scan import Scannable


class PlainTextScannerUI(ScannerUI):
    """
    Plain-text implementation of ScannerUI. Does not show progress.
    """

    def on_scanned(self, scannables: Sequence["Scannable"]) -> None:
        pass

    def on_skipped(self, scannable: "Scannable", reason: str) -> None:
        if reason:
            ui.display_info(f"Skipped {scannable.url}: {reason}")

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: Any) -> None:
        pass
