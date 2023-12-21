import sys

from ggshield.core.ui.ggshield_ui import GGShieldProgress, GGShieldUI
from ggshield.core.ui.plain_text.plain_text_scanner_ui import PlainTextScannerUI
from ggshield.core.ui.scanner_ui import ScannerUI


class PlainTextGGShieldProgress(GGShieldProgress):
    def advance(self, amount: int) -> None:
        pass


class PlainTextGGShieldUI(GGShieldUI):
    """
    Plain-text implementation of GGShieldUI. Suitable when output is not a TTY.
    """

    def create_scanner_ui(
        self,
        total: int,
        verbose: bool = False,
    ) -> ScannerUI:
        return PlainTextScannerUI()

    def create_message_only_scanner_ui(
        self,
        verbose: bool = False,
    ) -> ScannerUI:
        return PlainTextScannerUI()

    def create_progress(self, total: int) -> GGShieldProgress:
        return PlainTextGGShieldProgress(self)

    def display_info(self, message: str) -> None:
        print(message, file=sys.stderr)

    def display_warning(self, message: str) -> None:
        print(f"WARNING: {message}", file=sys.stderr)

    def display_error(self, message: str) -> None:
        print(f"ERROR: {message}", file=sys.stderr)
