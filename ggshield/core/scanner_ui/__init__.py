from ggshield.core.scanner_ui.plain_text_scanner_ui import PlainTextScannerUI
from ggshield.core.scanner_ui.rich_scanner_ui import (
    RichMessageOnlyScannerUI,
    RichProgressScannerUI,
)
from ggshield.core.ui import get_ui
from ggshield.core.ui.rich import RichGGShieldUI

from .scanner_ui import ScannerUI


def create_scanner_ui(total: int) -> ScannerUI:
    """
    Creates a ScannerUI instance. This is used to show progress on scanning
    Scannables.
    """
    if isinstance(get_ui(), RichGGShieldUI):
        return RichProgressScannerUI(get_ui(), total)
    else:
        return PlainTextScannerUI()


def create_message_only_scanner_ui():
    """
    Creates a ScannerUI instance without a progress bar. This is used when the scan
    itself is part of a larger scan. For example when scanning a commit range, each
    commit gets a message-only ScannerUI. Progress of the commit range scan is
    represented by a progress bar created using `create_progress()`.
    """
    if isinstance(get_ui(), RichGGShieldUI):
        return RichMessageOnlyScannerUI(get_ui())
    else:
        return PlainTextScannerUI()
