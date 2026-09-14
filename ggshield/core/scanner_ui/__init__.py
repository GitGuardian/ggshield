from ggshield.core.ui import get_ui

from .scanner_ui import ScannerUI


def create_scanner_ui(total: int) -> ScannerUI:
    """
    Creates a ScannerUI instance. This is used to show progress on scanning
    Scannables.
    """
    return get_ui().create_scanner_ui(total)


def create_message_only_scanner_ui() -> ScannerUI:
    """
    Creates a ScannerUI instance without a progress bar. This is used when the scan
    itself is part of a larger scan. For example when scanning a commit range, each
    commit gets a message-only ScannerUI. Progress of the commit range scan is
    represented by a progress bar created using `create_progress()`.
    """
    return get_ui().create_message_only_scanner_ui()
