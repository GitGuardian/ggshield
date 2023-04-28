from typing import Any, Sequence

from ggshield.core.text_utils import create_progress_bar
from ggshield.scan.scannable import Scannable

from .secret_scanner import SecretScannerUI


class RichSecretScannerUI(SecretScannerUI):
    """
    Implementation of SecretScannerUI using Rich to show a progress bar and report
    events.
    """

    def __init__(
        self, total: int, dataset_type: str = "", scannable_type: str = "files"
    ):
        self.progress = create_progress_bar(scannable_type)
        task_title = f"Scanning {dataset_type}..." if dataset_type else "Scanning..."
        self.task = self.progress.add_task(task_title, total=total)

    def __enter__(self) -> "RichSecretScannerUI":
        self.progress.__enter__()
        return self

    def __exit__(self, *args: Any) -> None:
        self.progress.__exit__(*args)

    def on_scanned(self, scannables: Sequence[Scannable]) -> None:
        self.progress.advance(self.task, len(scannables))

    def on_skipped(self, scannable: Scannable, reason: str) -> None:
        if reason:
            message = f"Skipped {scannable.path}: {reason}"
            self.progress.console.print(message)
        self.progress.advance(self.task, 1)
