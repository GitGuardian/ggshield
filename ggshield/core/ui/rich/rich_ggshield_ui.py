import sys
from typing import Any

import rich.markup
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from typing_extensions import Self

from ggshield.core.ui.scanner_ui import ScannerUI

from ..ggshield_ui import GGShieldProgress, GGShieldUI
from .rich_scanner_ui import RichMessageOnlyScannerUI, RichProgressScannerUI


class RichGGShieldProgress(GGShieldProgress):
    def __init__(self, ui: "RichGGShieldUI", total: int) -> None:
        super().__init__(ui)

        self.progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("{task.completed} / {task.total}"),
            console=ui.console,
        )
        self.task = self.progress.add_task("Scanning...", total=total)

    def advance(self, amount: int) -> None:
        self.progress.advance(self.task, advance=amount)

    def __enter__(self) -> Self:
        self.progress.__enter__()
        return self

    def __exit__(self, *args: Any) -> None:
        self.progress.__exit__(*args)


class RichGGShieldUI(GGShieldUI):
    """
    Implementation of GGShieldUI using rich, for a more user-friendly terminal output.
    """

    def __init__(self):
        self.console = Console(file=sys.stderr)

    def create_scanner_ui(
        self,
        total: int,
        verbose: bool = False,
    ) -> ScannerUI:
        return RichProgressScannerUI(self, total, verbose)

    def create_message_only_scanner_ui(
        self,
        verbose: bool = False,
    ) -> ScannerUI:
        return RichMessageOnlyScannerUI(self, verbose)

    def create_progress(self, total: int) -> GGShieldProgress:
        return RichGGShieldProgress(self, total)

    def display_info(self, message: str) -> None:
        message = rich.markup.escape(message)
        self.console.print(message)

    def display_warning(self, message: str) -> None:
        message = rich.markup.escape(message)
        self.console.print(f"[yellow]Warning:[/] {message}")

    def display_error(self, message: str) -> None:
        message = rich.markup.escape(message)
        self.console.print(f"[red]Error:[/] {message}")
