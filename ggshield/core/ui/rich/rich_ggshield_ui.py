import sys
from typing import Any

import rich.markup
from rich.console import Console
from rich.highlighter import RegexHighlighter
from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from rich.theme import Theme
from typing_extensions import Self

from ggshield.core.log_utils import set_log_handler
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


class LogHighlighter(RegexHighlighter):
    """Rich highlighter used by our Rich logging handler"""

    base_style = "log."
    highlights = [
        r'(?P<attrib_name>[\w_-]{1,50})=(?P<attrib_value>"?[.\w_-]+"?)?',
        "|".join(
            [
                r"(?P<http_call>(GET|POST) /[^\"]+)",
                r"(?P<url>(file|https|http|ws|wss)://[-0-9a-zA-Z$_+!`(),.?/;:&=%#~]*)",
                r"=\[(?P<attrib_value>[^]]+)",
                r"(?P<env_var>\$[A-Z0-9_]+)",
            ]
        ),
    ]


class RichGGShieldUI(GGShieldUI):
    """
    Implementation of GGShieldUI using rich, for a more user-friendly terminal output.
    """

    def __init__(self):
        self.console = Console(
            file=sys.stderr,
            theme=Theme(
                {
                    "log.attrib_name": "dim yellow",
                    "log.attrib_value": "green",
                    "log.http_call": "magenta",
                    "log.url": "blue underline",
                    "log.command": "green",
                    "log.env_var": "red",
                }
            ),
        )

        handler = RichHandler(
            highlighter=LogHighlighter(),
            console=self.console,
            keywords=[],
        )
        set_log_handler(handler)

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
