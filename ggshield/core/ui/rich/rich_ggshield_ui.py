import logging
import sys
from typing import Any

import rich.markup
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from typing_extensions import Self

from ..ggshield_ui import NAME_BY_LEVEL, DebugInfo, GGShieldProgress, GGShieldUI, Level


COLOR_BY_LEVEL = {
    Level.DEBUG: "green",
    Level.VERBOSE: "white",
    Level.INFO: "blue",
    Level.WARNING: "yellow",
    Level.ERROR: "red",
}

LEVEL_BY_LOGGING_LEVEL = {
    logging.DEBUG: Level.DEBUG,
    logging.INFO: Level.INFO,
    logging.WARNING: Level.WARNING,
    logging.ERROR: Level.ERROR,
}


class RichGGShieldProgress(GGShieldProgress):
    def __init__(self, console: Console, total: int) -> None:
        super().__init__()

        self.progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("{task.completed} / {task.total}"),
            console=console,
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
        super().__init__()
        self.console = Console(file=sys.stderr)
        self._previous_timestamp = ""

    def create_progress(self, total: int) -> GGShieldProgress:
        return RichGGShieldProgress(self.console, total)

    def _echo(self, level: Level, message: str) -> None:
        message = rich.markup.escape(message)

        if self.level == Level.DEBUG:
            self._debug_echo(level, message)
        else:
            self._normal_echo(level, message)

    def _debug_echo(self, level: Level, rich_message: str) -> None:
        color = COLOR_BY_LEVEL[level]
        name = rich.markup.escape(f"[{NAME_BY_LEVEL[level][0]}]")
        message = f"[{color}]{name}[/] {rich_message}"

        self.console.print(self._prefix() + message)

    def _normal_echo(self, level: Level, message: str) -> None:
        if level <= Level.WARNING:
            color = COLOR_BY_LEVEL[level]
            name = NAME_BY_LEVEL[level]
            message = f"[{color}]{name}:[/] {message}"

        self.console.print(
            self._prefix() + message,
            # Disable highlight if we are not debugging, this way we get more control
            # on the output.
            highlight=False,
        )

    def _echo_heading(self, message: str) -> None:
        message = rich.markup.escape(message)
        prefix = self._prefix()
        self.console.print(f"\n[green]{prefix}# {message}[/]", highlight=False)

    def _prefix(self) -> str:
        if self.level < Level.DEBUG:
            return ""
        info = DebugInfo.create()

        # Do not repeat timestamp if it's the same as before
        if info.timestamp == self._previous_timestamp:
            timestamp = " " * len(info.timestamp)
        else:
            timestamp = info.timestamp
            self._previous_timestamp = timestamp

        return (
            f"[cyan]{timestamp}[/] [bright_black]{info.process_id}:{info.thread_id}[/] "
        )

    def log(self, record: logging.LogRecord) -> None:
        level = LEVEL_BY_LOGGING_LEVEL.get(record.levelno, Level.ERROR)
        msg = f"[magenta]{record.name}:{record.lineno}[/] {record.getMessage()}"
        self._debug_echo(level, msg)
