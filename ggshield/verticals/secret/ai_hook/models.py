from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional

import click


MAX_READ_SIZE = 1024 * 1024 * 50  # We restrict payloads read to 50MB


class EventType(Enum):
    """Event type constants for hook events."""

    USER_PROMPT = auto()
    PRE_TOOL_USE = auto()
    POST_TOOL_USE = auto()
    # We are not interested in other less generic events for now
    # (most of the time, one of the three above will also be called anyway)
    OTHER = auto()


class Tool(Enum):
    """Tool constants for hook events."""

    BASH = auto()
    READ = auto()
    # We are not interested in other tools for now
    OTHER = auto()


@dataclass
class Result:
    """Result of a scan: allow or not."""

    event_type: EventType
    block: bool
    message: str
    nbr_secrets: int


class Flavor:
    """
    Class that can be derived to implement behavior specific to some AI code assistants.
    """

    name = "Your AI coding tool"

    def output_result(self, result: Result) -> int:
        """How to output the result of a scan.

        This base implementation has sensible defaults (like returning 2 in case of a block,
        and printing the output in stderr or stdout).

        This method is expected to have side effects, like printing to stdout or stderr.

        Args:
            result: the result of the scan.

        Returns: the exit code.
        """
        if result.block:
            click.echo(result.message, err=True)
            return 2
        else:
            click.echo("No secrets found. Good to go.")
            return 0

    @property
    def settings_path(self) -> Path:
        """Path to the settings file for this AI coding tool."""
        return Path(".agents") / "hooks.json"

    @property
    def settings_template(self) -> Dict[str, Any]:
        """
        Template for the settings file for this AI coding tool.
        Use the sentinel "<COMMAND>" for the places where the command should be inserted.
        """
        return {}

    def settings_locate(
        self, candidates: List[Dict[str, Any]], template: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Callback used to help locate the correct object to update in the settings.

        We don't want to overwrite other hooks nor create duplicates, so when the existing
        hook configuration is traversed and we end up in a list, this callback is used to
        locate the correct object to update.

        Args:
            candidates: the list of objects at the level currently traversed.
            template: the template of the expected object.

        Returns: the object to update, or None if no object was found.
        """
        return None


@dataclass
class Payload:
    event_type: EventType
    tool: Optional[Tool]
    content: str
    identifier: str
    flavor: Flavor
