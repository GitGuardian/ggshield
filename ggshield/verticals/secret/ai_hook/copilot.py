import json
from pathlib import Path
from typing import Any

import click

from .claude_code import Claude
from .models import Result


class Copilot(Claude):
    """Behavior specific to Copilot Chat.

    Inherits most of its behavior from Claude Code.
    """

    name = "Copilot"

    def output_result(self, result: Result) -> int:
        response: dict[str, Any] = {
            "continue": not result.block,
        }
        if result.block:
            # Having stopReason blocks Copilot, whether continue is true or false.
            response["stopReason"] = result.message

        click.echo(json.dumps(response))
        return 0

    @property
    def settings_path(self) -> Path:
        return Path(".github") / "hooks" / "hooks.json"
