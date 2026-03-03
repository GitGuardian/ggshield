from pathlib import Path

from .claude_code import Claude


class Copilot(Claude):
    """Behavior specific to Copilot Chat.

    Inherits most of its behavior from Claude Code.
    """

    name = "Copilot"

    @property
    def settings_path(self) -> Path:
        return Path(".github") / "hooks" / "hooks.json"
