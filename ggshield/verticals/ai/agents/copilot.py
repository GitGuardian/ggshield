from .vscode import VSCode


class Copilot(VSCode):
    """Behavior specific to Copilot CLI.

    Inherits most of its behavior from VSCode.
    """

    @property
    def name(self) -> str:
        return "copilot"

    @property
    def display_name(self) -> str:
        return "Copilot CLI"
