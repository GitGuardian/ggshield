from pathlib import Path
from typing import Iterator

from ggshield.core.dirs import get_user_home_dir
from ggshield.verticals.ai.models import EventType, HookPayload, MCPConfiguration, Scope

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

    @property
    def config_folder(self) -> Path:
        return get_user_home_dir() / ".copilot"

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".mcp.json"

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        # Load config file
        filepath = self.config_folder / "mcp-config.json"
        if not (data := self._load_json_file(filepath)):
            return
        yield from self._parse_servers_block(data, Scope.USER, None)
        # Search in installed plugins
        for plugin_folder in self.config_folder.glob("installed-plugins/*/*/"):
            for config in self._get_project_mcp_configurations(plugin_folder):
                config.scope = Scope.USER
                config.project = None
                yield config

    def is_caller(self, hook_payload: dict[str, str]) -> bool:
        # Copilot CLI only emits the default fields in all hooks, which in a way identifies it.
        default_fields = {"hook_event_name", "session_id", "timestamp", "cwd"}
        optional_fields = {"prompt", "tool_name", "tool_input", "tool_result"}
        return set(hook_payload.keys()) - optional_fields == default_fields

    def has_secret_already_leaked(self, payload: HookPayload) -> bool:
        # Copilot CLI doesn't allow blocking on UserPromptSubmit.
        # Special case: if we found a secret because we read a file that was "@" in a prompt,
        # then we did prevent the leak.
        if payload.event_type == EventType.USER_PROMPT and payload.tool is None:
            return True
        return super().has_secret_already_leaked(payload)
