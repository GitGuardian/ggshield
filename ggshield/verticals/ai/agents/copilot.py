import re
from pathlib import Path
from typing import Dict, Iterator, Tuple

from ggshield.core.dirs import get_user_home_dir
from ggshield.verticals.ai.models import (
    AIDiscovery,
    EventType,
    HookPayload,
    MCPConfiguration,
    Scope,
    Tool,
    Transport,
)

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
        # Hard-coded Github MCP server
        yield MCPConfiguration(
            name="github-mcp-server",
            agent=self.name,
            scope=Scope.USER,
            project=None,
            transport=Transport.HTTP,
            url="https://api.individual.githubcopilot.com/mcp/readonly",
        )

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

    def post_process_payload(self, payload: HookPayload):
        # Copilot CLI doesn't prefix the MCP tools by any specific string,
        # so we need to identify them by elimination.
        if payload.tool == Tool.OTHER:
            tool_name = payload.raw.get("tool_name", "")
            # The list of tools provided in the official documentation is not exhaustive,
            # (they don't list "report_intent" for instance), so I have no confidence in having
            # a whitelist/blacklist. Instead, we rely on the fact that Copilot separates the server
            # and tool names by a "-", which is never used in other tool names (they are snake_cased).
            if "-" in tool_name:
                payload.tool = Tool.MCP

    def _lookup_server_name(
        self, raw_tool_name: str, ai_config: AIDiscovery
    ) -> Tuple[str, str]:
        # Copilot's hook tool name is "{server}-{tool}"
        # which is unfortunate because server names can contain "-" in their name.
        # It also mangles the config name (replaces spaces, uses punycode encoding, ...).
        # It doesn't look like it can import MCP servers from other agents, so we filter them to avoid
        # false positives.
        # We look for the longest chain of parts separated by "-" that is a valid server configuration name.

        # Build a map of mangled server configuration names to server names.
        mangled_to_server: Dict[str, str] = {
            _mangle_name(configuration.name): server.name
            for server in ai_config.servers
            for configuration in server.configurations
            if configuration.agent == self.name
        }

        parts = raw_tool_name.split("-")

        # At each separation point (starting from the biggest name possible), check if the mangled name is in the map.
        for i in range(len(parts)):
            # lower() because of IDNA encoding, whereas Copilot preserves the case.
            mangled_name = "-".join(parts[:-i]).lower()
            if mangled_name in mangled_to_server:
                return mangled_to_server[mangled_name], "-".join(parts[-i:])

        # If no match is found, fallback to use the last part as the tool name.
        return "-".join(parts[:-1]), parts[-1]


def _mangle_name(name: str) -> str:
    """Mangle a name in the same way Copilot does."""
    return re.sub(r"\W", "-", name.lower()).encode("idna").decode()
