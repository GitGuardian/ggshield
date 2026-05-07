import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Literal, Optional

import click
from pygitguardian.models import (
    AIDiscovery,
    MCPActivityRequest,
    MCPArgumentInfo,
    MCPPromptInfo,
    MCPResourceInfo,
    MCPToolInfo,
)

from ggshield.core.dirs import get_user_home_dir

from ..models import (
    Agent,
    EventType,
    HookPayload,
    HookResult,
    MCPConfiguration,
    MCPServer,
    Scope,
    Transport,
)


class Cursor(Agent):
    """Behavior specific to Cursor."""

    @property
    def name(self) -> str:
        return "cursor"

    @property
    def display_name(self) -> str:
        return "Cursor"

    @property
    def config_folder(self) -> Path:
        return get_user_home_dir() / ".cursor"

    def output_result(self, result: HookResult) -> int:
        response = {}
        if result.payload.event_type == EventType.USER_PROMPT:
            response["continue"] = not result.block
            response["user_message"] = result.message
        elif result.payload.event_type == EventType.PRE_TOOL_USE:
            response["permission"] = "deny" if result.block else "allow"
            response["user_message"] = result.message
            response["agent_message"] = result.message
        elif result.payload.event_type == EventType.POST_TOOL_USE:
            pass  # Nothing to do here
        else:
            # Should not happen, but just in case
            click.echo("{}")
            return 2 if result.block else 0

        click.echo(json.dumps(response))
        # We don't use the return 2 convention to make sure our JSON output is read.
        return 0

    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        return Path(".cursor") / "hooks.json"

    @property
    def settings_template(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "hooks": {
                "beforeSubmitPrompt": [{"command": "<COMMAND>"}],
                "preToolUse": [{"command": "<COMMAND>"}],
                "postToolUse": [{"command": "<COMMAND>"}],
            },
        }

    def settings_locate(
        self, candidates: List[Dict[str, Any]], template: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        # We only have one kind of lists: in each hook. Simply look for "ggshield" or "<COMMAND>" in the command.
        for obj in candidates:
            command = obj.get("command", "")
            if "ggshield" in command or "<COMMAND>" in command:
                return obj
        return None

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".cursor" / "mcp.json"

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        """Yield user-scoped MCP configurations from every known Cursor source."""
        yield from super()._get_user_mcp_configurations()
        yield from self._get_plugin_mcp_configurations()
        yield from self._get_extension_mcp_configurations()

    def _get_plugin_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        """Yield MCP servers contributed by installed Cursor plugins.

        Cursor stores marketplace plugins in
        ``~/.cursor/plugins/cache/<owner>/<plugin>/<version>/`` and
        locally-installed plugins in ``~/.cursor/plugins/local/<plugin>/``.
        Each plugin can declare MCP servers either in
        ``<installPath>/mcp.json`` (or ``.mcp.json``) or inline under the
        ``mcpServers`` key of ``<installPath>/.cursor-plugin/plugin.json``.
        """
        plugins_root = self.config_folder / "plugins"
        # Marketplace plugins: cache/<owner>/<plugin>/<version>/
        for install_dir in plugins_root.glob("cache/*/*/*"):
            if install_dir.is_dir():
                yield from self._parse_cursor_plugin_dir(install_dir)
        # Local plugins: local/<plugin>/
        for install_dir in plugins_root.glob("local/*"):
            if install_dir.is_dir():
                yield from self._parse_cursor_plugin_dir(install_dir)

    def _parse_cursor_plugin_dir(self, install_dir: Path) -> Iterator[MCPConfiguration]:
        """Parse a single Cursor plugin install directory and yield any MCP servers."""
        # Preferred location: mcp.json or .mcp.json at the plugin root. The
        # file may use either the wrapped {"mcpServers": {...}} layout or the
        # bare {"name": {...}} layout, so we normalize before parsing.
        for filename in ("mcp.json", ".mcp.json"):
            mcp_data = self._load_json_file(install_dir / filename)
            if mcp_data is not None:
                if "mcpServers" not in mcp_data and "servers" not in mcp_data:
                    mcp_data = {"mcpServers": mcp_data}
                yield from self._parse_servers_block(mcp_data, Scope.USER, None)
                return

        # Fallback: inline mcpServers in the plugin manifest.
        manifest = self._load_json_file(install_dir / ".cursor-plugin" / "plugin.json")
        if not manifest:
            return
        inline = manifest.get("mcpServers")
        if isinstance(inline, dict):
            yield from self._parse_servers_block(
                {"mcpServers": inline}, Scope.USER, None
            )

    def _get_extension_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        """Yield MCP servers contributed by installed Cursor (VS Code) extensions.

        Extensions can register MCP servers programmatically via the
        ``contributes.mcpServerDefinitionProviders`` field of their
        ``package.json``. The server's actual transport/URL/command is set at
        runtime, so we only emit a placeholder configuration with the
        provider's id/label as the name and STDIO transport as a sensible
        default.
        """
        packages = self.config_folder.glob("extensions/*/package.json")
        for package_path in packages:
            package = self._load_json_file(package_path)
            if not package:
                continue
            providers = package.get("contributes", {}).get(
                "mcpServerDefinitionProviders", []
            )
            if not isinstance(providers, list):
                continue
            for provider in providers:
                if not isinstance(provider, dict):
                    continue
                name = provider.get("label") or provider.get("id")
                if not name:
                    continue
                # Cursor seems to truncate the label when parentheses are present.
                # Could be worth investigating the exact behavior more.
                name = name.split("(")[0].strip()
                yield MCPConfiguration(
                    name=name,
                    agent=self.name,
                    scope=Scope.USER,
                    transport=Transport.STDIO,
                    project=None,
                )

    def discover_project_directories(self) -> Iterator[Path]:
        # Because Cursor is based on VS Code, we can reuse the same logic than Copilot.
        user_folder = get_user_home_dir() / ".config" / "Cursor" / "User"
        for file in user_folder.glob("workspaceStorage/*/workspace.json"):
            if (data := self._load_json_file(file)) and "folder" in data:
                path = Path(data["folder"].removeprefix("file://"))
                if path.is_dir():
                    yield path.resolve()

    def discover_capabilities(self, server: MCPServer) -> bool:
        # For each project where Cursor was used, it created a folder with the project name
        # in its configuration folder. Inside that folder, it stores metadata for every
        # MCP server available in that project (one subfolder per server).
        # General strategy:
        #  - get all Cursor's configuration names
        #  - look for a SERVER_METADATA.json file with the expected name.
        configuration_names = {
            configuration.name
            for configuration in server.configurations
            if configuration.agent == self.name
        }

        for configuration_name in configuration_names:
            # Note: we didn't restrict the project folder,
            # because some servers (like plugins) won't have them in their configuration.
            # Fortunately, the name of the folder is derived from the MCP server name,
            # so we can use it to reduce the number of folders to look at, so it is still fast.
            for file in self.config_folder.glob(
                f"projects/*/mcps/*{configuration_name}/SERVER_METADATA.json"
            ):
                metadata = self._load_json_file(file)
                if self._server_name_matches(metadata, configuration_name):
                    # Found it! Update the folder
                    folder = file.parent
                    break
            else:
                # We didn't find our MCP server's metadata. Try next configuration.
                continue

            # If we reach this code, we found our MCP server's metadata folder.
            # Hopefully it is connected. If not, Cursor creates a STATUS.md file.
            if (folder / "STATUS.md").exists():
                # Don't go further, we may risk discovering only an "mcp_auth" tool
                # whereas the MCP server may be properly connected in another project.
                continue

            filled = False
            # Tools
            for file in folder.glob("tools/*.json"):
                tool = self._load_json_file(file)
                if not isinstance(tool, dict) or "name" not in tool:
                    continue
                server.tools.append(
                    MCPToolInfo(
                        name=tool["name"],
                        description=tool.get("description", ""),
                        arguments=_parse_tool_arguments(tool.get("arguments")),
                    )
                )
                filled = True
            # Resources
            for file in folder.glob("resources/*.json"):
                resource = self._load_json_file(file)
                if not isinstance(resource, dict) or "uri" not in resource:
                    continue
                server.resources.append(
                    MCPResourceInfo(
                        uri=resource["uri"],
                        name=resource.get("name", ""),
                        description=resource.get("description", ""),
                        mime_type=resource.get("mimeType", ""),
                    )
                )
                filled = True
            # Prompts
            for file in folder.glob("prompts/*.json"):
                prompt = self._load_json_file(file)
                if not isinstance(prompt, dict) or "name" not in prompt:
                    continue
                server.prompts.append(
                    MCPPromptInfo(
                        name=prompt["name"], description=prompt.get("description", "")
                    )
                )
                filled = True
            if filled:
                # Discovery done. Early return.
                return True

        return False

    def _server_name_matches(
        self, metadata: Optional[Dict[str, Any]], name: str
    ) -> bool:
        """Check if the server name matches the metadata."""
        if metadata is None:
            return False
        server_name = metadata.get("serverName", "")
        # Extension-based servers are prefixed with "extension-"
        server_name = server_name.removeprefix("extension-")
        return server_name == name

    def parse_mcp_activity(
        self, payload: HookPayload, ai_config: AIDiscovery
    ) -> MCPActivityRequest:
        """Parse the MCP activity from an MCP hook payload."""

        # Cursor only sends the MCP tool, not the server.
        # Fortunately, we should have been able to discover the tools earlier.

        tools_to_server = {}
        for server in ai_config.servers:
            for tool in server.tools:
                # Hopefully we won't have duplicates
                tools_to_server[tool.name] = server.name

        raw_tool_name: str = payload.raw.get("tool_name", "")
        tool_name = raw_tool_name.removeprefix("MCP:")
        server_name = tools_to_server.get(tool_name, "")

        return MCPActivityRequest(
            user=ai_config.user,
            tool=tool_name,
            server=server_name,
            agent=self.name,
            model=payload.raw.get("model", ""),
            cwd=payload.raw.get("workspace_roots", [""])[0],
            input=payload.raw.get("tool_input", {}),
        )


def _parse_tool_arguments(
    schema: Optional[Dict[str, Any]],
) -> Optional[List[MCPArgumentInfo]]:
    """Parse a JSON-Schema ``arguments`` object into a list of MCPArgumentInfo.

    The schema is expected to follow the standard MCP tool descriptor format::

        {"type": "object", "properties": {...}, "required": [...]}
    """
    if not isinstance(schema, dict):
        return None
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return None
    required_set = set(schema.get("required", []))
    arguments: List[MCPArgumentInfo] = []
    for name, prop in properties.items():
        if not isinstance(prop, dict):
            continue
        arguments.append(
            MCPArgumentInfo(
                name=name,
                type=prop.get("type", "string"),
                description=prop.get("description"),
                required=name in required_set,
            )
        )
    return arguments or None
