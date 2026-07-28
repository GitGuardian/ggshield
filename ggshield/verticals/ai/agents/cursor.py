import json
import logging
import sqlite3
from datetime import datetime
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

from ggshield.core.dirs import get_editor_user_data_dir, get_user_home_dir

from ..agent_activity.sources import SQLiteActivitySource
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


logger = logging.getLogger(__name__)


# Cursor tags every tool call in cursorDiskKV bubbles with a numeric "tool" kind
# under $.toolFormerData.tool. 19 is the MCP kind. Brittle — bump if Cursor
# renumbers tool kinds in a future release.
MCP_TOOL_KIND = 19

CHAT_DB_RELATIVE_PATH = (
    Path(".config") / "Cursor" / "User" / "globalStorage" / "state.vscdb"
)


class CursorActivitySource(SQLiteActivitySource):
    """Every Cursor composer bubble, shipped raw.

    Cursor stores chat bubbles (prompts, assistant turns, tool calls) as JSON
    blobs in the cursorDiskKV table of its SQLite state.vscdb, keyed
    bubbleId:<composer>:<bubble>. The database lives outside the agent's config
    dir, so source_path_for falls back to its absolute path.

    Each row is shipped verbatim ({"key": …, "value": <bubble json>});
    GitGuardian scans and strips secrets server-side before storing it.
    """

    key_columns = ("key",)

    def discover(self) -> Iterator[Path]:
        db_path = get_editor_user_data_dir("Cursor") / "globalStorage" / "state.vscdb"
        return iter([db_path] if db_path.is_file() else [])


class BubbleActivitySource(CursorActivitySource):
    kind = "6_composer_bubble"
    query = "SELECT key, value FROM cursorDiskKV WHERE key LIKE 'bubbleId:%'"


class ComposerActivitySource(CursorActivitySource):
    kind = "5_composer_data"
    query = "SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%'"


class Cursor(Agent):
    """Behavior specific to Cursor."""

    # Composer must be first, to have the metadata to populate the bubble session.
    agent_activity_sources = [ComposerActivitySource(), BubbleActivitySource()]

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
        message = result.message or result.warning
        response = {}
        if result.payload.event_type == EventType.USER_PROMPT:
            response["continue"] = not result.block
            response["user_message"] = message
        elif result.payload.event_type == EventType.PRE_TOOL_USE:
            response["permission"] = "deny" if result.block else "allow"
            response["user_message"] = message
            response["agent_message"] = message
        elif result.payload.event_type == EventType.POST_TOOL_USE:
            pass  # Nothing to do here
        else:
            # Should not happen, but just in case
            click.echo("{}")
            return 2 if result.block else 0

        click.echo(json.dumps(response))
        # We don't use the return 2 convention to make sure our JSON output is read.
        return 0

    def is_caller(self, hook_payload: Dict[str, Any]) -> bool:
        return "cursor_version" in hook_payload

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

    @property
    def user_mcp_file(self) -> Path:
        return self.config_folder / "mcp.json"

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
            mcp_data = self._load_file(install_dir / filename)
            if mcp_data is not None:
                if "mcpServers" not in mcp_data and "servers" not in mcp_data:
                    mcp_data = {"mcpServers": mcp_data}
                yield from self._parse_servers_block(mcp_data, Scope.USER, None)
                return

        # Fallback: mcpServers in the plugin manifest (inline block, path to a
        # config file, or a list of either).
        manifest = self._load_file(install_dir / ".cursor-plugin" / "plugin.json")
        if not manifest:
            return
        inline = manifest.get("mcpServers")
        if inline is not None:
            yield from self._parse_servers_block(
                {"mcpServers": inline}, Scope.USER, None, base_dir=install_dir
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
            package = self._load_file(package_path)
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
            if (data := self._load_file(file)) and "folder" in data:
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
                metadata = self._load_file(file)
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
                tool = self._load_file(file)
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
                resource = self._load_file(file)
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
                prompt = self._load_file(file)
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
            timestamp=payload.timestamp,
        )

    def iter_history_events(
        self, ai_config: Optional[AIDiscovery]
    ) -> Iterator[MCPActivityRequest]:
        """Read past MCP tool calls from Cursor's chat database.

        Each chat message is a row keyed ``bubbleId:<composerId>:<bubbleId>`` in
        ``cursorDiskKV``.
        """
        db_path = get_user_home_dir() / CHAT_DB_RELATIVE_PATH
        if not db_path.is_file():
            return
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            logger.warning("Cursor: could not open chat database %s: %s", db_path, exc)
            return
        try:
            cwd_by_composer = self._load_composer_cwd_map(conn)
            model_by_composer: Dict[str, str] = {}
            rows = conn.execute(
                "SELECT substr(key, 10, 36) AS composer_id, value "
                "FROM cursorDiskKV "
                "WHERE key LIKE 'bubbleId:%' "
                "AND json_extract(value, '$.toolFormerData.tool') = ?",
                (MCP_TOOL_KIND,),
            )
            for composer_id, raw in rows:
                if composer_id not in cwd_by_composer:
                    cwd_by_composer[composer_id] = self._lookup_composer_cwd(
                        conn, composer_id
                    )
                if composer_id not in model_by_composer:
                    model_by_composer[composer_id] = self._lookup_composer_model(
                        conn, composer_id
                    )
                event = self._parse_bubble(
                    raw,
                    ai_config,
                    cwd_by_composer[composer_id],
                    model_by_composer[composer_id],
                )
                if event is not None:
                    yield event
        except sqlite3.Error as exc:
            logger.warning("Cursor: read failed on %s: %s", db_path, exc)
        finally:
            conn.close()

    def _parse_bubble(
        self,
        raw: str,
        ai_config: Optional[AIDiscovery],
        cwd: str,
        model: str,
    ) -> Optional[MCPActivityRequest]:
        """Turn a cursorDiskKV bubble row into an MCPActivityRequest, or None."""
        try:
            bubble = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(bubble, dict):
            return None

        tfd = bubble.get("toolFormerData") or {}
        if not isinstance(tfd, dict):
            return None

        # params is a stringified JSON object — the only field that reliably
        # carries the server name across the 3 toolFormerData.name conventions.
        try:
            params = json.loads(tfd.get("params") or "{}")
        except (json.JSONDecodeError, TypeError):
            return None
        tools = params.get("tools") if isinstance(params, dict) else None
        if not (isinstance(tools, list) and tools and isinstance(tools[0], dict)):
            return None
        tool_name = tools[0].get("name") or ""
        server_cfg_name = tools[0].get("serverName") or ""
        if not tool_name or not server_cfg_name:
            return None

        try:
            envelope = json.loads(tfd.get("rawArgs") or "{}")
        except (json.JSONDecodeError, TypeError):
            envelope = {}
        args = envelope.get("args") if isinstance(envelope, dict) else None
        tool_input = args if isinstance(args, dict) else {}

        try:
            ts = datetime.fromisoformat(
                str(bubble.get("createdAt", "")).replace("Z", "+00:00")
            )
        except ValueError:
            return None

        return MCPActivityRequest(
            user=self._user_or_default(ai_config),
            tool=tool_name,
            server=self._resolve_server_name(server_cfg_name, ai_config),
            agent=self.name,
            model=model,
            cwd=cwd,
            input=tool_input,
            timestamp=ts,
        )

    def _resolve_server_name(
        self, cfg_name: str, ai_config: Optional[AIDiscovery]
    ) -> str:
        """Look up the canonical server name; fall back to the configuration name."""
        if ai_config is None:
            return cfg_name
        for server in ai_config.servers:
            for configuration in server.configurations:
                if configuration.name == cfg_name:
                    return server.name
        return cfg_name

    def _load_composer_cwd_map(self, conn: sqlite3.Connection) -> Dict[str, str]:
        """Read ``composer.composerHeaders`` once and map composerId → workspace path."""
        try:
            row = conn.execute(
                "SELECT value FROM ItemTable WHERE key = 'composer.composerHeaders'"
            ).fetchone()
        except sqlite3.Error:
            return {}
        if not row or not row[0]:
            return {}
        try:
            headers = json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            return {}
        composers = headers.get("allComposers") if isinstance(headers, dict) else None
        if not isinstance(composers, list):
            return {}
        result: Dict[str, str] = {}
        for header in composers:
            if not isinstance(header, dict):
                continue
            composer_id = header.get("composerId")
            if not isinstance(composer_id, str):
                continue
            uri = (header.get("workspaceIdentifier") or {}).get("uri") or {}
            path = uri.get("path") if isinstance(uri, dict) else None
            if isinstance(path, str) and path:
                result[composer_id] = path
        return result

    def _lookup_composer_cwd(self, conn: sqlite3.Connection, composer_id: str) -> str:
        """Fallback: pull the workspace path from any user bubble in this composer."""
        row = conn.execute(
            "SELECT json_extract(value, '$.workspaceUris') FROM cursorDiskKV "
            "WHERE key LIKE ? "
            "AND json_extract(value, '$.type') = 1 "
            "AND json_extract(value, '$.workspaceUris') != '[]' "
            "LIMIT 1",
            (f"bubbleId:{composer_id}:%",),
        ).fetchone()
        if not row or not row[0]:
            return ""
        try:
            uris = json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            return ""
        if isinstance(uris, list) and uris and isinstance(uris[0], str):
            return uris[0].removeprefix("file://")
        return ""

    def _lookup_composer_model(self, conn: sqlite3.Connection, composer_id: str) -> str:
        """Return ``modelConfig.modelName`` for the composer (e.g. ``composer-2``)."""
        row = conn.execute(
            "SELECT json_extract(value, '$.modelConfig.modelName') "
            "FROM cursorDiskKV WHERE key = ?",
            (f"composerData:{composer_id}",),
        ).fetchone()
        return row[0] if row and isinstance(row[0], str) else ""


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
