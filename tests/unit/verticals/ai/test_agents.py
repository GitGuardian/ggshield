import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest
from pygitguardian.models import MCPToolInfo, UserInfo

from ggshield.core.dirs import get_user_home_dir
from ggshield.verticals.ai.agents.claude_code import Claude, _mangle_server_name
from ggshield.verticals.ai.agents.codex import Codex
from ggshield.verticals.ai.agents.copilot import Copilot
from ggshield.verticals.ai.agents.cursor import Cursor, _parse_tool_arguments
from ggshield.verticals.ai.agents.vscode import VSCode
from ggshield.verticals.ai.models import (
    Agent,
    AIDiscovery,
    EventType,
    HookPayload,
    MCPConfiguration,
    MCPServer,
    Scope,
    Tool,
    Transport,
)


def _user() -> UserInfo:
    return UserInfo(
        hostname="host", username="user", machine_id="mid", user_email="u@e.com"
    )


def _cfg(
    name: str = "srv",
    agent: str = "cursor",
    scope: Scope = Scope.USER,
    project: Optional[Path] = None,
) -> MCPConfiguration:
    return MCPConfiguration(
        name=name,
        agent=agent,
        scope=scope,
        transport=Transport.STDIO,
        project=str(project) if project else None,
    )


def _ai_discovery(servers: Optional[List[MCPServer]] = None) -> AIDiscovery:
    return AIDiscovery(user=_user(), servers=servers or [], discovery_duration=0.1)


def _payload(
    agent: Agent, raw: Optional[Dict[str, Any]] = None, tool: Tool = Tool.MCP
) -> HookPayload:
    return HookPayload(
        event_type=EventType.PRE_TOOL_USE,
        tool=tool,
        content="",
        identifier="",
        agent=agent,
        raw=raw or {},
    )


# ===========================================================================
# Cursor
# ===========================================================================


class TestCursorDiscoverCapabilities:
    def _setup_mcps_folder(
        self, tmp_path: Path, project_path: Path, server_name: str
    ) -> Path:
        """Build a Cursor-style mcps/<server>/ folder layout and return the agent."""
        mangled = project_path.as_posix().replace("/", "-").lstrip("-")
        mcps_root = tmp_path / ".cursor" / "projects" / mangled / "mcps"
        server_dir = mcps_root / f"user-{server_name}"
        server_dir.mkdir(parents=True, exist_ok=True)
        # SERVER_METADATA.json
        (server_dir / "SERVER_METADATA.json").write_text(
            json.dumps({"serverName": server_name})
        )
        return server_dir

    def test_populates_tools_resources_prompts(self, tmp_path: Path):
        project = Path("/home/user/project")
        server_dir = self._setup_mcps_folder(tmp_path, project, "my-mcp")

        (server_dir / "tools").mkdir()
        (server_dir / "tools" / "t1.json").write_text(
            json.dumps({"name": "do_thing", "description": "Does a thing"})
        )
        (server_dir / "resources").mkdir()
        (server_dir / "resources" / "r1.json").write_text(
            json.dumps({"uri": "file:///data", "name": "data"})
        )
        (server_dir / "prompts").mkdir()
        (server_dir / "prompts" / "p1.json").write_text(
            json.dumps({"name": "greeting", "description": "Says hi"})
        )

        cursor = Cursor()
        cfg = _cfg(name="my-mcp", agent="cursor", project=project)
        server = MCPServer(name="my-mcp", configurations=[cfg])

        with patch.object(
            type(cursor),
            "config_folder",
            new_callable=lambda: property(lambda self: tmp_path / ".cursor"),
        ):
            result = cursor.discover_capabilities(server)

        assert result is True
        assert len(server.tools) == 1
        assert server.tools[0].name == "do_thing"
        assert len(server.resources) == 1
        assert server.resources[0].uri == "file:///data"
        assert len(server.prompts) == 1
        assert server.prompts[0].name == "greeting"

    def test_status_md_present_returns_false(self, tmp_path: Path):
        project = Path("/home/user/project")
        server_dir = self._setup_mcps_folder(tmp_path, project, "my-mcp")
        (server_dir / "STATUS.md").write_text("disconnected")
        (server_dir / "tools").mkdir()
        (server_dir / "tools" / "t1.json").write_text(json.dumps({"name": "t"}))

        cursor = Cursor()
        cfg = _cfg(name="my-mcp", agent="cursor", project=project)
        server = MCPServer(name="my-mcp", configurations=[cfg])

        with patch.object(
            type(cursor),
            "config_folder",
            new_callable=lambda: property(lambda self: tmp_path / ".cursor"),
        ):
            result = cursor.discover_capabilities(server)

        assert result is False
        assert len(server.tools) == 0

    def test_no_matching_metadata_returns_false(self, tmp_path: Path):
        project = Path("/home/user/project")
        self._setup_mcps_folder(tmp_path, project, "other-server")

        cursor = Cursor()
        cfg = _cfg(name="my-mcp", agent="cursor", project=project)
        server = MCPServer(name="my-mcp", configurations=[cfg])

        with patch.object(
            type(cursor),
            "config_folder",
            new_callable=lambda: property(lambda self: tmp_path / ".cursor"),
        ):
            result = cursor.discover_capabilities(server)

        assert result is False

    def test_non_cursor_configuration_skipped(self):
        cursor = Cursor()
        cfg = _cfg(name="srv", agent="claude-code", project=Path("/proj"))
        server = MCPServer(name="srv", configurations=[cfg])
        assert cursor.discover_capabilities(server) is False

    def test_extension_prefixed_metadata_matches_short_cfg_name(self, tmp_path: Path):
        """An extension-provided server (serverName "extension-my-server") must match cfg "my-server"."""
        project = Path("/home/user/project")
        mangled = project.as_posix().replace("/", "-").lstrip("-")
        mcps_root = tmp_path / ".cursor" / "projects" / mangled / "mcps"
        server_dir = mcps_root / "extension-my-server"
        server_dir.mkdir(parents=True)
        (server_dir / "SERVER_METADATA.json").write_text(
            json.dumps({"serverName": "extension-my-server"})
        )
        (server_dir / "tools").mkdir()
        (server_dir / "tools" / "t1.json").write_text(json.dumps({"name": "find"}))

        cursor = Cursor()
        cfg = _cfg(name="my-server", agent="cursor", project=project)
        server = MCPServer(name="server", configurations=[cfg])

        with patch.object(
            type(cursor),
            "config_folder",
            new_callable=lambda: property(lambda self: tmp_path / ".cursor"),
        ):
            assert cursor.discover_capabilities(server) is True
        assert [t.name for t in server.tools] == ["find"]


class TestCursorGetPluginMcpConfigurations:
    def _patch(self, cursor: Cursor, config_folder: Path):
        return patch.object(
            type(cursor),
            "config_folder",
            new_callable=lambda: property(lambda self: config_folder),
        )

    def test_marketplace_plugin_with_mcp_json(self, tmp_path: Path):
        config_folder = tmp_path / ".cursor"
        install_dir = (
            config_folder / "plugins" / "cache" / "cursor-public" / "sentry" / "abc123"
        )
        install_dir.mkdir(parents=True)
        (install_dir / "mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"}
                    }
                }
            )
        )

        cursor = Cursor()
        with self._patch(cursor, config_folder):
            configs = list(cursor._get_plugin_mcp_configurations())

        assert len(configs) == 1
        assert configs[0].name == "sentry"
        assert configs[0].scope == Scope.USER
        assert configs[0].project is None
        assert configs[0].transport == Transport.HTTP
        assert configs[0].url == "https://mcp.sentry.dev/mcp"

    def test_local_plugin_with_dot_mcp_json_bare_layout(self, tmp_path: Path):
        config_folder = tmp_path / ".cursor"
        install_dir = config_folder / "plugins" / "local" / "my-plugin"
        install_dir.mkdir(parents=True)
        # Bare layout (no "mcpServers" wrapper)
        (install_dir / ".mcp.json").write_text(
            json.dumps({"my-srv": {"command": "node", "args": ["index.js"]}})
        )

        cursor = Cursor()
        with self._patch(cursor, config_folder):
            configs = list(cursor._get_plugin_mcp_configurations())

        assert len(configs) == 1
        assert configs[0].name == "my-srv"
        assert configs[0].transport == Transport.STDIO
        assert configs[0].command == "node"

    def test_inline_mcp_servers_in_manifest(self, tmp_path: Path):
        config_folder = tmp_path / ".cursor"
        install_dir = config_folder / "plugins" / "cache" / "owner" / "inline" / "v1"
        install_dir.mkdir(parents=True)
        (install_dir / ".cursor-plugin").mkdir()
        (install_dir / ".cursor-plugin" / "plugin.json").write_text(
            json.dumps(
                {
                    "name": "inline",
                    "mcpServers": {
                        "inline-srv": {
                            "url": "https://example.com/mcp",
                            "transport": "sse",
                        }
                    },
                }
            )
        )

        cursor = Cursor()
        with self._patch(cursor, config_folder):
            configs = list(cursor._get_plugin_mcp_configurations())

        assert len(configs) == 1
        assert configs[0].name == "inline-srv"
        assert configs[0].transport == Transport.SSE
        assert configs[0].url == "https://example.com/mcp"

    def test_manifest_string_path_with_custom_filename(self, tmp_path: Path):
        # Real-world case (datadog-labs/cursor-plugin): the manifest points to
        # a custom-named config file at the plugin root.
        config_folder = tmp_path / ".cursor"
        install_dir = config_folder / "plugins" / "cache" / "owner" / "dd" / "v1"
        install_dir.mkdir(parents=True)
        (install_dir / ".cursor-plugin").mkdir()
        (install_dir / ".cursor-plugin" / "plugin.json").write_text(
            json.dumps({"name": "dd", "mcpServers": "./.dd_cursor_mcp.json"})
        )
        (install_dir / ".dd_cursor_mcp.json").write_text(
            json.dumps({"mcpServers": {"datadog": {"command": "npx"}}})
        )

        cursor = Cursor()
        with self._patch(cursor, config_folder):
            configs = list(cursor._get_plugin_mcp_configurations())

        assert len(configs) == 1
        assert configs[0].name == "datadog"
        assert configs[0].command == "npx"

    def test_manifest_array_of_path_and_inline(self, tmp_path: Path):
        config_folder = tmp_path / ".cursor"
        install_dir = config_folder / "plugins" / "local" / "mixed"
        install_dir.mkdir(parents=True)
        (install_dir / ".cursor-plugin").mkdir()
        (install_dir / ".cursor-plugin" / "plugin.json").write_text(
            json.dumps(
                {
                    "name": "mixed",
                    "mcpServers": [
                        "./mcp/remote.json",
                        {"inline-srv": {"command": "npx"}},
                    ],
                }
            )
        )
        (install_dir / "mcp").mkdir()
        (install_dir / "mcp" / "remote.json").write_text(
            json.dumps({"mcpServers": {"from-file": {"url": "https://e.com/mcp"}}})
        )

        cursor = Cursor()
        with self._patch(cursor, config_folder):
            configs = list(cursor._get_plugin_mcp_configurations())

        assert sorted(c.name for c in configs) == ["from-file", "inline-srv"]

    def test_plugin_without_mcp_servers_yields_nothing(self, tmp_path: Path):
        config_folder = tmp_path / ".cursor"
        install_dir = (
            config_folder / "plugins" / "cache" / "owner" / "skills-only" / "v1"
        )
        install_dir.mkdir(parents=True)
        (install_dir / ".cursor-plugin").mkdir()
        (install_dir / ".cursor-plugin" / "plugin.json").write_text(
            json.dumps({"name": "skills-only"})
        )

        cursor = Cursor()
        with self._patch(cursor, config_folder):
            configs = list(cursor._get_plugin_mcp_configurations())

        assert configs == []

    def test_missing_plugins_folder_yields_nothing(self, tmp_path: Path):
        cursor = Cursor()
        with self._patch(cursor, tmp_path / ".cursor"):
            configs = list(cursor._get_plugin_mcp_configurations())
        assert configs == []


class TestCursorGetExtensionMcpConfigurations:
    def _patch(self, cursor: Cursor, config_folder: Path):
        return patch.object(
            type(cursor),
            "config_folder",
            new_callable=lambda: property(lambda self: config_folder),
        )

    def _write_registry(self, config_folder: Path, entries: List[Dict[str, Any]]):
        ext_root = config_folder / "extensions"
        ext_root.mkdir(parents=True, exist_ok=True)
        (ext_root / "extensions.json").write_text(json.dumps(entries))

    def test_extension_with_mcp_provider_yields_config(self, tmp_path: Path):
        config_folder = tmp_path / ".cursor"
        ext_dir = config_folder / "extensions" / "eamodio.gitlens-17.12.2-universal"
        ext_dir.mkdir(parents=True)
        (ext_dir / "package.json").write_text(
            json.dumps(
                {
                    "contributes": {
                        "mcpServerDefinitionProviders": [
                            {
                                "id": "gitlens.gkMcpProvider",
                                "label": "GitKraken (bundled with GitLens)",
                            }
                        ]
                    }
                }
            )
        )
        self._write_registry(
            config_folder,
            [{"relativeLocation": "eamodio.gitlens-17.12.2-universal"}],
        )

        cursor = Cursor()
        with self._patch(cursor, config_folder):
            configs = list(cursor._get_extension_mcp_configurations())

        assert len(configs) == 1
        assert configs[0].name == "GitKraken"
        assert configs[0].scope == Scope.USER
        assert configs[0].project is None
        assert configs[0].transport == Transport.STDIO

    def test_extension_without_mcp_provider_skipped(self, tmp_path: Path):
        config_folder = tmp_path / ".cursor"
        ext_dir = config_folder / "extensions" / "pub.plain-1.0.0"
        ext_dir.mkdir(parents=True)
        (ext_dir / "package.json").write_text(
            json.dumps({"contributes": {"commands": [{"command": "foo"}]}})
        )
        self._write_registry(config_folder, [{"relativeLocation": "pub.plain-1.0.0"}])

        cursor = Cursor()
        with self._patch(cursor, config_folder):
            configs = list(cursor._get_extension_mcp_configurations())

        assert configs == []

    def test_multiple_providers_yield_one_each(self, tmp_path: Path):
        config_folder = tmp_path / ".cursor"
        ext_dir = config_folder / "extensions" / "pub.multi-1.0.0"
        ext_dir.mkdir(parents=True)
        (ext_dir / "package.json").write_text(
            json.dumps(
                {
                    "contributes": {
                        "mcpServerDefinitionProviders": [
                            {"id": "p1", "label": "Provider 1"},
                            {"id": "p2", "label": "Provider 2"},
                        ]
                    }
                }
            )
        )
        self._write_registry(config_folder, [{"relativeLocation": "pub.multi-1.0.0"}])

        cursor = Cursor()
        with self._patch(cursor, config_folder):
            configs = list(cursor._get_extension_mcp_configurations())

        assert [c.name for c in configs] == ["Provider 1", "Provider 2"]

    def test_missing_registry_yields_nothing(self, tmp_path: Path):
        cursor = Cursor()
        with self._patch(cursor, tmp_path / ".cursor"):
            configs = list(cursor._get_extension_mcp_configurations())
        assert configs == []


class TestCursorDiscoverProjectDirectories:
    def test_valid_workspace_json_yields_path(self, tmp_path: Path):
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        ws_storage = (
            tmp_path / ".config" / "Cursor" / "User" / "workspaceStorage" / "abc"
        )
        ws_storage.mkdir(parents=True)
        (ws_storage / "workspace.json").write_text(
            json.dumps({"folder": f"file://{project_dir}"})
        )

        cursor = Cursor()
        with patch.object(
            type(cursor),
            "config_folder",
            new_callable=lambda: property(
                lambda self: tmp_path / ".config" / "Cursor" / "User"
            ),
        ):
            with patch(
                "ggshield.verticals.ai.agents.cursor.get_user_home_dir",
                return_value=tmp_path,
            ):
                dirs = list(cursor.discover_project_directories())

        assert project_dir.resolve() in dirs

    def test_missing_folder_key_skipped(self, tmp_path: Path):
        ws_storage = (
            tmp_path / ".config" / "Cursor" / "User" / "workspaceStorage" / "abc"
        )
        ws_storage.mkdir(parents=True)
        (ws_storage / "workspace.json").write_text(json.dumps({"other": "val"}))

        cursor = Cursor()
        with patch.object(
            type(cursor),
            "config_folder",
            new_callable=lambda: property(
                lambda self: tmp_path / ".config" / "Cursor" / "User"
            ),
        ):
            with patch(
                "ggshield.verticals.ai.agents.cursor.get_user_home_dir",
                return_value=tmp_path,
            ):
                dirs = list(cursor.discover_project_directories())

        assert dirs == []


class TestCursorParseMcpActivity:
    def test_strips_mcp_prefix_and_maps_server(self):
        cursor = Cursor()
        tool_info = MCPToolInfo(name="run_query")
        server = MCPServer(
            name="my-db-server",
            tools=[tool_info],
            configurations=[_cfg(name="db", agent="cursor")],
        )
        discovery = _ai_discovery(servers=[server])
        payload = _payload(
            cursor,
            raw={
                "tool_name": "MCP:run_query",
                "model": "gpt-4",
                "workspace_roots": ["/home/user/proj"],
                "tool_input": {"sql": "SELECT 1"},
            },
        )

        req = cursor.parse_mcp_activity(payload, discovery)

        assert req.tool == "run_query"
        assert req.server == "my-db-server"
        assert req.model == "gpt-4"
        assert req.input == {"sql": "SELECT 1"}

    def test_unknown_tool_returns_empty_server(self):
        cursor = Cursor()
        discovery = _ai_discovery(servers=[])
        payload = _payload(cursor, raw={"tool_name": "MCP:unknown"})

        req = cursor.parse_mcp_activity(payload, discovery)

        assert req.tool == "unknown"
        assert req.server == ""


# ===========================================================================
# Claude Code
# ===========================================================================


class TestClaudeGetUserMcpConfigurations:
    def test_user_level_and_project_level_parsed(self, tmp_path: Path):
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        claude_json = {
            "mcpServers": {"global-srv": {"command": "npx", "args": ["-y", "mcp"]}},
            "projects": {
                str(project_dir): {
                    "mcpServers": {
                        "project-srv": {"command": "node", "args": ["index.js"]}
                    }
                }
            },
        }
        with patch(
            "ggshield.verticals.ai.agents.claude_code.get_user_home_dir",
            return_value=tmp_path,
        ):
            (tmp_path / ".claude.json").write_text(json.dumps(claude_json))
            claude = Claude()
            configs = list(claude._get_user_mcp_configurations())

        names = {c.name for c in configs}
        assert "global-srv" in names
        assert "project-srv" in names

    def test_missing_file_yields_nothing(self, tmp_path: Path):
        with patch(
            "ggshield.verticals.ai.agents.claude_code.get_user_home_dir",
            return_value=tmp_path,
        ):
            claude = Claude()
            configs = list(claude._get_user_mcp_configurations())
        assert configs == []


class TestClaudeGetPluginMcpConfigurations:
    def _setup(self, tmp_path: Path) -> Path:
        config_folder = tmp_path / ".claude"
        (config_folder / "plugins").mkdir(parents=True)
        return config_folder

    def _make_plugin(
        self,
        config_folder: Path,
        plugin_id: str,
        version: str = "1.0.0",
    ) -> Path:
        install_dir = (
            config_folder
            / "plugins"
            / "cache"
            / plugin_id.split("@")[1]
            / plugin_id.split("@")[0]
            / version
        )
        install_dir.mkdir(parents=True)
        (install_dir / ".claude-plugin").mkdir()
        (install_dir / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"name": plugin_id.split("@")[0]})
        )
        return install_dir

    def _patch(self, claude: Claude, config_folder: Path):
        return patch.object(
            type(claude),
            "config_folder",
            new_callable=lambda: property(lambda self: config_folder),
        )

    def test_user_scope_plugin_with_bare_mcp_json(self, tmp_path: Path):
        config_folder = self._setup(tmp_path)
        install_dir = self._make_plugin(config_folder, "context7@official")
        # Bare layout (just servers, no "mcpServers" wrapper)
        (install_dir / ".mcp.json").write_text(
            json.dumps({"context7": {"command": "npx", "args": ["-y", "ctx7"]}})
        )
        (config_folder / "plugins" / "installed_plugins.json").write_text(
            json.dumps(
                {
                    "version": 2,
                    "plugins": {
                        "context7@official": [
                            {
                                "scope": "user",
                                "installPath": str(install_dir),
                                "version": "1.0.0",
                            }
                        ]
                    },
                }
            )
        )

        claude = Claude()
        with self._patch(claude, config_folder):
            configs = list(claude._get_plugin_mcp_configurations())

        assert len(configs) == 1
        assert configs[0].name == "context7"
        assert configs[0].scope == Scope.USER
        assert configs[0].project is None
        assert configs[0].transport == Transport.STDIO
        assert configs[0].command == "npx"

    def test_project_scope_plugin_tied_to_project(self, tmp_path: Path):
        config_folder = self._setup(tmp_path)
        install_dir = self._make_plugin(config_folder, "shared@official")
        (install_dir / ".mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"shared-srv": {"command": "node", "args": ["s.js"]}}}
            )
        )
        project_path = get_user_home_dir() / "proj"
        (config_folder / "plugins" / "installed_plugins.json").write_text(
            json.dumps(
                {
                    "plugins": {
                        "shared@official": [
                            {
                                "scope": "project",
                                "projectPath": str(project_path),
                                "installPath": str(install_dir),
                                "version": "1.0.0",
                            }
                        ]
                    }
                }
            )
        )

        claude = Claude()
        with self._patch(claude, config_folder):
            configs = list(claude._get_plugin_mcp_configurations())

        assert len(configs) == 1
        assert configs[0].name == "shared-srv"
        assert configs[0].scope == Scope.PROJECT
        assert configs[0].project == str(project_path)

    def test_local_scope_plugin_marked_as_user_with_project(self, tmp_path: Path):
        config_folder = self._setup(tmp_path)
        install_dir = self._make_plugin(config_folder, "local@official")
        (install_dir / ".mcp.json").write_text(
            json.dumps({"local-srv": {"command": "node"}})
        )
        project_path = get_user_home_dir() / "proj"
        (config_folder / "plugins" / "installed_plugins.json").write_text(
            json.dumps(
                {
                    "plugins": {
                        "local@official": [
                            {
                                "scope": "local",
                                "projectPath": str(project_path),
                                "installPath": str(install_dir),
                            }
                        ]
                    }
                }
            )
        )

        claude = Claude()
        with self._patch(claude, config_folder):
            configs = list(claude._get_plugin_mcp_configurations())

        assert len(configs) == 1
        assert configs[0].scope == Scope.USER
        assert configs[0].project == str(project_path)

    def test_inline_mcp_servers_in_manifest(self, tmp_path: Path):
        config_folder = self._setup(tmp_path)
        install_dir = self._make_plugin(config_folder, "inline@official")
        (install_dir / ".claude-plugin" / "plugin.json").write_text(
            json.dumps(
                {
                    "name": "inline",
                    "mcpServers": {
                        "inline-srv": {
                            "url": "https://example.com/mcp",
                            "transport": "sse",
                        }
                    },
                }
            )
        )
        (config_folder / "plugins" / "installed_plugins.json").write_text(
            json.dumps(
                {
                    "plugins": {
                        "inline@official": [
                            {
                                "scope": "user",
                                "installPath": str(install_dir),
                            }
                        ]
                    }
                }
            )
        )

        claude = Claude()
        with self._patch(claude, config_folder):
            configs = list(claude._get_plugin_mcp_configurations())

        assert len(configs) == 1
        assert configs[0].name == "inline-srv"
        assert configs[0].transport == Transport.SSE
        assert configs[0].url == "https://example.com/mcp"

    def test_manifest_string_path_resolved_against_install_dir(self, tmp_path: Path):
        config_folder = self._setup(tmp_path)
        install_dir = self._make_plugin(config_folder, "pathy@official")
        (install_dir / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"name": "pathy", "mcpServers": "./custom-mcp.json"})
        )
        (install_dir / "custom-mcp.json").write_text(
            json.dumps({"mcpServers": {"pathy-srv": {"command": "node"}}})
        )
        (config_folder / "plugins" / "installed_plugins.json").write_text(
            json.dumps(
                {
                    "plugins": {
                        "pathy@official": [
                            {"scope": "user", "installPath": str(install_dir)}
                        ]
                    }
                }
            )
        )

        claude = Claude()
        with self._patch(claude, config_folder):
            configs = list(claude._get_plugin_mcp_configurations())

        assert len(configs) == 1
        assert configs[0].name == "pathy-srv"
        assert configs[0].command == "node"

    def test_missing_install_dir_skipped(self, tmp_path: Path):
        config_folder = self._setup(tmp_path)
        (config_folder / "plugins" / "installed_plugins.json").write_text(
            json.dumps(
                {
                    "plugins": {
                        "ghost@official": [
                            {
                                "scope": "user",
                                "installPath": "/does/not/exist",
                            }
                        ]
                    }
                }
            )
        )

        claude = Claude()
        with self._patch(claude, config_folder):
            configs = list(claude._get_plugin_mcp_configurations())

        assert configs == []

    def test_plugin_without_mcp_servers_yields_nothing(self, tmp_path: Path):
        config_folder = self._setup(tmp_path)
        install_dir = self._make_plugin(config_folder, "skills@official")
        (config_folder / "plugins" / "installed_plugins.json").write_text(
            json.dumps(
                {
                    "plugins": {
                        "skills@official": [
                            {
                                "scope": "user",
                                "installPath": str(install_dir),
                            }
                        ]
                    }
                }
            )
        )

        claude = Claude()
        with self._patch(claude, config_folder):
            configs = list(claude._get_plugin_mcp_configurations())

        assert configs == []

    def test_missing_installed_plugins_file_yields_nothing(self, tmp_path: Path):
        config_folder = self._setup(tmp_path)

        claude = Claude()
        with self._patch(claude, config_folder):
            configs = list(claude._get_plugin_mcp_configurations())

        assert configs == []


class TestClaudeGetClaudeAiMcpConfigurations:
    def test_dedup_across_two_sources(self, tmp_path: Path):
        config_folder = tmp_path / ".claude"
        config_folder.mkdir()
        (tmp_path / ".claude.json").write_text(
            json.dumps(
                {
                    "claudeAiMcpEverConnected": [
                        "claude.ai Notion",
                        "claude.ai Granola",
                    ]
                }
            )
        )
        (config_folder / "mcp-needs-auth-cache.json").write_text(
            json.dumps(
                {
                    "claude.ai Notion": {"timestamp": 1, "id": "mcpsrv_a"},
                    "claude.ai Slack": {"timestamp": 2, "id": "mcpsrv_b"},
                }
            )
        )

        claude = Claude()
        with (
            patch(
                "ggshield.verticals.ai.agents.claude_code.get_user_home_dir",
                return_value=tmp_path,
            ),
            patch.object(
                type(claude),
                "config_folder",
                new_callable=lambda: property(lambda self: config_folder),
            ),
        ):
            configs = list(claude._get_claudeai_mcp_configurations())

        names = {c.name for c in configs}
        assert names == {"Notion", "Granola", "Slack"}
        for cfg in configs:
            assert cfg.scope == Scope.USER
            assert cfg.transport == Transport.HTTP
            assert cfg.project is None

    def test_no_sources_yields_nothing(self, tmp_path: Path):
        config_folder = tmp_path / ".claude"
        config_folder.mkdir()

        claude = Claude()
        with (
            patch(
                "ggshield.verticals.ai.agents.claude_code.get_user_home_dir",
                return_value=tmp_path,
            ),
            patch.object(
                type(claude),
                "config_folder",
                new_callable=lambda: property(lambda self: config_folder),
            ),
        ):
            configs = list(claude._get_claudeai_mcp_configurations())

        assert configs == []


class TestClaudeDiscoverProjectDirectories:
    def test_yields_existing_directories(self, tmp_path: Path):
        project = tmp_path / "proj"
        project.mkdir()
        history = tmp_path / ".claude" / "history.jsonl"
        history.parent.mkdir(parents=True)
        history.write_text(json.dumps({"project": str(project)}) + "\n")

        claude = Claude()
        with patch.object(
            type(claude),
            "config_folder",
            new_callable=lambda: property(lambda self: tmp_path / ".claude"),
        ):
            dirs = list(claude.discover_project_directories())

        assert project.resolve() in dirs

    def test_skips_nonexistent_directories(self, tmp_path: Path):
        history = tmp_path / ".claude" / "history.jsonl"
        history.parent.mkdir(parents=True)
        history.write_text(
            json.dumps({"project": str(tmp_path / "nonexistent")}) + "\n"
        )

        claude = Claude()
        with patch.object(
            type(claude),
            "config_folder",
            new_callable=lambda: property(lambda self: tmp_path / ".claude"),
        ):
            dirs = list(claude.discover_project_directories())

        assert dirs == []


class TestClaudeParseMcpActivity:
    def test_parses_mcp_double_underscore_format(self):
        claude = Claude()
        cfg = _cfg(name="my.server", agent="claude-code")
        server = MCPServer(
            name="my.server", configurations=[cfg], tools=[MCPToolInfo(name="run")]
        )
        discovery = _ai_discovery(servers=[server])
        # Claude mangles "my.server" → "my_server" in the tool name
        payload = _payload(
            claude,
            raw={"tool_name": "mcp__my_server__run", "cwd": "/tmp", "tool_input": {}},
        )

        req = claude.parse_mcp_activity(payload, discovery)

        assert req.tool == "run"
        assert req.server == "my.server"

    def test_server_with_double_underscore_handled(self):
        claude = Claude()
        discovery = _ai_discovery(servers=[])
        payload = _payload(
            claude,
            raw={
                "tool_name": "mcp__a__b__tool_name",
                "cwd": "/tmp",
                "tool_input": {},
            },
        )

        req = claude.parse_mcp_activity(payload, discovery)

        assert req.tool == "tool_name"
        assert req.server == "a__b"  # falls back to mangled name

    def test_fallback_to_mangled_name(self):
        claude = Claude()
        discovery = _ai_discovery(servers=[])
        payload = _payload(
            claude,
            raw={"tool_name": "mcp__unknown__do_it", "cwd": "/tmp", "tool_input": {}},
        )

        req = claude.parse_mcp_activity(payload, discovery)

        assert req.server == "unknown"


# ---------------------------------------------------------------------------
# _mangle_server_name
# ---------------------------------------------------------------------------


class TestMangleServerName:
    @pytest.mark.parametrize(
        "name, expected",
        [
            pytest.param("my-seRver-123", "my-seRver-123", id="alphanumeric_dashes"),
            pytest.param(
                "my.server/v2 alpha", "my_server_v2_alpha", id="special_chars"
            ),
            pytest.param("simple", "simple", id="plain_alpha"),
            pytest.param("a@b#c", "a_b_c", id="symbols"),
        ],
    )
    def test_mangle_server_name(self, name: str, expected: str):
        assert _mangle_server_name(name) == expected


# ===========================================================================
# Codex
# ===========================================================================


class TestCodex:
    def test_config_folder(self, tmp_path: Path):
        codex = Codex()

        with patch("ggshield.verticals.ai.agents.codex.get_user_home_dir") as mock_home:
            mock_home.return_value = tmp_path
            assert codex.config_folder == tmp_path / ".codex"

    def test_project_mcp_file(self):
        assert Codex().project_mcp_file(Path("/tmp/project")) == (
            Path("/tmp/project") / ".codex" / "config.toml"
        )

    def test_parse_mcp_activity(self):
        codex = Codex()
        cfg = _cfg(name="my.server", agent="codex")
        server = MCPServer(
            name="my.server", configurations=[cfg], tools=[MCPToolInfo(name="run")]
        )
        discovery = _ai_discovery(servers=[server])
        payload = _payload(
            codex,
            raw={
                "tool_name": "mcp__my_server__run",
                "cwd": "/tmp/project",
                "model": "gpt-5.4",
                "tool_input": {"query": "hello"},
            },
        )

        req = codex.parse_mcp_activity(payload, discovery)

        assert req.user == discovery.user
        assert req.tool == "run"
        assert req.server == "my.server"
        assert req.agent == "codex"
        assert req.model == "gpt-5.4"
        assert req.cwd == "/tmp/project"
        assert req.input == {"query": "hello"}


class TestCodexDiscoverProjectDirectories:
    def _patch(self, codex: Codex, config_folder: Path):
        return patch.object(
            type(codex),
            "config_folder",
            new_callable=lambda: property(lambda self: config_folder),
        )

    def test_yields_project_keys_from_config_toml(self, tmp_path: Path):
        config_folder = tmp_path / ".codex"
        config_folder.mkdir()
        (config_folder / "config.toml").write_text(
            '[projects]\n"/home/user/project-a" = {}\n"/home/user/project-b" = {}\n'
        )

        codex = Codex()
        with self._patch(codex, config_folder):
            dirs = list(codex.discover_project_directories())

        assert Path("/home/user/project-a") in dirs
        assert Path("/home/user/project-b") in dirs

    def test_missing_config_toml_yields_nothing(self, tmp_path: Path):
        config_folder = tmp_path / ".codex"
        config_folder.mkdir()

        codex = Codex()
        with self._patch(codex, config_folder):
            dirs = list(codex.discover_project_directories())

        assert dirs == []

    def test_config_toml_without_projects_key_yields_nothing(self, tmp_path: Path):
        config_folder = tmp_path / ".codex"
        config_folder.mkdir()
        (config_folder / "config.toml").write_text('model = "gpt-5"\n')

        codex = Codex()
        with self._patch(codex, config_folder):
            dirs = list(codex.discover_project_directories())

        assert dirs == []


class TestCodexGetProjectMcpConfigurations:
    def _patch(self, codex: Codex, config_folder: Path):
        return patch.object(
            type(codex),
            "config_folder",
            new_callable=lambda: property(lambda self: config_folder),
        )

    def test_includes_standard_project_config(self, tmp_path: Path):
        """The parent's project-level config (.codex/config.toml) is included."""
        project = tmp_path / "myproject"
        project.mkdir()
        codex_dir = project / ".codex"
        codex_dir.mkdir()
        (codex_dir / "config.toml").write_text(
            '[mcpServers.proj-srv]\ncommand = "node"\nargs = ["index.js"]\n'
        )

        codex = Codex()
        configs = list(codex._get_project_mcp_configurations(project))

        assert len(configs) == 1
        assert configs[0].name == "proj-srv"
        assert configs[0].scope == Scope.PROJECT

    def test_includes_local_codex_plugin(self, tmp_path: Path):
        """A .codex-plugin directory with .mcp.json at project root is discovered."""
        project = tmp_path / "myproject"
        plugin_dir = project / ".codex-plugin"
        plugin_dir.mkdir(parents=True)
        (project / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "plugin-srv": {"command": "npx", "args": ["-y", "srv"]}
                    }
                }
            )
        )

        codex = Codex()
        configs = list(codex._get_project_mcp_configurations(project))

        plugin_configs = [c for c in configs if c.name == "plugin-srv"]
        assert len(plugin_configs) == 1
        assert plugin_configs[0].scope == Scope.PROJECT
        assert plugin_configs[0].project == str(project)
        assert plugin_configs[0].transport == Transport.STDIO
        assert plugin_configs[0].command == "npx"

    def test_no_plugin_dir_yields_only_standard(self, tmp_path: Path):
        """When .codex-plugin doesn't exist, only standard config is considered."""
        project = tmp_path / "myproject"
        project.mkdir()

        codex = Codex()
        configs = list(codex._get_project_mcp_configurations(project))

        assert configs == []


class TestCodexGetUserMcpConfigurations:
    def _patch(self, codex: Codex, config_folder: Path):
        return patch.object(
            type(codex),
            "config_folder",
            new_callable=lambda: property(lambda self: config_folder),
        )

    def test_includes_standard_user_config(self, tmp_path: Path):
        config_folder = tmp_path / ".codex"
        config_folder.mkdir()
        (config_folder / "config.toml").write_text(
            '[mcpServers.global-srv]\ncommand = "npx"\nargs = ["-y", "mcp"]\n'
        )

        codex = Codex()
        with self._patch(codex, config_folder):
            configs = list(codex._get_user_mcp_configurations())

        assert any(c.name == "global-srv" for c in configs)

    def test_includes_marketplace_plugins(self, tmp_path: Path):
        config_folder = tmp_path / ".codex"
        install_dir = (
            config_folder / "plugins" / "cache" / "codex-public" / "sentry" / "abc123"
        )
        install_dir.mkdir(parents=True)
        (install_dir / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"}
                    }
                }
            )
        )

        codex = Codex()
        with self._patch(codex, config_folder):
            configs = list(codex._get_user_mcp_configurations())

        plugin_configs = [c for c in configs if c.name == "sentry"]
        assert len(plugin_configs) == 1
        assert plugin_configs[0].scope == Scope.USER
        assert plugin_configs[0].project is None
        assert plugin_configs[0].transport == Transport.HTTP
        assert plugin_configs[0].url == "https://mcp.sentry.dev/mcp"

    def test_missing_plugins_folder_yields_only_standard(self, tmp_path: Path):
        config_folder = tmp_path / ".codex"
        config_folder.mkdir()

        codex = Codex()
        with self._patch(codex, config_folder):
            configs = list(codex._get_user_mcp_configurations())

        assert configs == []


class TestCodexGetCodexPluginMcpConfigurations:
    def test_missing_dir_yields_nothing(self, tmp_path: Path):
        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(
                tmp_path / "nonexistent", Scope.USER
            )
        )
        assert configs == []

    def test_dir_without_mcp_json_yields_nothing(self, tmp_path: Path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()

        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(plugin_dir, Scope.USER)
        )
        assert configs == []

    def test_user_scope_sets_no_project(self, tmp_path: Path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / ".mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"my-srv": {"command": "node", "args": ["s.js"]}}}
            )
        )

        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(plugin_dir, Scope.USER)
        )

        assert len(configs) == 1
        assert configs[0].name == "my-srv"
        assert configs[0].scope == Scope.USER
        assert configs[0].project is None
        assert configs[0].transport == Transport.STDIO

    def test_project_scope_sets_project_to_plugin_dir(self, tmp_path: Path):
        plugin_dir = tmp_path / "myproject" / ".codex-plugin"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / ".mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"local-srv": {"command": "python", "args": ["srv.py"]}}}
            )
        )

        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(plugin_dir, Scope.PROJECT)
        )

        assert len(configs) == 1
        assert configs[0].name == "local-srv"
        assert configs[0].scope == Scope.PROJECT
        assert configs[0].project == str(plugin_dir)

    def test_http_transport_detected(self, tmp_path: Path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"remote": {"url": "https://example.com/mcp"}}})
        )

        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(plugin_dir, Scope.USER)
        )

        assert len(configs) == 1
        assert configs[0].transport == Transport.HTTP
        assert configs[0].url == "https://example.com/mcp"

    def test_bare_layout_in_mcp_json(self, tmp_path: Path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        # Bare layout (no "mcpServers" wrapper)
        (plugin_dir / ".mcp.json").write_text(
            json.dumps({"my-srv": {"command": "node", "args": ["index.js"]}})
        )

        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(plugin_dir, Scope.USER)
        )

        assert len(configs) == 1
        assert configs[0].name == "my-srv"
        assert configs[0].transport == Transport.STDIO
        assert configs[0].command == "node"

    def test_inline_mcp_servers_in_manifest(self, tmp_path: Path):
        plugin_dir = tmp_path / "plugin"
        manifest_dir = plugin_dir / ".codex-plugin"
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "package.json").write_text(
            json.dumps(
                {
                    "interface": {"displayName": "Inline Plugin"},
                    "mcpServers": {
                        "inline-srv": {
                            "url": "https://example.com/mcp",
                            "transport": "sse",
                        }
                    },
                }
            )
        )

        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(plugin_dir, Scope.USER)
        )

        assert len(configs) == 1
        assert configs[0].name == "inline-srv"
        assert configs[0].transport == Transport.SSE
        assert configs[0].url == "https://example.com/mcp"
        assert configs[0].display_name == "Inline Plugin"

    def test_manifest_string_path_with_custom_filename(self, tmp_path: Path):
        plugin_dir = tmp_path / "plugin"
        manifest_dir = plugin_dir / ".codex-plugin"
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "package.json").write_text(
            json.dumps({"mcpServers": "./custom_mcp.json"})
        )
        (plugin_dir / "custom_mcp.json").write_text(
            json.dumps({"mcpServers": {"custom": {"command": "npx"}}})
        )

        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(plugin_dir, Scope.USER)
        )

        assert len(configs) == 1
        assert configs[0].name == "custom"
        assert configs[0].command == "npx"

    def test_manifest_string_path_to_bare_layout_file(self, tmp_path: Path):
        plugin_dir = tmp_path / "plugin"
        manifest_dir = plugin_dir / ".codex-plugin"
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "package.json").write_text(
            json.dumps({"mcpServers": "./custom_mcp.json"})
        )
        # Bare layout (no "mcpServers" wrapper) in the referenced file
        (plugin_dir / "custom_mcp.json").write_text(
            json.dumps({"bare-srv": {"command": "python", "args": ["srv.py"]}})
        )

        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(plugin_dir, Scope.USER)
        )

        assert len(configs) == 1
        assert configs[0].name == "bare-srv"
        assert configs[0].command == "python"

    def test_manifest_array_of_path_and_inline(self, tmp_path: Path):
        plugin_dir = tmp_path / "plugin"
        manifest_dir = plugin_dir / ".codex-plugin"
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "package.json").write_text(
            json.dumps(
                {
                    "mcpServers": [
                        "./mcp/remote.json",
                        {"inline-srv": {"command": "npx"}},
                    ],
                }
            )
        )
        (plugin_dir / "mcp").mkdir()
        (plugin_dir / "mcp" / "remote.json").write_text(
            json.dumps({"mcpServers": {"from-file": {"url": "https://e.com/mcp"}}})
        )

        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(plugin_dir, Scope.USER)
        )

        assert sorted(c.name for c in configs) == ["from-file", "inline-srv"]

    def test_manifest_without_mcp_servers_falls_back_to_mcp_json(self, tmp_path: Path):
        plugin_dir = tmp_path / "plugin"
        manifest_dir = plugin_dir / ".codex-plugin"
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "package.json").write_text(
            json.dumps({"interface": {"displayName": "Skills Plugin"}})
        )
        (plugin_dir / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"default-srv": {"command": "node"}}})
        )

        codex = Codex()
        configs = list(
            codex._get_codex_plugin_mcp_configurations(plugin_dir, Scope.USER)
        )

        assert len(configs) == 1
        assert configs[0].name == "default-srv"
        assert configs[0].display_name == "Skills Plugin"


# ===========================================================================
# VSCode
# ===========================================================================


class TestVSCodeParseMcpActivity:
    @pytest.mark.parametrize(
        "tool_name, config_name, expected_tool",
        [
            pytest.param("mcp_myserver_mytool", "myserver", "mytool", id="simple"),
            pytest.param(
                "mcp_server_tool_name_extra",
                "server",
                "tool_name_extra",
                id="multiple_underscores_in_tool",
            ),
            pytest.param(
                "mcp_server_name_tool_name",
                "server_name",
                "tool_name",
                id="multiple_underscores_in_tool_and_config",
            ),
            pytest.param(
                "mcp_foo_b_r__tool_name",
                "Foo (Bâr)",
                "tool_name",
                id="special_chars_in_config_name",
            ),
            pytest.param(
                "mcp_verylongserve_tool_name",
                "VeryLongServerName",
                "tool_name",
                id="long_server_name",
            ),
        ],
    )
    def test_identify_server_tool_split(
        self, tool_name: str, config_name: str, expected_tool: str
    ):
        """Test that the server and tool names are split correctly."""
        vscode = VSCode()
        cfg = _cfg(name=config_name, agent="vscode")
        server = MCPServer(name="identified", configurations=[cfg])
        discovery = _ai_discovery(servers=[server])
        payload = _payload(
            vscode,
            raw={"tool_name": tool_name, "cwd": "/tmp", "tool_input": {}},
        )

        req = vscode.parse_mcp_activity(payload, discovery)

        assert req.tool == expected_tool
        assert req.server == "identified"

    def test_identify_from_multiple_servers(self):
        """Test that the server and tool names are split correctly."""
        vscode = VSCode()
        cfg1 = _cfg(name="foo", agent="vscode")
        cfg2 = _cfg(name="foo_bar", agent="cursor")
        server = MCPServer(name="server1", configurations=[cfg1])
        server2 = MCPServer(name="server2", configurations=[cfg2])
        discovery = _ai_discovery(servers=[server, server2])
        payload = _payload(
            vscode,
            raw={"tool_name": "mcp_foo_bar_tool_name", "cwd": "/tmp", "tool_input": {}},
        )

        req = vscode.parse_mcp_activity(payload, discovery)

        assert req.tool == "tool_name"
        assert req.server == "server2"

    def test_unknown_server_falls_back_to_cfg_name(self):
        vscode = VSCode()
        discovery = _ai_discovery(servers=[])
        payload = _payload(
            vscode,
            raw={"tool_name": "mcp_unknown_tool_name", "cwd": "/tmp", "tool_input": {}},
        )

        req = vscode.parse_mcp_activity(payload, discovery)

        assert req.server == "unknown"
        assert req.tool == "tool_name"


# ===========================================================================
# Copilot
# ===========================================================================


class TestCopilotParseMcpActivity:
    @pytest.mark.parametrize(
        "tool_name, config_name, expected_tool",
        [
            pytest.param("myserver-mytool", "myserver", "mytool", id="simple"),
            pytest.param(
                "server-tool_name",
                "server",
                "tool_name",
                id="underscores_in_tool",
            ),
            pytest.param(
                "server-name-tool-name",
                "server-name",
                "tool-name",
                id="multiple_dashes_in_tool_and_config",
            ),
            pytest.param(
                "xn--Foob_ar_s--Prod--twb-tool_name",
                "Foob_ar_ös (Prod)",
                "tool_name",
                id="special_chars_in_config_name",
            ),
            pytest.param(
                "xn--Fo-bar_bz--Spam---Toto-----T-ta------Tutu-42-2vd5e46b-tool_name",
                "Fôo-bar_bäz (Spam) [Toto]   <Tâ/ta> -  (Tutu 42",
                "tool_name",
                id="special_chars_in_config_name_2",
            ),
            pytest.param(
                "FooVeryLong-NameWithCapsInCamelCase-tool_name",
                "FooVeryLong-NameWithCapsInCamelCase",
                "tool_name",
                id="long_server_name",
            ),
            pytest.param(
                "Server-MCP-With-Spaces-tool_name",
                "Server MCP With Spaces",
                "tool_name",
                id="server_name_with_spaces",
            ),
        ],
    )
    def test_identify_server_tool_split(
        self, tool_name: str, config_name: str, expected_tool: str
    ):
        """Test that the server and tool names are split correctly."""
        copilot = Copilot()
        cfg = _cfg(name=config_name, agent="copilot")
        server = MCPServer(name="identified", configurations=[cfg])
        discovery = _ai_discovery(servers=[server])
        payload = _payload(
            copilot,
            raw={"tool_name": tool_name, "cwd": "/tmp", "tool_input": {}},
        )

        req = copilot.parse_mcp_activity(payload, discovery)

        assert req.tool == expected_tool
        assert req.server == "identified"

    def test_identify_from_multiple_servers(self):
        """Test that the server and tool names are split correctly."""
        copilot = Copilot()
        cfg1 = _cfg(name="foo", agent="copilot")
        cfg2 = _cfg(name="foo-bar", agent="copilot")
        server = MCPServer(name="server1", configurations=[cfg1])
        server2 = MCPServer(name="server2", configurations=[cfg2])
        discovery = _ai_discovery(servers=[server, server2])
        payload = _payload(
            copilot,
            raw={"tool_name": "foo-bar-tool-name", "cwd": "/tmp", "tool_input": {}},
        )

        req = copilot.parse_mcp_activity(payload, discovery)

        assert req.tool == "tool-name"
        assert req.server == "server2"

    def test_unknown_server_falls_back_to_cfg_name(self):
        copilot = Copilot()
        discovery = _ai_discovery(servers=[])
        payload = _payload(
            copilot,
            raw={
                "tool_name": "unknown-server-tool_name",
                "cwd": "/tmp",
                "tool_input": {},
            },
        )

        req = copilot.parse_mcp_activity(payload, discovery)

        assert req.server == "unknown-server"
        assert req.tool == "tool_name"


# ===========================================================================
# _parse_tool_arguments (Cursor helper)
# ===========================================================================


class TestParseToolArguments:
    def test_valid_schema(self):
        schema = {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "SQL query"},
                "limit": {"type": "integer"},
            },
            "required": ["query"],
        }
        result = _parse_tool_arguments(schema)
        assert result is not None
        assert len(result) == 2
        q = next(a for a in result if a.name == "query")
        assert q.required is True
        assert q.description == "SQL query"
        lim = next(a for a in result if a.name == "limit")
        assert lim.required is False

    def test_empty_properties_returns_none(self):
        schema = {"type": "object", "properties": {}}
        assert _parse_tool_arguments(schema) is None

    @pytest.mark.parametrize(
        "schema",
        [
            pytest.param(None, id="none"),
            pytest.param("string", id="string"),
            pytest.param(42, id="integer"),
        ],
    )
    def test_non_dict_schema_returns_none(self, schema: Any):
        assert _parse_tool_arguments(schema) is None
