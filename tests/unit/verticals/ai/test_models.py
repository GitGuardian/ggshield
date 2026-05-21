import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest
from pygitguardian.models import MCPConfiguration

from ggshield.core.scan import File, StringScannable
from ggshield.verticals.ai.agents import Cursor
from ggshield.verticals.ai.models import (
    EventType,
    HookPayload,
    HookResult,
    Scope,
    Tool,
    Transport,
)


# ---------------------------------------------------------------------------
# HookPayload.scannable
# ---------------------------------------------------------------------------


class TestHookPayloadScannable:
    def test_read_tool_existing_text_file_returns_file(self, tmp_path: Path):
        f = tmp_path / "code.py"
        f.write_text("secret = 'abc'")
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            content="",
            identifier=str(f),
            agent=Cursor(),
            raw={},
        )
        assert isinstance(payload.scannable, File)

    def test_read_tool_missing_file_returns_string_scannable(self):
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            content="some content",
            identifier="/nonexistent/path.txt",
            agent=Cursor(),
            raw={},
        )
        assert isinstance(payload.scannable, StringScannable)

    def test_read_tool_binary_file_returns_string_scannable(self, tmp_path: Path):
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            content="",
            identifier=str(f),
            agent=Cursor(),
            raw={},
        )
        assert isinstance(payload.scannable, StringScannable)

    def test_non_read_tool_returns_string_scannable(self):
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.BASH,
            content="echo hello",
            identifier="cmd",
            agent=Cursor(),
            raw={},
        )
        assert isinstance(payload.scannable, StringScannable)


# ---------------------------------------------------------------------------
# HookPayload.empty
# ---------------------------------------------------------------------------


class TestHookPayloadEmpty:
    @pytest.mark.parametrize(
        "content, expected",
        [
            pytest.param("non-empty", False, id="non_empty_content"),
            pytest.param("", True, id="empty_content"),
        ],
    )
    def test_empty(self, content: str, expected: bool):
        payload = HookPayload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content=content,
            identifier="id",
            agent=Cursor(),
            raw={},
        )
        assert payload.empty is expected


# ---------------------------------------------------------------------------
# HookResult.allow
# ---------------------------------------------------------------------------


class TestHookResultAllow:
    def test_allow_creates_non_blocking_result(self):
        payload = HookPayload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content="hi",
            identifier="id",
            agent=Cursor(),
            raw={},
        )
        result = HookResult.allow(payload)
        assert result.block is False
        assert result.message == ""
        assert result.nbr_secrets == 0
        assert result.payload is payload


# ---------------------------------------------------------------------------
# Agent._parse_servers_block
# ---------------------------------------------------------------------------


class TestParseServersBlock:
    def _parse(
        self,
        data: Dict[str, Any],
        scope: Scope = Scope.USER,
        project: Optional[Path] = None,
    ) -> List[MCPConfiguration]:
        return list(Cursor()._parse_servers_block(data, scope, project))

    def test_mcp_servers_key_stdio(self):
        data = {
            "mcpServers": {
                "myserver": {
                    "command": "npx",
                    "args": ["-y", "mcp-server"],
                    "env": {"KEY": "val"},
                }
            }
        }
        configs = self._parse(data)
        assert len(configs) == 1
        cfg = configs[0]
        assert cfg.name == "myserver"
        assert cfg.transport == Transport.STDIO
        assert cfg.command == "npx"
        assert cfg.args == ["-y", "mcp-server"]
        assert cfg.env == {"KEY": "val"}

    def test_servers_key(self):
        data = {"servers": {"s1": {"command": "node"}}}
        configs = self._parse(data)
        assert len(configs) == 1
        assert configs[0].name == "s1"

    def test_url_entry_detected_as_http(self):
        data = {"mcpServers": {"remote": {"url": "https://example.com/mcp"}}}
        configs = self._parse(data)
        assert configs[0].transport == Transport.HTTP
        assert configs[0].url == "https://example.com/mcp"

    def test_url_entry_with_sse_transport(self):
        data = {
            "mcpServers": {
                "remote": {"url": "https://example.com/sse", "transport": "sse"}
            }
        }
        configs = self._parse(data)
        assert configs[0].transport == Transport.SSE

    def test_empty_block_yields_nothing(self):
        assert self._parse({}) == []
        assert self._parse({"mcpServers": {}}) == []


# ---------------------------------------------------------------------------
# Agent._load_file
# ---------------------------------------------------------------------------


class TestLoadFile:
    def test_returns_dict_for_valid_json(self, tmp_path: Path):
        f = tmp_path / "ok.json"
        f.write_text(json.dumps({"key": "value"}))
        assert Cursor()._load_file(f) == {"key": "value"}

    def test_returns_none_for_missing_file(self, tmp_path: Path):
        assert Cursor()._load_file(tmp_path / "missing.json") is None

    def test_returns_none_for_invalid_json(self, tmp_path: Path):
        f = tmp_path / "bad.json"
        f.write_text("{not valid json")
        assert Cursor()._load_file(f) is None

    def test_returns_none_for_non_dict_json(self, tmp_path: Path):
        f = tmp_path / "list.json"
        f.write_text(json.dumps([1, 2, 3]))
        assert Cursor()._load_file(f) is None


# ---------------------------------------------------------------------------
# Agent._load_jsonl_file
# ---------------------------------------------------------------------------


class TestLoadJsonlFile:
    def test_yields_valid_lines(self, tmp_path: Path):
        f = tmp_path / "data.jsonl"
        f.write_text('{"a":1}\n{"b":2}\n')
        assert list(Cursor()._load_jsonl_file(f)) == [{"a": 1}, {"b": 2}]

    def test_skips_invalid_lines(self, tmp_path: Path):
        f = tmp_path / "mixed.jsonl"
        f.write_text('{"ok":true}\nnot json\n{"also":"ok"}\n')
        assert list(Cursor()._load_jsonl_file(f)) == [
            {"ok": True},
            {"also": "ok"},
        ]

    def test_yields_nothing_for_missing_file(self, tmp_path: Path):
        assert list(Cursor()._load_jsonl_file(tmp_path / "nope.jsonl")) == []


# ---------------------------------------------------------------------------
# Agent.discover_mcp_configurations
# ---------------------------------------------------------------------------


class TestDiscoverMcpConfigurations:
    def test_combines_user_and_project_configs(self, tmp_path: Path):
        # User-level config
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "mcp.json").write_text(
            json.dumps({"mcpServers": {"global-srv": {"command": "node", "args": []}}})
        )

        # Project-level config
        project = tmp_path / "project"
        project.mkdir()
        cursor_dir = project / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text(
            json.dumps({"mcpServers": {"proj-srv": {"command": "python", "args": []}}})
        )

        agent = Cursor()
        with patch.object(type(agent), "config_folder", new=config_dir):
            result = agent.discover_mcp_configurations([project])

        assert len(result) == 2
        assert result[0].name == "global-srv"
        assert result[0].scope == Scope.USER
        assert result[1].name == "proj-srv"
        assert result[1].scope == Scope.PROJECT
        assert result[1].project == str(project)

    def test_no_configs_returns_empty(self, tmp_path: Path):
        agent = Cursor()
        with patch.object(type(agent), "config_folder", new=tmp_path / "empty"):
            result = agent.discover_mcp_configurations([])
        assert result == []
