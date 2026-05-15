import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import pytest
from pygitguardian.models import AIDiscovery, MCPConfiguration, MCPServer, UserInfo

from ggshield.verticals.ai.agents.cursor import (
    CHAT_DB_RELATIVE_PATH,
    MCP_TOOL_KIND,
    Cursor,
)


def _bubble(**overrides) -> str:
    base = {
        "type": 2,
        "bubbleId": "b1",
        "createdAt": "2026-04-01T09:00:00.000Z",
        "workspaceUris": [],
        "toolFormerData": {
            "tool": MCP_TOOL_KIND,
            "toolCallId": "tool_AAA",
            "name": "mcp_linear_get_issue",
            "rawArgs": json.dumps(
                {
                    "name": "user-linear-get_issue",
                    "args": {"id": "NHI-1"},
                    "toolCallId": "tool_AAA",
                    "providerIdentifier": "linear",
                    "toolName": "get_issue",
                }
            ),
            "params": json.dumps(
                {
                    "tools": [
                        {
                            "name": "get_issue",
                            "parameters": '{"id":"NHI-1"}',
                            "serverName": "linear",
                        }
                    ]
                }
            ),
        },
    }
    base.update(overrides)
    return json.dumps(base)


@pytest.fixture
def empty_ai_config() -> AIDiscovery:
    return AIDiscovery(
        user=UserInfo(hostname="h", username="u", machine_id="m"),
        servers=[],
        discovery_duration=0.0,
    )


class TestCursorParseBubble:
    def test_extracts_mcp_tool_use(self, empty_ai_config) -> None:
        event = Cursor()._parse_bubble(
            _bubble(), empty_ai_config, "/home/u/repo", "composer-2"
        )
        assert event is not None
        assert event.tool == "get_issue"
        assert event.server == "linear"
        assert event.agent == "cursor"
        assert event.cwd == "/home/u/repo"
        assert event.model == "composer-2"
        assert event.timestamp == datetime(2026, 4, 1, 9, 0, tzinfo=timezone.utc)
        assert event.input == {"id": "NHI-1"}

    def test_unwraps_rawargs_envelope(self, empty_ai_config) -> None:
        """``rawArgs`` is a stringified envelope; only its ``args`` field is the live input."""
        raw = _bubble(
            toolFormerData={
                "tool": MCP_TOOL_KIND,
                "toolCallId": "tool_X",
                "rawArgs": json.dumps(
                    {
                        "name": "user-Notion-notion-get-users",
                        "args": {"user_id": "self"},
                        "toolCallId": "tool_X",
                        "providerIdentifier": "Notion",
                        "toolName": "notion-get-users",
                    }
                ),
                "params": json.dumps(
                    {
                        "tools": [
                            {
                                "name": "notion-get-users",
                                "parameters": '{"user_id":"self"}',
                                "serverName": "Notion",
                            }
                        ]
                    }
                ),
            }
        )
        event = Cursor()._parse_bubble(raw, empty_ai_config, "", "")
        assert event is not None
        assert event.input == {"user_id": "self"}

    def test_skips_malformed_json(self, empty_ai_config) -> None:
        assert Cursor()._parse_bubble("not-json", empty_ai_config, "", "") is None

    def test_skips_missing_tool_former_data(self, empty_ai_config) -> None:
        raw = json.dumps({"type": 2, "createdAt": "2026-04-01T09:00:00Z"})
        assert Cursor()._parse_bubble(raw, empty_ai_config, "", "") is None

    def test_skips_when_params_lacks_tools(self, empty_ai_config) -> None:
        raw = _bubble(
            toolFormerData={
                "tool": MCP_TOOL_KIND,
                "toolCallId": "x",
                "params": "{}",
                "rawArgs": "{}",
            }
        )
        assert Cursor()._parse_bubble(raw, empty_ai_config, "", "") is None

    def test_skips_when_timestamp_invalid(self, empty_ai_config) -> None:
        raw = _bubble(createdAt="not-a-date")
        assert Cursor()._parse_bubble(raw, empty_ai_config, "", "") is None

    def test_handles_dash_form_name(self, empty_ai_config) -> None:
        """Newer name layout (mcp-<server>-<tool>) still parses via params.tools[0]."""
        raw = _bubble(
            toolFormerData={
                "tool": MCP_TOOL_KIND,
                "toolCallId": "tool_X",
                "name": "mcp-ward-runs-app-linear-get_issue",
                "rawArgs": json.dumps(
                    {
                        "name": "user-linear-get_issue",
                        "args": {"id": "NHI-9"},
                        "toolCallId": "tool_X",
                        "providerIdentifier": "linear",
                        "toolName": "get_issue",
                    }
                ),
                "params": json.dumps(
                    {
                        "tools": [
                            {
                                "name": "get_issue",
                                "parameters": '{"id":"NHI-9"}',
                                "serverName": "ward-runs-app-linear",
                            }
                        ]
                    }
                ),
            }
        )
        event = Cursor()._parse_bubble(raw, empty_ai_config, "", "")
        assert event is not None
        assert event.tool == "get_issue"
        assert event.server == "ward-runs-app-linear"
        assert event.input == {"id": "NHI-9"}

    def test_resolves_server_display_name_from_discovery(self) -> None:
        config = AIDiscovery(
            user=UserInfo(hostname="h", username="u", machine_id="m"),
            servers=[
                MCPServer(
                    name="LinearDisplay",
                    configurations=[
                        MCPConfiguration(
                            name="linear",
                            agent="cursor",
                            scope=MCPConfiguration.Scope.USER,
                            transport=MCPConfiguration.Transport.STDIO,
                            project=None,
                        )
                    ],
                ),
            ],
            discovery_duration=0.0,
        )
        event = Cursor()._parse_bubble(_bubble(), config, "", "")
        assert event is not None
        assert event.server == "LinearDisplay"


class TestCursorIterHistoryEvents:
    def _make_db(self, tmp_path: Path) -> Path:
        db_dir = tmp_path / CHAT_DB_RELATIVE_PATH.parent
        db_dir.mkdir(parents=True)
        return db_dir / CHAT_DB_RELATIVE_PATH.name

    def _seed(
        self,
        db_path: Path,
        rows: list[tuple[str, str]],
        item_table_rows: Optional[list[tuple[str, str]]] = None,
    ) -> None:
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("CREATE TABLE ItemTable (key TEXT UNIQUE, value BLOB)")
        conn.executemany("INSERT INTO cursorDiskKV VALUES (?, ?)", rows)
        if item_table_rows:
            conn.executemany("INSERT INTO ItemTable VALUES (?, ?)", item_table_rows)
        conn.commit()
        conn.close()

    @staticmethod
    def _composer_headers(*entries: tuple[str, str]) -> str:
        """Build a ``composer.composerHeaders`` JSON blob for the given (id, path) pairs."""
        return json.dumps(
            {
                "allComposers": [
                    {
                        "composerId": composer_id,
                        "workspaceIdentifier": {
                            "uri": {
                                "path": path,
                                "fsPath": path,
                                "external": f"file://{path}",
                                "scheme": "file",
                            }
                        },
                    }
                    for composer_id, path in entries
                ]
            }
        )

    def test_yields_events_resolves_cwd_via_item_table_and_model(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        composer = "11111111-2222-3333-4444-555555555555"
        rows = [
            (f"bubbleId:{composer}:tool-1", _bubble()),
            (
                f"bubbleId:{composer}:tool-2",
                _bubble(
                    toolFormerData={
                        "tool": MCP_TOOL_KIND,
                        "toolCallId": "tool_BBB",
                        "rawArgs": json.dumps(
                            {
                                "name": "user-linear-get_issue",
                                "args": {"id": "NHI-2"},
                                "toolCallId": "tool_BBB",
                                "providerIdentifier": "linear",
                                "toolName": "get_issue",
                            }
                        ),
                        "params": json.dumps(
                            {
                                "tools": [
                                    {
                                        "name": "get_issue",
                                        "parameters": "",
                                        "serverName": "linear",
                                    }
                                ]
                            }
                        ),
                    }
                ),
            ),
            (
                f"composerData:{composer}",
                json.dumps({"modelConfig": {"modelName": "composer-2"}}),
            ),
            # Non-MCP tool — should be filtered out at SQL level.
            (
                f"bubbleId:{composer}:other-1",
                json.dumps(
                    {
                        "type": 2,
                        "toolFormerData": {"tool": 9, "name": "codebase_search"},
                    }
                ),
            ),
        ]
        item_table_rows = [
            (
                "composer.composerHeaders",
                self._composer_headers((composer, "/home/u/repo")),
            )
        ]

        db_path = self._make_db(tmp_path)
        self._seed(db_path, rows, item_table_rows)

        with patch(
            "ggshield.verticals.ai.agents.cursor.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Cursor().iter_history_events(empty_ai_config))

        assert len(events) == 2
        assert all(e.cwd == "/home/u/repo" for e in events)
        assert all(e.model == "composer-2" for e in events)
        assert events[0].input == {"id": "NHI-1"}
        assert events[1].input == {"id": "NHI-2"}

    def test_falls_back_to_bubble_workspace_when_not_in_item_table(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        """No ItemTable header for this composer → fall back to the user bubble."""
        composer = "11111111-2222-3333-4444-555555555555"
        user_bubble = json.dumps(
            {
                "type": 1,
                "createdAt": "2026-04-01T08:59:00Z",
                "workspaceUris": ["file:///home/u/repo"],
            }
        )
        rows = [
            (f"bubbleId:{composer}:user-1", user_bubble),
            (f"bubbleId:{composer}:tool-1", _bubble()),
        ]
        db_path = self._make_db(tmp_path)
        self._seed(db_path, rows)  # no ItemTable rows seeded

        with patch(
            "ggshield.verticals.ai.agents.cursor.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Cursor().iter_history_events(empty_ai_config))

        assert len(events) == 1
        assert events[0].cwd == "/home/u/repo"
        assert events[0].model == ""

    def test_missing_db_yields_nothing(self, tmp_path: Path, empty_ai_config) -> None:
        with patch(
            "ggshield.verticals.ai.agents.cursor.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Cursor().iter_history_events(empty_ai_config))
        assert events == []

    def test_empty_cwd_when_no_workspace_anywhere(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        composer = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        user_bubble = json.dumps(
            {
                "type": 1,
                "createdAt": "2026-04-01T08:59:00Z",
                "workspaceUris": [],
            }
        )
        rows = [
            (f"bubbleId:{composer}:user-1", user_bubble),
            (f"bubbleId:{composer}:tool-1", _bubble()),
        ]
        db_path = self._make_db(tmp_path)
        self._seed(db_path, rows)  # no ItemTable rows seeded

        with patch(
            "ggshield.verticals.ai.agents.cursor.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Cursor().iter_history_events(empty_ai_config))

        assert len(events) == 1
        assert events[0].cwd == ""
