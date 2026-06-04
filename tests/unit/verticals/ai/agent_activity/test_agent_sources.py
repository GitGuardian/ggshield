"""Each agent's registered source discovers its on-disk transcript and ships the
record **raw** (verbatim). GitGuardian scans and strips secrets server-side, so
secrets are still present client-side here. Uses GG_USER_HOME_DIR to redirect
every ``get_user_home_dir()`` call at once."""

import json
import sqlite3
from pathlib import Path

import pytest

from ggshield.core.dirs import get_editor_user_data_dir


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("GG_USER_HOME_DIR", str(tmp_path))
    return tmp_path


def test_claude_agent_ships_raw_transcript_lines(fake_home: Path) -> None:
    from ggshield.verticals.ai.agents.claude_code import Claude

    proj = fake_home / ".claude" / "projects" / "-repo"
    proj.mkdir(parents=True)
    line = json.dumps(
        {
            "type": "assistant",
            "message": {"content": [{"type": "tool_use", "name": "Bash"}]},
        }
    )
    (proj / "s.jsonl").write_text(line + "\n")

    [event] = list(Claude().iter_agent_activity_events())

    assert event.agent_name == "claude-code"
    assert event.source_kind == "session_transcript"
    assert event.source_path == "projects/-repo/s.jsonl"
    # Shipped verbatim — server-side scanning happens later, not in the source.
    assert event.content == line


def test_claude_agent_ships_subagent_transcripts(fake_home: Path) -> None:
    """Subagent transcripts live in a separate file and must be collected too."""
    from ggshield.verticals.ai.agents.claude_code import Claude

    session = fake_home / ".claude" / "projects" / "-repo" / "sess-uuid"
    subagents = session / "subagents"
    subagents.mkdir(parents=True)
    main_line = json.dumps({"type": "user", "message": {"content": "hi"}})
    (session.parent / "sess-uuid.jsonl").write_text(main_line + "\n")
    sub_line = json.dumps(
        {"type": "user", "isSidechain": True, "message": {"content": "do X"}}
    )
    (subagents / "agent-abc.jsonl").write_text(sub_line + "\n")

    events = list(Claude().iter_agent_activity_events())

    kinds = {e.source_kind for e in events}
    assert kinds == {"session_transcript", "subagent_transcript"}
    [sub] = [e for e in events if e.source_kind == "subagent_transcript"]
    assert sub.source_path == "projects/-repo/sess-uuid/subagents/agent-abc.jsonl"
    assert sub.content == sub_line


def test_claude_agent_ships_subagent_meta(fake_home: Path) -> None:
    """The subagent .meta.json (links the run to its parent Task call) is shipped."""
    from ggshield.verticals.ai.agents.claude_code import Claude

    subagents = fake_home / ".claude" / "projects" / "-repo" / "sess" / "subagents"
    subagents.mkdir(parents=True)
    meta = json.dumps(
        {"agentType": "Explore", "description": "map X", "toolUseId": "toolu_1"}
    )
    (subagents / "agent-abc.meta.json").write_text(meta)

    events = list(Claude().iter_agent_activity_events())

    [m] = [e for e in events if e.source_kind == "subagent_meta"]
    assert m.source_path == "projects/-repo/sess/subagents/agent-abc.meta.json"
    assert m.content == meta


def test_codex_agent_ships_raw_rollout_lines(fake_home: Path) -> None:
    from ggshield.verticals.ai.agents.codex import Codex

    sessions = fake_home / ".codex" / "sessions" / "2026" / "06" / "01"
    sessions.mkdir(parents=True)
    line = json.dumps({"type": "response_item", "payload": {"type": "function_call"}})
    (sessions / "rollout-x.jsonl").write_text(line + "\n")

    [event] = list(Codex().iter_agent_activity_events())

    assert event.agent_name == "codex"
    assert event.content == line


def test_cursor_agent_ships_raw_bubble_rows(fake_home: Path) -> None:
    from ggshield.verticals.ai.agents.cursor import Cursor

    db_path = get_editor_user_data_dir("Cursor") / "globalStorage" / "state.vscdb"
    db_path.parent.mkdir(parents=True)
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE cursorDiskKV (key TEXT, value TEXT)")
    bubble_value = json.dumps({"type": 2, "bubbleId": "b1", "text": "hi"})
    conn.execute(
        "INSERT INTO cursorDiskKV VALUES (?, ?)", ("bubbleId:c1:b1", bubble_value)
    )
    # A non-bubble row must be filtered out by the source query.
    conn.execute("INSERT INTO cursorDiskKV VALUES (?, ?)", ("composerData:c1", "{}"))
    conn.commit()
    conn.close()

    [composer_data, event] = list(Cursor().iter_agent_activity_events())

    assert composer_data.agent_name == "cursor"
    assert composer_data.source_kind == "composer_data"
    assert composer_data.record_offset == "composerData:c1"

    assert event.agent_name == "cursor"
    assert event.record_offset == "bubbleId:c1:b1"
    # Whole row shipped verbatim as {"key": ..., "value": <bubble json>}.
    row = json.loads(event.content)
    assert row["key"] == "bubbleId:c1:b1"
    assert json.loads(row["value"])["bubbleId"] == "b1"


def test_copilot_agent_ships_raw_event_lines(fake_home: Path) -> None:
    from ggshield.verticals.ai.agents.copilot import Copilot

    session = fake_home / ".copilot" / "session-state" / "uuid-1"
    session.mkdir(parents=True)
    line = json.dumps({"type": "tool.execution_start", "data": {"mcpToolName": "x"}})
    (session / "events.jsonl").write_text(line + "\n")

    [event] = list(Copilot().iter_agent_activity_events())

    assert event.agent_name == "copilot"
    assert event.source_kind == "session_events"
    assert event.source_path == "session-state/uuid-1/events.jsonl"
    assert event.content == line


def test_vscode_agent_ships_raw_chat_session_lines(fake_home: Path) -> None:
    from ggshield.verticals.ai.agents.vscode import VSCode

    sessions = (
        get_editor_user_data_dir("Code") / "workspaceStorage" / "hash" / "chatSessions"
    )
    sessions.mkdir(parents=True)
    line = json.dumps({"kind": 2, "v": [{"role": "user", "text": "hi"}]})
    (sessions / "s1.jsonl").write_text(line + "\n")

    [event] = list(VSCode().iter_agent_activity_events())

    assert event.agent_name == "vscode"
    assert event.source_kind == "chat_session"
    assert event.source_path == "workspaceStorage/hash/chatSessions/s1.jsonl"
    assert event.content == line


def test_copilot_does_not_inherit_vscode_source(fake_home: Path) -> None:
    """Copilot stores sessions under ~/.copilot, not VSCode's workspaceStorage,
    so it must override (not inherit) VSCode's activity source."""
    from ggshield.verticals.ai.agents.copilot import Copilot, CopilotActivitySource

    [source] = Copilot().agent_activity_sources
    assert isinstance(source, CopilotActivitySource)
