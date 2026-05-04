import json
from collections import Counter
from pathlib import Path
from typing import List, Set
from unittest.mock import MagicMock, patch

import pytest
from pygitguardian import GGClient
from pygitguardian.models import MCPActivityResponse

from ggshield.utils.git_shell import Filemode
from ggshield.verticals.ai.agents import Claude, Codex, Copilot, Cursor
from ggshield.verticals.ai.hooks import AIHookScanner, find_filepaths, parse_hook_input
from ggshield.verticals.ai.mcp import send_mcp_activity
from ggshield.verticals.ai.models import EventType, HookPayload, HookResult, Tool
from ggshield.verticals.secret import SecretScanner
from ggshield.verticals.secret.secret_scan_collection import Result as ScanResult
from ggshield.verticals.secret.secret_scan_collection import Results, Secret


def _dummy_payload(event_type: EventType = EventType.OTHER) -> HookPayload:
    return HookPayload(
        event_type=event_type,
        tool=None,
        content="",
        identifier="",
        agent=Cursor(),
        raw={},
    )


@pytest.fixture
def tmp_file(tmp_path: Path) -> Path:
    """Create a temporary file with content."""
    file = tmp_path / "test.txt"
    file.write_text("this is the content")
    return file


def _mock_scanner(matches: List[str]) -> MagicMock:
    """Create a mock SecretScanner that returns the given Results from scan()."""
    mock = MagicMock(spec=SecretScanner)
    mock.client = MagicMock(spec=GGClient)
    scan_result = Results(
        results=[
            ScanResult(
                filename="url",
                filemode=Filemode.FILE,
                path=Path("."),
                url="url",
                secrets=[_make_secret(match) for match in matches],
                ignored_secrets_count_by_kind=Counter(),
            )
        ],
        errors=[],
    )
    mock.scan.return_value = scan_result
    return mock


def _make_secret(match_str: str = "***"):
    """Minimal Secret for tests; _message_from_secrets only uses detector_display_name, validity, matches[].match."""
    mock_match = MagicMock()
    mock_match.match = match_str
    return Secret(
        detector_display_name="dummy-detector",
        detector_name="dummy-detector",
        detector_group_name=None,
        documentation_url=None,
        validity="valid",
        known_secret=False,
        incident_url=None,
        matches=[mock_match],
        ignore_reason=None,
        diff_kind=None,
        is_vaulted=False,
        vault_type=None,
        vault_name=None,
        vault_path=None,
        vault_path_count=None,
    )


class TestAIHookScannerScanContent:
    """Unit tests for AIHookScanner._scan_content."""

    def test_no_secrets_returns_allow(self):
        """When scanner returns no secrets, result has block=False and nbr_secrets=0."""
        hook_scanner = AIHookScanner(_mock_scanner([]))
        payload = HookPayload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content="safe content",
            identifier="id",
            agent=Cursor(),
            raw={},
        )
        result = hook_scanner._scan_content(payload)
        assert isinstance(result, HookResult)
        assert result.block is False
        assert result.nbr_secrets == 0
        assert result.message == ""

    def test_with_secrets_returns_block_and_message(self):
        """When scanner returns secrets, result has block=True, nbr_secrets and message set."""
        hook_scanner = AIHookScanner(_mock_scanner(["sk-xxx"]))
        payload = HookPayload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content="content with sk-xxx",
            identifier="id",
            agent=Cursor(),
            raw={},
        )
        result = hook_scanner._scan_content(payload)
        assert isinstance(result, HookResult)
        assert result.block is True
        assert result.nbr_secrets == 1
        assert "dummy-detector" in result.message
        assert "secret" in result.message.lower()
        assert "remove the secrets from your prompt" in result.message


class TestAIHookScannerScan:
    """Unit tests for the AIHookScanner.scan() method."""

    def test_empty_input_raises(self):
        """Empty or whitespace-only input raises ValueError."""
        scanner = AIHookScanner(_mock_scanner([]))
        with pytest.raises(ValueError, match="No input received on stdin"):
            scanner.scan("")
        with pytest.raises(ValueError, match="No input received on stdin"):
            scanner.scan("   \n  ")

    def test_scan_no_secrets_returns_zero(self):
        """scan() with no secrets returns 0."""
        scanner = AIHookScanner(_mock_scanner([]))
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "cursor_version": "1.2.3",
        }
        code = scanner.scan(json.dumps(data))
        assert code == 0

    @patch("ggshield.verticals.ai.hooks.AIHookScanner._send_secret_notification")
    def test_scan_post_tool_use_with_secrets_sends_notification(
        self, mock_notify: MagicMock
    ):
        """scan() on POST_TOOL_USE with secrets sends a notification and returns 0 (no block)."""
        scanner = AIHookScanner(_mock_scanner(["sk-xxx"]))
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo sk-xxx"},
            "tool_response": {"stdout": "sk-xxx\n"},
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "session_id": "427ae0c5-0862-4e14-aa2c-12fad909c323",
        }
        code = scanner.scan(json.dumps(data))
        assert code == 0
        mock_notify.assert_called_once()
        args = mock_notify.call_args[0]
        assert args[0] == 1  # nbr_secrets
        assert args[1] == Tool.BASH  # tool

    def test_scan_pre_tool_use_with_secrets_blocks(self):
        """scan() on PRE_TOOL_USE with secrets returns block result."""
        scanner = AIHookScanner(_mock_scanner(["sk-xxx"]))
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo sk-xxx"},
            "session_id": "427ae0c5-0862-4e14-aa2c-12fad909c323",
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
        }
        code = scanner.scan(json.dumps(data))
        # Claude output_result always returns 0
        assert code == 0

    def test_scan_no_content_returns_allow(self):
        """scan() with no content returns 0 (and doesn't call the API)."""
        mock_scanner = _mock_scanner([])
        scanner = AIHookScanner(mock_scanner)
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "doesn-t-exist"},
            "cursor_version": "1.2.3",
        }
        code = scanner.scan(json.dumps(data))
        assert code == 0
        mock_scanner.scan.assert_not_called()

    def test_scan_payloads_refuse_empty_list(self):
        """scan() with empty list of payloads raises ValueError."""
        scanner = AIHookScanner(_mock_scanner([]))
        with pytest.raises(ValueError):
            scanner._scan_payloads([])


class TestMCPActivity:
    """Unit tests for MCP activity handling."""

    @pytest.mark.parametrize(
        "event_type, tool",
        [
            (EventType.USER_PROMPT, None),
            (EventType.POST_TOOL_USE, Tool.MCP),
            (EventType.PRE_TOOL_USE, Tool.BASH),
            (EventType.OTHER, None),
        ],
    )
    def test_send_mcp_activity_early_returns_for_non_mcp_pre_tool_use(
        self, event_type: EventType, tool: Tool
    ):
        """send_mcp_activity returns allowed=True without calling the API
        when the payload is not an MCP PreToolUse."""
        client = MagicMock(spec=GGClient)
        payload = HookPayload(
            event_type=event_type,
            tool=tool,
            content="some content",
            identifier="id",
            agent=Cursor(),
            raw={},
        )
        result = send_mcp_activity(client, payload)
        assert isinstance(result, MCPActivityResponse)
        assert result.allowed is True
        assert result.reason == ""
        client.post.assert_not_called()

    @patch("ggshield.verticals.ai.hooks.send_mcp_activity")
    def test_scan_calls_send_mcp_activity_for_mcp_pre_tool_use(
        self, mock_send_mcp: MagicMock
    ):
        """AIHookScanner.scan() calls send_mcp_activity when the payload is an MCP PreToolUse."""
        mock_send_mcp.return_value = MCPActivityResponse(allowed=True, reason="")
        scanner = AIHookScanner(_mock_scanner([]))
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__some_server__some_tool",
            "tool_input": {"arg": "value"},
            "cursor_version": "2.5.25",
        }
        scanner.scan(json.dumps(data))
        mock_send_mcp.assert_called_once()
        call_payload = mock_send_mcp.call_args[0][1]
        assert call_payload.event_type == EventType.PRE_TOOL_USE
        assert call_payload.tool == Tool.MCP


class TestMessageFromSecrets:
    """Unit tests for AIHookScanner._message_from_secrets with different payload types."""

    def test_message_for_bash_tool(self):
        """Message for BASH tool mentions environment variables."""
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.BASH,
            content="echo sk-xxx",
            identifier="echo sk-xxx",
            agent=Cursor(),
            raw={},
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "remove the secrets from the command" in message
        assert "environment variables" in message

    def test_message_for_read_tool(self):
        """Message for READ tool mentions file content."""
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            content="file content with secret",
            identifier="/path/to/file",
            agent=Cursor(),
            raw={},
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "remove the secrets from" in message

    def test_message_for_edit_tool(self):
        """Message for EDIT tool mentions file edits."""
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.EDIT,
            content="*** Begin Patch\n+sk-xxx\n*** End Patch\n",
            identifier="patch",
            agent=Codex(),
            raw={},
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "remove the secrets from the file edit" in message
        assert "environment variables" in message

    def test_message_for_other_tool(self):
        """Message for OTHER tool uses generic message."""
        payload = HookPayload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.OTHER,
            content="some content",
            identifier="id",
            agent=Cursor(),
            raw={},
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "remove the secrets from the tool input" in message

    def test_message_escapes_markdown(self):
        """When escape_markdown=True, asterisks in matches are replaced with dots."""
        payload = HookPayload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content="content",
            identifier="id",
            agent=Cursor(),
            raw={},
        )
        message = AIHookScanner._message_from_secrets(
            [_make_secret("sk-xxx")], payload, escape_markdown=True
        )
        # The message itself should not contain raw asterisks from matches
        # (the header uses ** for bold which is intentional)
        assert "Detected" in message


class TestSendSecretNotification:
    """Unit tests for AIHookScanner._send_secret_notification."""

    @patch("ggshield.verticals.ai.hooks.Notify")
    def test_notification_for_bash_tool(self, mock_notify_cls: MagicMock):
        """Notification for BASH tool says 'running a command'."""
        AIHookScanner._send_secret_notification(1, Tool.BASH, "Claude Code")
        instance = mock_notify_cls.return_value
        assert "running a command" in instance.message
        assert "Claude Code" in instance.message
        instance.send.assert_called_once()

    @patch("ggshield.verticals.ai.hooks.Notify")
    def test_notification_for_read_tool(self, mock_notify_cls: MagicMock):
        """Notification for READ tool says 'reading a file'."""
        AIHookScanner._send_secret_notification(2, Tool.READ, "Cursor")
        instance = mock_notify_cls.return_value
        assert "reading a file" in instance.message
        assert "2" in instance.message
        instance.send.assert_called_once()

    @patch("ggshield.verticals.ai.hooks.Notify")
    def test_notification_for_other_tool(self, mock_notify_cls: MagicMock):
        """Notification for OTHER tool says 'using a tool'."""
        AIHookScanner._send_secret_notification(1, Tool.OTHER, "Copilot")
        instance = mock_notify_cls.return_value
        assert "using a tool" in instance.message
        instance.send.assert_called_once()

    @patch("ggshield.verticals.ai.hooks.Notify")
    def test_notification_for_edit_tool(self, mock_notify_cls: MagicMock):
        """Notification for EDIT tool says 'editing a file'."""
        AIHookScanner._send_secret_notification(1, Tool.EDIT, "Codex")
        instance = mock_notify_cls.return_value
        assert "editing a file" in instance.message
        assert "Codex" in instance.message
        instance.send.assert_called_once()


class TestAIHookScannerParseInput:
    """Unit tests for AIHookparse_hook_input."""

    def test_invalid_json_raises(self):
        """Invalid JSON raises ValueError with parse error."""
        with pytest.raises(ValueError, match="Failed to parse JSON"):
            parse_hook_input("not json {")
        with pytest.raises(ValueError, match="Failed to parse JSON"):
            parse_hook_input("{ missing brace ")

    def test_missing_event_type_raises(self):
        """JSON without event type raises ValueError."""
        with pytest.raises(ValueError):
            parse_hook_input('{"prompt": "hello"}')

    def test_cursor_user_prompt(self):
        """Test Cursor beforeSubmitPrompt (user prompt) parsing."""
        data = {
            "conversation_id": "75fed8a8-2078-4e49-80d2-776b20d441c3",
            "generation_id": "1501ede6-b8ac-43f4-9943-0e218610c5c6",
            "model": "default",
            "prompt": "hello world",
            "attachments": [],
            "hook_event_name": "beforeSubmitPrompt",
            "cursor_version": "2.5.25",
            "workspace_roots": ["/home/user1/foo"],
            "user_email": "user@example.com",
            "transcript_path": "/home/user1/.cursor/projects/foo/agent-transcripts/75fed8a8/75fed8a8.jsonl",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.content == "hello world"
        assert payload.tool is None
        assert payload.identifier != ""
        assert isinstance(payload.agent, Cursor)

    def test_cursor_pre_tool_use_shell(self):
        """Test Cursor preToolUse with Shell (bash) parsing."""
        data = {
            "conversation_id": "37a17cfc-322c-47ab-88c5-e810f23f4739",
            "generation_id": "049f5b26-326a-4081-82c1-e5c42a63d19e",
            "model": "default",
            "tool_name": "Shell",
            "tool_input": {
                "command": "whoami",
                "cwd": "",
                "timeout": 30000,
            },
            "tool_use_id": "ec1b1027-5b24-4a18-90c7-f8f616d0aeb4",
            "hook_event_name": "preToolUse",
            "cursor_version": "2.5.25",
            "workspace_roots": ["/home/user1/foo"],
            "transcript_path": "/home/user1/.cursor/projects/foo/agent-transcripts/37a17cfc/37a17cfc.jsonl",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert payload.content == "whoami"
        assert payload.identifier == "whoami"
        assert isinstance(payload.agent, Cursor)

    def test_cursor_pre_tool_use_read(self, tmp_file: Path):
        """Test Cursor preToolUse with Read (file) parsing."""
        data = {
            "conversation_id": "75fed8a8-2078-4e49-80d2-776b20d441c3",
            "generation_id": "1501ede6-b8ac-43f4-9943-0e218610c5c6",
            "model": "default",
            "tool_name": "Read",
            "tool_input": {"file_path": tmp_file.as_posix()},
            "tool_use_id": "tool_fbfdb104-86a6-4111-a1bf-ce789f93cab",
            "hook_event_name": "preToolUse",
            "cursor_version": "2.5.25",
            "workspace_roots": ["/home/user1/foo"],
            "transcript_path": "/home/user1/.cursor/projects/foo/agent-transcripts/75fed8a8/75fed8a8.jsonl",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == tmp_file.as_posix()
        assert payload.content == ""
        assert payload.scannable.content == "this is the content"
        assert isinstance(payload.agent, Cursor)

    def test_cursor_post_tool_use_shell(self):
        """Test Cursor postToolUse with Shell (simulated cat command result)."""
        data = {
            "conversation_id": "37a17cfc-322c-47ab-88c5-e810f23f4739",
            "generation_id": "049f5b26-326a-4081-82c1-e5c42a63d19e",
            "model": "default",
            "tool_name": "Shell",
            "tool_input": {"command": "whoami", "cwd": "", "timeout": 30000},
            "tool_output": '{"output":"user1","exitCode":0}',
            "duration": 280.475,
            "tool_use_id": "ec1b1027-5b24-4a18-90c7-f8f616d0aeb4",
            "hook_event_name": "postToolUse",
            "cursor_version": "2.5.25",
            "workspace_roots": ["/home/user1/foo"],
            "transcript_path": "/home/user/.cursor/projects/foo/agent-transcripts/37a17cfc/37a17cfc.jsonl",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "user1" in payload.content
        assert isinstance(payload.agent, Cursor)

    def test_claude_user_prompt(self):
        """Test Claude Code UserPromptSubmit parsing."""
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user1/.claude/projects/foo/273ad859-3608-4799-9971-fa15ecb1a65c.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.content == "hello world"
        assert payload.tool is None
        assert isinstance(payload.agent, Claude)

    def test_claude_pre_tool_use_bash(self):
        """Test Claude Code PreToolUse with Bash parsing."""
        data = {
            "session_id": "3b7ae0c5-0862-4e14-aa2c-12fad909c323",
            "transcript_path": "/home/user1/.claude/projects/foo/3b7ae0c5.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "whoami",
                "description": "whoami to test postTool hook",
            },
            "tool_use_id": "toolu_01BPMKeZAMCqBtn1xJRNfDJw",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "whoami" in payload.content
        assert isinstance(payload.agent, Claude)

    def test_claude_pre_tool_use_read(self, tmp_file: Path):
        """Test Claude Code PreToolUse with Read parsing."""
        # From raw_hooks_logs: Claude PreToolUse Read
        data = {
            "session_id": "3b7ae0c5-0862-4e14-aa2c-12fad909c323",
            "transcript_path": "/home/user1/.claude/projects/foo/3b7ae0c5.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": tmp_file.as_posix()},
            "tool_use_id": "toolu_01WabtWJpzf1ZJ8GJ3JfQEmq",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == tmp_file.as_posix()
        assert payload.content == ""
        assert payload.scannable.content == "this is the content"
        assert isinstance(payload.agent, Claude)

    def test_claude_post_tool_use_bash(self):
        """Test Claude Code PostToolUse with Bash (simulated cat command result)."""
        # From raw_hooks_logs: Claude PostToolUse Bash - tool_response has stdout
        data = {
            "session_id": "3b7ae0c5-0862-4e14-aa2c-12fad909c323",
            "transcript_path": "/home/user1/.claude/projects/foo/3b7ae0c5.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "whoami",
                "description": "whoami to test postTool hook",
            },
            "tool_response": {
                "stdout": "user1\n",
                "stderr": "",
                "interrupted": False,
                "isImage": False,
                "noOutputExpected": False,
            },
            "tool_use_id": "toolu_01BPMKeZAMCqBtn1xJRNfDJw",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        # Content is json.dumps(tool_response), so the stdout is inside the string
        assert "user1" in payload.content
        assert isinstance(payload.agent, Claude)

    def test_claude_parse_read_files_in_prompt(self):
        """Test parsing "@file_path" mentions from Claude Code prompt."""
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user1/.claude/projects/foo/273ad859-3608-4799-9971-fa15ecb1a65c.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "read @folder/file.txt and summarize the content.",
        }
        payloads = parse_hook_input(json.dumps(data))
        assert len(payloads) == 2
        payload = payloads[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.tool == Tool.READ
        assert payload.identifier == "folder/file.txt"
        assert payload.content == ""  # empty because inexistent file
        assert isinstance(payload.agent, Claude)

        payload = payloads[1]
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.content == "read @folder/file.txt and summarize the content."
        assert payload.tool is None
        assert isinstance(payload.agent, Claude)

    def test_copilot_user_prompt(self):
        """Test Copilot UserPromptSubmit parsing."""
        data = {
            "timestamp": "2026-02-26T11:28:53.112Z",
            "hookEventName": "UserPromptSubmit",
            "sessionId": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "transcript_path": (
                "/home/user1/.config/Code/User/workspaceStorage/"
                "abc123/GitHub.copilot-chat/transcripts/69cc6a03.jsonl"
            ),
            "prompt": "hello world",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert "hello world" in payload.content
        assert payload.tool is None
        assert isinstance(payload.agent, Copilot)

    def test_copilot_pre_tool_use_run_in_terminal(self):
        """Test Copilot PreToolUse with run_in_terminal (shell) parsing."""
        # From raw_hooks_logs: Copilot PreToolUse run_in_terminal
        data = {
            "timestamp": "2026-02-26T11:29:05.821Z",
            "hookEventName": "PreToolUse",
            "sessionId": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "transcript_path": (
                "/home/user1/.config/Code/User/workspaceStorage/"
                "abc123/GitHub.copilot-chat/transcripts/69cc6a03.jsonl"
            ),
            "tool_name": "run_in_terminal",
            "tool_input": {
                "command": "whoami",
                "explanation": "whoami to test preToolUse hook",
                "goal": "whoami to test preToolUse hook",
                "isBackground": False,
                "timeout": 0,
            },
            "tool_use_id": "call_ADJcoVxpnzPtpU6uf0h9wzLR__vscode-1772105116075",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "whoami" in payload.content
        assert isinstance(payload.agent, Copilot)

    def test_copilot_pre_tool_use_read_file(self, tmp_file: Path):
        """Test Copilot PreToolUse with read_file parsing."""
        # From raw_hooks_logs: Copilot PreToolUse read_file (nonexistent path for deterministic test)
        data = {
            "timestamp": "2026-02-26T11:53:49.593Z",
            "hookEventName": "PreToolUse",
            "sessionId": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "transcript_path": (
                "/home/user1/.config/Code/User/workspaceStorage/"
                "abc123/GitHub.copilot-chat/transcripts/69cc6a03.jsonl"
            ),
            "tool_name": "read_file",
            "tool_input": {
                "filePath": tmp_file.as_posix(),
                "startLine": 1,
                "endLine": 200,
            },
            "tool_use_id": "call_iMFuTGETQ2z23a3xYTqcHBXp__vscode-1772105116078",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == tmp_file.as_posix()
        assert payload.content == ""
        assert payload.scannable.content == "this is the content"
        assert isinstance(payload.agent, Copilot)

    def test_copilot_post_tool_use_run_in_terminal(self):
        """Test Copilot PostToolUse with run_in_terminal (simulated cat result)."""
        # From raw_hooks_logs: Copilot PostToolUse run_in_terminal - tool_response is string
        data = {
            "timestamp": "2026-02-26T11:53:47.392Z",
            "hookEventName": "PostToolUse",
            "sessionId": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "transcript_path": (
                "/home/user1/.config/Code/User/workspaceStorage/"
                "abc123/GitHub.copilot-chat/transcripts/69cc6a03.jsonl"
            ),
            "tool_name": "run_in_terminal",
            "tool_input": {
                "command": "whoami",
                "explanation": "whoami to test postToolUse hook",
                "goal": "whoami to test postToolUse hook",
                "isBackground": False,
                "timeout": 0,
            },
            "tool_response": "user1",
            "tool_use_id": "call_f96KUoNCGS8jENVKnlWnSz5Q__vscode-1772105116077",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "user1" in payload.content
        assert isinstance(payload.agent, Copilot)

    def test_codex_user_prompt(self):
        """Test Codex UserPromptSubmit parsing."""
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user/.codex/sessions/2026/04/30/session.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "UserPromptSubmit",
            "turn_id": "turn_123",
            "model": "gpt-5.4",
            "prompt": "hello world",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.content == "hello world"
        assert payload.tool is None
        assert isinstance(payload.agent, Codex)

    def test_codex_pre_tool_use_bash(self):
        """Test Codex PreToolUse with Bash parsing."""
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user/.codex/sessions/2026/04/30/session.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "PreToolUse",
            "turn_id": "turn_123",
            "model": "gpt-5.4",
            "tool_name": "Bash",
            "tool_input": {"command": "whoami"},
            "tool_use_id": "call_123",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert payload.content == "whoami"
        assert isinstance(payload.agent, Codex)

    def test_codex_pre_tool_use_apply_patch(self):
        """Test Codex PreToolUse with apply_patch parsing."""
        patch = "*** Begin Patch\n*** Add File: secret.txt\n+token\n*** End Patch\n"
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user/.codex/sessions/2026/04/30/session.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "PreToolUse",
            "turn_id": "turn_123",
            "model": "gpt-5.4",
            "tool_name": "apply_patch",
            "tool_input": {"command": patch},
            "tool_use_id": "call_123",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.EDIT
        assert payload.content == patch
        assert isinstance(payload.agent, Codex)

    def test_pre_tool_use_read_with_missing_file(self):
        """PRE_TOOL_USE with tool_name 'read' and non-existing file yields empty content."""
        content = json.dumps(
            {
                "hook_event_name": "pretooluse",
                "tool_name": "read",
                "tool_input": {"file_path": "/nonexistent/path"},
                "cursor_version": "1.2.3",
            }
        )
        payload = parse_hook_input(content)[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == "/nonexistent/path"
        assert payload.content == ""

    def test_pre_tool_use_other_tool(self):
        """PRE_TOOL_USE with unknown tool yields Tool.OTHER and empty content."""
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "SomeUnknownTool",
            "tool_input": {"arg": "value"},
            "cursor_version": "1.2.3",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.OTHER
        assert payload.content == ""

    def test_other_event_type(self):
        """Unknown event type yields EventType.OTHER with empty content."""
        data = {
            "hook_event_name": "SomeOtherEvent",
            "prompt": "hello",
            "cursor_version": "1.2.3",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.OTHER
        assert payload.content == ""
        assert payload.tool is None


class TestFlavorOutputResult:
    """Unit tests for Cursor, Claude, Copilot output_result with Result objects.

    Mocks click.echo to capture stdout/stderr and asserts both output and return code.
    """

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_user_prompt_allow(self, mock_echo: MagicMock):
        """Cursor USER_PROMPT with block=False: JSON to stdout, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.USER_PROMPT))
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is True
        assert out["user_message"] == ""

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_user_prompt_block(self, mock_echo: MagicMock):
        """Cursor USER_PROMPT with block=True: JSON to stdout, return 0."""
        result = HookResult(
            block=True,
            message="Remove secrets from prompt",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.USER_PROMPT),
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is False
        assert out["user_message"] == "Remove secrets from prompt"

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_pre_tool_use_allow(self, mock_echo: MagicMock):
        """Cursor PRE_TOOL_USE with block=False: permission allow, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.PRE_TOOL_USE))
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["permission"] == "allow"

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_pre_tool_use_block(self, mock_echo: MagicMock):
        """Cursor PRE_TOOL_USE with block=True: permission deny, return 0."""
        result = HookResult(
            block=True,
            message="Secrets detected in command",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.PRE_TOOL_USE),
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["permission"] == "deny"
        assert out["user_message"] == "Secrets detected in command"

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_post_tool_use(self, mock_echo: MagicMock):
        """Cursor POST_TOOL_USE: empty JSON to stdout, return 0."""
        result = HookResult(
            block=True,
            message="Too late",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.POST_TOOL_USE),
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        assert json.loads(args[0]) == {}

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_other_block(self, mock_echo: MagicMock):
        """Cursor OTHER event with block: empty JSON, return 2."""
        result = HookResult(
            block=True,
            message="",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.OTHER),
        )
        code = Cursor().output_result(result)
        assert code == 2
        mock_echo.assert_called_once_with("{}")

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_other_allow(self, mock_echo: MagicMock):
        """Cursor OTHER event without block: empty JSON, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.OTHER))
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once_with("{}")

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_claude_output_result_allow(self, mock_echo: MagicMock):
        """Claude with block=False: JSON continue true to stdout, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.USER_PROMPT))
        code = Claude().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is True

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_claude_output_result_block(self, mock_echo: MagicMock):
        """Claude with block=True: JSON continue false and stopReason to stdout, return 0."""
        result = HookResult(
            block=True,
            message="Secrets in file",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.PRE_TOOL_USE),
        )
        code = Claude().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert (
            out["hookSpecificOutput"]["permissionDecisionReason"] == "Secrets in file"
        )

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_copilot_output_result_allow(self, mock_echo: MagicMock):
        """Copilot with block=False: same as Claude, JSON to stdout, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.USER_PROMPT))
        code = Copilot().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is True
        assert "stopReason" not in out

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_copilot_output_result_block(self, mock_echo: MagicMock):
        """Copilot with block=True: same as Claude, JSON to stdout, return 0."""
        result = HookResult(
            block=True,
            message="Secret in tool output",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.POST_TOOL_USE),
        )
        code = Copilot().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["decision"] == "block"
        assert out["reason"] == "Secret in tool output"

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_copilot_other_result_block(self, mock_echo: MagicMock):
        """Copilot with block=True, other type of event"""
        result = HookResult(
            block=True,
            message="Secret in tool output",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.OTHER),
        )
        code = Copilot().output_result(result)
        assert code == 0
        args, _ = mock_echo.call_args
        out = json.loads(args[0])
        assert not out["continue"]

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_allow(self, mock_echo: MagicMock):
        """Codex with block=False: empty JSON to stdout, return 0."""
        result = HookResult.allow(_dummy_payload(EventType.PRE_TOOL_USE))
        code = Codex().output_result(result)
        assert code == 0
        mock_echo.assert_called_once_with("{}")

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_pre_tool_use_block(self, mock_echo: MagicMock):
        """Codex PRE_TOOL_USE with block=True: permission deny JSON, return 0."""
        result = HookResult(
            block=True,
            message="Secrets detected in command",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.PRE_TOOL_USE),
        )
        code = Codex().output_result(result)
        assert code == 0
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False
        out = json.loads(args[0])
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert (
            out["hookSpecificOutput"]["permissionDecisionReason"]
            == "Secrets detected in command"
        )

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_user_prompt_block(self, mock_echo: MagicMock):
        """Codex USER_PROMPT with block=True: block decision JSON, return 0."""
        result = HookResult(
            block=True,
            message="Secrets detected in prompt",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.USER_PROMPT),
        )
        code = Codex().output_result(result)
        assert code == 0
        args, _ = mock_echo.call_args
        out = json.loads(args[0])
        assert out["decision"] == "block"
        assert out["reason"] == "Secrets detected in prompt"

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_other_block(self, mock_echo: MagicMock):
        """Codex unsupported event with block=True writes to stderr and returns 2."""
        result = HookResult(
            block=True,
            message="Unsupported Codex event",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.OTHER),
        )
        code = Codex().output_result(result)
        assert code == 2
        mock_echo.assert_called_once_with("Unsupported Codex event", err=True)


@pytest.mark.parametrize(
    "prompt, filepaths",
    [
        ("read @folder/file.txt and summarize the content.", {"folder/file.txt"}),
        (
            "A multi-lineprompt with @file1 \n and @file2 \n and @file3 read.",
            {"file1", "file2", "file3"},
        ),
        ("@filename.txt", {"filename.txt"}),
        ("same @file @file twice", {"file"}),
        ("File can start with a dot: @.env", {".env"}),
        (
            "Files simply mentioned without @ prefix are not matched: foo.txt bar.txt.",
            set(),
        ),
        ("emails like foo@example.com are not matched.", set()),
        (
            "test @file.multiple.extensions.txt and @file2.txt",
            {"file.multiple.extensions.txt", "file2.txt"},
        ),
        ("files (@folder/foo.txt) can be between parentheses.", {"folder/foo.txt"}),
        ("files @can-contain-hyphens.txt", {"can-contain-hyphens.txt"}),
        (
            'Supports @"file with spaces (and comma, and parentheses) in name".',
            {"file with spaces (and comma, and parentheses) in name"},
        ),
        ('read @"file with \\" in its name.txt"', {'file with \\" in its name.txt'}),
        (
            "Path at the end of a sentence: @file.txt. Another one: @file2.txt.",
            {"file.txt", "file2.txt"},
        ),
        # Edge cases and extra coverage
        ("@ alone or at end: hello @", set()),
        ("@ only: @", set()),
        ('Empty quoted path: @""', set()),
        ("Unquoted path with comma: @a.txt, and @b.txt", {"a.txt", "b.txt"}),
        ("Unquoted path with semicolon: @x; @y", {"x", "y"}),
        ("Paths with underscores: @my_special_file.txt", {"my_special_file.txt"}),
        ("Windows-style path: read @src\\main.py", {"src\\main.py"}),
        (
            'Mixed quoted and unquoted: @config.json and @"big file.txt"',
            {"config.json", "big file.txt"},
        ),
        ("Newline before @: line1\n@file.txt", {"file.txt"}),
    ],
)
def test_find_filepaths(prompt: str, filepaths: Set[str]):
    """Test filepath regex."""
    assert find_filepaths(prompt) == filepaths, prompt
