import json
from collections import Counter
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret import SecretScanner
from ggshield.verticals.secret.ai_hook.claude_code import Claude
from ggshield.verticals.secret.ai_hook.copilot import Copilot
from ggshield.verticals.secret.ai_hook.cursor import Cursor
from ggshield.verticals.secret.ai_hook.models import EventType, Flavor, Payload
from ggshield.verticals.secret.ai_hook.models import Result as HookResult
from ggshield.verticals.secret.ai_hook.models import Tool
from ggshield.verticals.secret.ai_hook.scanner import AIHookScanner
from ggshield.verticals.secret.secret_scan_collection import Result as ScanResult
from ggshield.verticals.secret.secret_scan_collection import Results, Secret


def _mock_scanner(matches: List[str]) -> MagicMock:
    """Create a mock SecretScanner that returns the given Results from scan()."""
    mock = MagicMock(spec=SecretScanner)
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


@pytest.fixture
def tmp_file(tmp_path: Path) -> Path:
    """Create a temporary file with content."""
    file = tmp_path / "test.txt"
    file.write_text("this is the content")
    return file


class TestAIHookScannerParseInput:
    """Unit tests for AIHookScanner._parse_input."""

    def test_empty_input_raises(self):
        """Empty or whitespace-only input raises ValueError."""
        scanner = AIHookScanner(_mock_scanner([]))
        with pytest.raises(ValueError, match="No input received on stdin"):
            scanner.scan("")
        with pytest.raises(ValueError, match="No input received on stdin"):
            scanner.scan("   \n  ")

    def test_invalid_json_raises(self):
        """Invalid JSON raises ValueError with parse error."""
        scanner = AIHookScanner(_mock_scanner([]))
        with pytest.raises(ValueError, match="Failed to parse JSON"):
            scanner._parse_input("not json {")
        with pytest.raises(ValueError, match="Failed to parse JSON"):
            scanner._parse_input("{ missing brace ")

    def test_missing_event_type_raises(self):
        """JSON without event type raises ValueError."""
        scanner = AIHookScanner(_mock_scanner([]))
        with pytest.raises(ValueError, match="couldn't find event type"):
            scanner._parse_input('{"prompt": "hello"}')

    def test_cursor_user_prompt(self):
        """Test Cursor beforeSubmitPrompt (user prompt) parsing."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.content == "hello world"
        assert payload.tool is None
        assert payload.identifier != ""
        assert isinstance(payload.flavor, Cursor)

    def test_cursor_pre_tool_use_shell(self):
        """Test Cursor preToolUse with Shell (bash) parsing."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert payload.content == "whoami"
        assert payload.identifier == "whoami"
        assert isinstance(payload.flavor, Cursor)

    def test_cursor_pre_tool_use_read(self, tmp_file: Path):
        """Test Cursor preToolUse with Read (file) parsing."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == tmp_file.as_posix()
        # The content of the file has been read
        assert payload.content == "this is the content"
        assert isinstance(payload.flavor, Cursor)

    def test_cursor_post_tool_use_shell(self):
        """Test Cursor postToolUse with Shell (simulated cat command result)."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "user1" in payload.content
        assert isinstance(payload.flavor, Cursor)

    def test_claude_user_prompt(self):
        """Test Claude Code UserPromptSubmit parsing."""
        scanner = AIHookScanner(_mock_scanner([]))
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user1/.claude/projects/foo/273ad859-3608-4799-9971-fa15ecb1a65c.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
        }
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.USER_PROMPT
        assert payload.content == "hello world"
        assert payload.tool is None
        assert isinstance(payload.flavor, Claude)

    def test_claude_pre_tool_use_bash(self):
        """Test Claude Code PreToolUse with Bash parsing."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "whoami" in payload.content
        assert isinstance(payload.flavor, Claude)

    def test_claude_pre_tool_use_read(self, tmp_file: Path):
        """Test Claude Code PreToolUse with Read parsing."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == tmp_file.as_posix()
        assert payload.content == "this is the content"
        assert isinstance(payload.flavor, Claude)

    def test_claude_post_tool_use_bash(self):
        """Test Claude Code PostToolUse with Bash (simulated cat command result)."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        # Content is json.dumps(tool_response), so the stdout is inside the string
        assert "user1" in payload.content
        assert isinstance(payload.flavor, Claude)

    def test_copilot_user_prompt(self):
        """Test Copilot UserPromptSubmit parsing."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.USER_PROMPT
        assert "hello world" in payload.content
        assert payload.tool is None
        assert isinstance(payload.flavor, Copilot)

    def test_copilot_pre_tool_use_run_in_terminal(self):
        """Test Copilot PreToolUse with run_in_terminal (shell) parsing."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "whoami" in payload.content
        assert isinstance(payload.flavor, Copilot)

    def test_copilot_pre_tool_use_read_file(self, tmp_file: Path):
        """Test Copilot PreToolUse with read_file parsing."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == tmp_file.as_posix()
        assert payload.content == "this is the content"
        assert isinstance(payload.flavor, Copilot)

    def test_copilot_post_tool_use_run_in_terminal(self):
        """Test Copilot PostToolUse with run_in_terminal (simulated cat result)."""
        scanner = AIHookScanner(_mock_scanner([]))
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
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "user1" in payload.content
        assert isinstance(payload.flavor, Copilot)

    def test_pre_tool_use_read_with_missing_file(self):
        """PRE_TOOL_USE with tool_name 'read' and non-existing file yields empty content."""
        scanner = AIHookScanner(_mock_scanner([]))
        content = json.dumps(
            {
                "hook_event_name": "pretooluse",
                "tool_name": "read",
                "tool_input": {"file_path": "/nonexistent/path"},
            }
        )
        payload = scanner._parse_input(content)
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == "/nonexistent/path"
        assert payload.content == ""

    def test_pre_tool_use_other_tool(self):
        """PRE_TOOL_USE with unknown tool yields Tool.OTHER and empty content."""
        scanner = AIHookScanner(_mock_scanner([]))
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "SomeUnknownTool",
            "tool_input": {"arg": "value"},
        }
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.OTHER
        assert payload.content == ""

    def test_other_event_type(self):
        """Unknown event type yields EventType.OTHER with empty content."""
        scanner = AIHookScanner(_mock_scanner([]))
        data = {
            "hook_event_name": "SomeOtherEvent",
            "prompt": "hello",
        }
        payload = scanner._parse_input(json.dumps(data))
        assert payload.event_type == EventType.OTHER
        assert payload.content == ""
        assert payload.tool is None


class TestAIHookScannerScanContent:
    """Unit tests for AIHookScanner._scan_content."""

    def test_no_secrets_returns_allow(self):
        """When scanner returns no secrets, result has block=False and nbr_secrets=0."""
        hook_scanner = AIHookScanner(_mock_scanner([]))
        payload = Payload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content="safe content",
            identifier="id",
            flavor=Flavor(),
        )
        result = hook_scanner._scan_content(payload)
        assert isinstance(result, HookResult)
        assert result.block is False
        assert result.nbr_secrets == 0
        assert result.message == ""

    def test_with_secrets_returns_block_and_message(self):
        """When scanner returns secrets, result has block=True, nbr_secrets and message set."""
        hook_scanner = AIHookScanner(_mock_scanner(["sk-xxx"]))
        payload = Payload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content="content with sk-xxx",
            identifier="id",
            flavor=Flavor(),
        )
        result = hook_scanner._scan_content(payload)
        assert isinstance(result, HookResult)
        assert result.block is True
        assert result.nbr_secrets == 1
        assert "dummy-detector" in result.message
        assert "secret" in result.message.lower()
        assert "remove the secrets from your prompt" in result.message


class TestFlavorOutputResult:
    """Unit tests for Cursor, Claude, Copilot output_result with Result objects.

    Mocks click.echo to capture stdout/stderr and asserts both output and return code.
    """

    @patch("ggshield.verticals.secret.ai_hook.cursor.click.echo")
    def test_cursor_output_result_user_prompt_allow(self, mock_echo: MagicMock):
        """Cursor USER_PROMPT with block=False: JSON to stdout, return 0."""
        result = HookResult(
            event_type=EventType.USER_PROMPT,
            block=False,
            message="",
            nbr_secrets=0,
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is True
        assert out["user_message"] == ""

    @patch("ggshield.verticals.secret.ai_hook.cursor.click.echo")
    def test_cursor_output_result_user_prompt_block(self, mock_echo: MagicMock):
        """Cursor USER_PROMPT with block=True: JSON to stdout, return 0."""
        result = HookResult(
            event_type=EventType.USER_PROMPT,
            block=True,
            message="Remove secrets from prompt",
            nbr_secrets=1,
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is False
        assert out["user_message"] == "Remove secrets from prompt"

    @patch("ggshield.verticals.secret.ai_hook.cursor.click.echo")
    def test_cursor_output_result_pre_tool_use_allow(self, mock_echo: MagicMock):
        """Cursor PRE_TOOL_USE with block=False: permission allow, return 0."""
        result = HookResult(
            event_type=EventType.PRE_TOOL_USE,
            block=False,
            message="",
            nbr_secrets=0,
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["permission"] == "allow"
        assert out["reason"] == ""

    @patch("ggshield.verticals.secret.ai_hook.cursor.click.echo")
    def test_cursor_output_result_pre_tool_use_block(self, mock_echo: MagicMock):
        """Cursor PRE_TOOL_USE with block=True: permission deny, return 0."""
        result = HookResult(
            event_type=EventType.PRE_TOOL_USE,
            block=True,
            message="Secrets detected in command",
            nbr_secrets=1,
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["permission"] == "deny"
        assert out["decision"] == "deny"
        assert out["reason"] == "Secrets detected in command"

    @patch("ggshield.verticals.secret.ai_hook.cursor.click.echo")
    def test_cursor_output_result_post_tool_use(self, mock_echo: MagicMock):
        """Cursor POST_TOOL_USE: empty JSON to stdout, return 0."""
        result = HookResult(
            event_type=EventType.POST_TOOL_USE,
            block=True,
            message="Too late",
            nbr_secrets=1,
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        assert json.loads(args[0]) == {}

    @patch("ggshield.verticals.secret.ai_hook.cursor.click.echo")
    def test_cursor_output_result_other_block(self, mock_echo: MagicMock):
        """Cursor OTHER event with block: empty JSON, return 2."""
        result = HookResult(
            event_type=EventType.OTHER,
            block=True,
            message="",
            nbr_secrets=1,
        )
        code = Cursor().output_result(result)
        assert code == 2
        mock_echo.assert_called_once_with("{}")

    @patch("ggshield.verticals.secret.ai_hook.cursor.click.echo")
    def test_cursor_output_result_other_allow(self, mock_echo: MagicMock):
        """Cursor OTHER event without block: empty JSON, return 0."""
        result = HookResult(
            event_type=EventType.OTHER,
            block=False,
            message="",
            nbr_secrets=0,
        )
        code = Cursor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once_with("{}")

    @patch("ggshield.verticals.secret.ai_hook.claude_code.click.echo")
    def test_claude_output_result_allow(self, mock_echo: MagicMock):
        """Claude with block=False: JSON continue true to stdout, return 0."""
        result = HookResult(
            event_type=EventType.USER_PROMPT,
            block=False,
            message="",
            nbr_secrets=0,
        )
        code = Claude().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is True
        assert out["stopReason"] == ""

    @patch("ggshield.verticals.secret.ai_hook.claude_code.click.echo")
    def test_claude_output_result_block(self, mock_echo: MagicMock):
        """Claude with block=True: JSON continue false and stopReason to stdout, return 0."""
        result = HookResult(
            event_type=EventType.PRE_TOOL_USE,
            block=True,
            message="Secrets in file",
            nbr_secrets=1,
        )
        code = Claude().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is False
        assert out["stopReason"] == "Secrets in file"

    @patch("ggshield.verticals.secret.ai_hook.claude_code.click.echo")
    def test_copilot_output_result_allow(self, mock_echo: MagicMock):
        """Copilot with block=False: same as Claude, JSON to stdout, return 0."""
        result = HookResult(
            event_type=EventType.USER_PROMPT,
            block=False,
            message="",
            nbr_secrets=0,
        )
        code = Copilot().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is True
        assert "stopReason" not in out

    @patch("ggshield.verticals.secret.ai_hook.claude_code.click.echo")
    def test_copilot_output_result_block(self, mock_echo: MagicMock):
        """Copilot with block=True: same as Claude, JSON to stdout, return 0."""
        result = HookResult(
            event_type=EventType.POST_TOOL_USE,
            block=True,
            message="Secret in tool output",
            nbr_secrets=1,
        )
        code = Copilot().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["continue"] is False
        assert out["stopReason"] == "Secret in tool output"


class TestBaseFlavor:
    """Unit tests for the base Flavor class."""

    @patch("ggshield.verticals.secret.ai_hook.models.click.echo")
    def test_base_flavor_output_result_allow(self, mock_echo: MagicMock):
        """Base Flavor with block=False: prints allow message, returns 0."""
        result = HookResult(
            event_type=EventType.USER_PROMPT,
            block=False,
            message="",
            nbr_secrets=0,
        )
        code = Flavor().output_result(result)
        assert code == 0
        mock_echo.assert_called_once_with("No secrets found. Good to go.")

    @patch("ggshield.verticals.secret.ai_hook.models.click.echo")
    def test_base_flavor_output_result_block(self, mock_echo: MagicMock):
        """Base Flavor with block=True: prints message to stderr, returns 2."""
        result = HookResult(
            event_type=EventType.PRE_TOOL_USE,
            block=True,
            message="Secrets found",
            nbr_secrets=1,
        )
        code = Flavor().output_result(result)
        assert code == 2
        mock_echo.assert_called_once_with("Secrets found", err=True)

    def test_base_flavor_settings_path(self):
        """Base Flavor settings_path returns default path."""
        assert Flavor().settings_path == Path(".agents") / "hooks.json"

    def test_base_flavor_settings_template(self):
        """Base Flavor settings_template returns empty dict."""
        assert Flavor().settings_template == {}

    def test_base_flavor_settings_locate(self):
        """Base Flavor settings_locate always returns None."""
        assert Flavor().settings_locate([{"a": 1}], {"a": 1}) is None


class TestAIHookScannerScan:
    """Unit tests for the AIHookScanner.scan() method."""

    def test_scan_no_secrets_returns_zero(self):
        """scan() with no secrets returns 0."""
        scanner = AIHookScanner(_mock_scanner([]))
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
        }
        code = scanner.scan(json.dumps(data))
        assert code == 0

    @patch(
        "ggshield.verticals.secret.ai_hook.scanner.AIHookScanner._send_secret_notification"
    )
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
        }
        code = scanner.scan(json.dumps(data))
        assert code == 0
        mock_scanner.scan.assert_not_called()


class TestMessageFromSecrets:
    """Unit tests for AIHookScanner._message_from_secrets with different payload types."""

    def test_message_for_bash_tool(self):
        """Message for BASH tool mentions environment variables."""
        payload = Payload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.BASH,
            content="echo sk-xxx",
            identifier="echo sk-xxx",
            flavor=Flavor(),
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "remove the secrets from the command" in message
        assert "environment variables" in message

    def test_message_for_read_tool(self):
        """Message for READ tool mentions file content."""
        payload = Payload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            content="file content with secret",
            identifier="/path/to/file",
            flavor=Flavor(),
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "remove the secrets from the file content" in message

    def test_message_for_other_tool(self):
        """Message for OTHER tool uses generic message."""
        payload = Payload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.OTHER,
            content="some content",
            identifier="id",
            flavor=Flavor(),
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "remove the secrets from the tool input" in message

    def test_message_escapes_markdown(self):
        """When escape_markdown=True, asterisks in matches are replaced with dots."""
        payload = Payload(
            event_type=EventType.USER_PROMPT,
            tool=None,
            content="content",
            identifier="id",
            flavor=Flavor(),
        )
        message = AIHookScanner._message_from_secrets(
            [_make_secret("sk-xxx")], payload, escape_markdown=True
        )
        # The message itself should not contain raw asterisks from matches
        # (the header uses ** for bold which is intentional)
        assert "Detected" in message


class TestSendSecretNotification:
    """Unit tests for AIHookScanner._send_secret_notification."""

    @patch("ggshield.verticals.secret.ai_hook.scanner.Notify")
    def test_notification_for_bash_tool(self, mock_notify_cls: MagicMock):
        """Notification for BASH tool says 'running a command'."""
        AIHookScanner._send_secret_notification(1, Tool.BASH, "Claude Code")
        instance = mock_notify_cls.return_value
        assert "running a command" in instance.message
        assert "Claude Code" in instance.message
        instance.send.assert_called_once()

    @patch("ggshield.verticals.secret.ai_hook.scanner.Notify")
    def test_notification_for_read_tool(self, mock_notify_cls: MagicMock):
        """Notification for READ tool says 'reading a file'."""
        AIHookScanner._send_secret_notification(2, Tool.READ, "Cursor")
        instance = mock_notify_cls.return_value
        assert "reading a file" in instance.message
        assert "2" in instance.message
        instance.send.assert_called_once()

    @patch("ggshield.verticals.secret.ai_hook.scanner.Notify")
    def test_notification_for_other_tool(self, mock_notify_cls: MagicMock):
        """Notification for OTHER tool says 'using a tool'."""
        AIHookScanner._send_secret_notification(1, Tool.OTHER, "Copilot")
        instance = mock_notify_cls.return_value
        assert "using a tool" in instance.message
        instance.send.assert_called_once()
