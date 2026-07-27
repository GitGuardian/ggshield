import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import List, Optional, Set
from unittest.mock import MagicMock, patch

import pytest
from pygitguardian import GGClient
from pygitguardian.models import MCPActivityResponse

from ggshield.core.scan import ScanContext, ScanMode
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.ai.agents import Agent, Claude, Codex, Copilot, Cursor, VSCode
from ggshield.verticals.ai.hooks import (
    AIHookScanner,
    build_agent_headers,
    find_filepaths,
    has_already_been_seen,
    parse_hook_input,
)
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


def _make_secret(
    match_str: str = "***",
    known_secret: bool = False,
    incident_url: Optional[str] = None,
):
    """Minimal Secret for tests; _message_from_secrets only uses
    detector_display_name, validity, matches[].match, known_secret and
    incident_url."""
    mock_match = MagicMock()
    mock_match.match = match_str
    return Secret(
        detector_display_name="dummy-detector",
        detector_name="dummy-detector",
        detector_group_name=None,
        documentation_url=None,
        validity="valid",
        known_secret=known_secret,
        incident_url=incident_url,
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
        assert "remove the secret from your prompt" in result.message


class TestHasAlreadyBeenSeen:
    def test_first_call_is_not_duplicate(self):
        assert has_already_been_seen('{"hook_event_name": "PreToolUse"}') is False

    def test_second_identical_call_is_duplicate(self):
        content = '{"hook_event_name": "PreToolUse"}'
        assert has_already_been_seen(content) is False
        assert has_already_been_seen(content) is True

    def test_different_payload_is_not_duplicate(self):
        assert has_already_been_seen('{"prompt": "a"}') is False
        assert has_already_been_seen('{"prompt": "b"}') is False


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

    def test_scan_duplicate_payload_skips_processing(self):
        """scan() with the same payload as the previous call returns early."""
        mock_scanner = _mock_scanner([])
        scanner = AIHookScanner(mock_scanner)
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "cursor_version": "1.2.3",
        }
        content = json.dumps(data)
        assert scanner.scan(content) == 0
        assert scanner.scan(content) == 0
        mock_scanner.scan.assert_called_once()

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
        result = mock_notify.call_args[0][0]
        assert result.nbr_secrets == 1  # nbr_secrets
        assert result.payload.tool == Tool.BASH  # tool

    @patch("ggshield.verticals.ai.hooks._send_desktop_notification")
    def test_scan_post_tool_use_notifier_failure_still_emits_block(
        self, mock_send: MagicMock
    ):
        """GIVEN a PostToolUse leak whose desktop notifier backend crashes
        (e.g. BinaryNotFound on a Homebrew install)
        WHEN scan() runs
        THEN the notifier failure is swallowed and scan() still returns the
        normal block exit code instead of crashing the hook (NHI-1681)."""
        mock_send.side_effect = Exception("BinaryNotFound")
        scanner = AIHookScanner(_mock_scanner(["sk-xxx"]))
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo sk-xxx"},
            "tool_response": {"stdout": "sk-xxx\n"},
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "session_id": "427ae0c5-0862-4e14-aa2c-12fad909c323",
        }
        # Must not raise, and must still reach output_result() (exit 0 for Claude).
        assert scanner.scan(json.dumps(data)) == 0
        mock_send.assert_called_once()

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


class TestBuildAgentHeaders:
    """``build_agent_headers`` names the calling AI agent via GGShield-Agent-Name.

    Machine identity (Machine-Id / Machine-Username) is sent on every scan by
    ``ScanContext.get_http_headers`` — only the agent name is hook-specific.
    """

    AGENT_HEADER = "GGShield-Agent-Name"

    def test_returns_only_the_agent_name(self):
        """Just the unprefixed Agent-Name; machine identity is not the hook's job."""
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"command": "echo hello"},
            "cwd": "/home/alice/project",
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "session_id": "427ae0c5-0862-4e14-aa2c-12fad909c323",
        }
        assert build_agent_headers(json.dumps(data)) == {"Agent-Name": "claude-code"}

    def test_agent_name_flows_through_scan_context(self):
        """Fed into ScanContext, the agent name becomes a prefixed header beside mode."""
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"command": "echo hello"},
            "transcript_path": "/home/user/.claude/projects/foo/session.jsonl",
            "session_id": "s",
        }
        ctx = ScanContext(
            scan_mode=ScanMode.AI_HOOK,
            command_path="ggshield secret scan ai-hook",
            extra_headers=build_agent_headers(json.dumps(data)),
        )
        http_headers = ctx.get_http_headers()
        assert http_headers[self.AGENT_HEADER] == "claude-code"
        assert http_headers["mode"] == ScanMode.AI_HOOK.value

    def test_unrecognized_agent_degrades_to_empty_dict(self):
        """An unrecognized agent yields no headers rather than raising (fail-open)."""
        assert build_agent_headers(json.dumps({"hook_event_name": "PreToolUse"})) == {}

    def test_invalid_json_degrades_to_empty_dict(self):
        """Malformed input yields no headers rather than raising (fail-open)."""
        assert build_agent_headers("not json") == {}


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

    def _payload(
        self,
        event_type: EventType = EventType.PRE_TOOL_USE,
        tool: Optional[Tool] = None,
        identifier: str = "id",
    ) -> HookPayload:
        return HookPayload(
            event_type=event_type,
            tool=tool,
            content="content",
            identifier=identifier,
            agent=Cursor(),
            raw={},
        )

    def test_message_for_user_prompt(self):
        """USER_PROMPT: header/status/remediation talk about the prompt."""
        payload = self._payload(event_type=EventType.USER_PROMPT, tool=None)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "in your prompt" in message
        assert "The prompt was not sent to the agent" in message
        assert "remove the secret from your prompt" in message

    def test_escape_markdown_adds_hard_breaks(self):
        """escape_markdown turns single newlines into markdown hard breaks
        (two trailing spaces) so agents rendering the message as markdown
        (e.g. Codex) don't collapse them into spaces. Blank-line separations
        are left untouched."""
        payload = self._payload(event_type=EventType.PRE_TOOL_USE, tool=Tool.BASH)
        secrets = [_make_secret("sk-xxx")]
        plain = AIHookScanner._message_from_secrets(secrets, payload)
        markdown = AIHookScanner._message_from_secrets(
            secrets, payload, escape_markdown=True
        )
        assert "  \n" not in plain
        lines = markdown.split("\n")
        for line, next_line in zip(lines, lines[1:]):
            if line and next_line:
                assert line.endswith("  ")
            else:
                assert not line.endswith(" ")
        # Blank-line separations are preserved
        assert markdown.count("\n\n") == plain.count("\n\n")

    def test_message_for_pre_bash_tool(self):
        """PRE_TOOL_USE + Bash: header names the command, nothing ran yet,
        remediation points to a secrets manager."""
        payload = self._payload(event_type=EventType.PRE_TOOL_USE, tool=Tool.BASH)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "in the command" in message
        assert "was not executed" in message
        assert "secrets manager" in message

    def test_message_for_pre_read_tool(self):
        """PRE_TOOL_USE + Read: header names the file, remediation says to
        avoid sharing it."""
        payload = self._payload(
            event_type=EventType.PRE_TOOL_USE,
            tool=Tool.READ,
            identifier="/path/to/file",
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "/path/to/file" in message
        assert "avoid sharing this file" in message

    @pytest.mark.parametrize("tool", [Tool.MCP, Tool.OTHER, None])
    def test_message_for_pre_other_tools(self, tool: Optional[Tool]):
        """PRE_TOOL_USE with MCP, an unrecognized tool, or no tool at all
        share the same generic "tool input" wording."""
        payload = self._payload(event_type=EventType.PRE_TOOL_USE, tool=tool)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "in the tool input" in message

    def test_other_event_type_falls_back_to_pre_generic_wording(self):
        """An unrecognized event type (EventType.OTHER) falls back to the
        same wording as PRE_TOOL_USE with a non-Bash/Read tool."""
        payload = self._payload(event_type=EventType.OTHER, tool=None)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "in the tool input" in message
        assert "was not executed" in message

    @pytest.mark.parametrize("tool", [Tool.BASH, Tool.READ, Tool.MCP, Tool.OTHER])
    def test_message_for_post_tool_use_says_leaked(self, tool: Tool):
        """POST_TOOL_USE, regardless of tool: the secret already reached the
        agent, so status says it's compromised and remediation says to revoke
        it (today it is tool-first, which wrongly gives Read/MCP the
        pre-leak "not leaked yet" wording on POST_TOOL_USE)."""
        payload = self._payload(
            event_type=EventType.POST_TOOL_USE, tool=tool, identifier="/path/to/file"
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "Consider it compromised" in message
        assert "revoke the secret" in message

    def test_message_for_post_read_names_the_file(self):
        """POST_TOOL_USE + Read: header names the file, like its PreToolUse
        counterpart, instead of falling back to "in the tool output"."""
        payload = self._payload(
            event_type=EventType.POST_TOOL_USE,
            tool=Tool.READ,
            identifier="/path/to/file",
        )
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "/path/to/file" in message

    def test_message_escapes_markdown(self):
        """When escape_markdown=True, asterisks in matches are replaced with a bullet."""
        payload = self._payload(event_type=EventType.USER_PROMPT, tool=None)
        message = AIHookScanner._message_from_secrets(
            [_make_secret("sk-xxx")], payload, escape_markdown=True
        )
        # The message itself should not contain raw asterisks from matches
        # (the header and bolded validity use ** for bold which is intentional)
        assert "Detected" in message
        assert "•" in message

    def test_message_includes_incident_url_for_known_secret(self):
        """A known secret with an incident_url gets an "Incident URL" line,
        and, on POST_TOOL_USE, a step to resolve the incident."""
        payload = self._payload(event_type=EventType.POST_TOOL_USE, tool=Tool.BASH)
        secret = _make_secret(
            "sk-xxx",
            known_secret=True,
            incident_url="https://dashboard.gitguardian.com/incidents/1",
        )
        message = AIHookScanner._message_from_secrets([secret], payload)
        assert "Incident URL: https://dashboard.gitguardian.com/incidents/1" in message
        assert (
            "resolve the incident linked above in your GitGuardian dashboard."
            in message
        )

    def test_message_omits_incident_url_for_unknown_secret(self):
        """A secret that isn't a known incident never gets an Incident URL line."""
        payload = self._payload(event_type=EventType.POST_TOOL_USE, tool=Tool.BASH)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert "Incident URL" not in message

    def test_message_omits_resolve_incident_step_before_leak(self):
        """A known secret with an incident_url still gets its Incident URL
        line on PRE_TOOL_USE, but no "resolve the incident" step since
        nothing has leaked yet."""
        payload = self._payload(event_type=EventType.PRE_TOOL_USE, tool=Tool.BASH)
        secret = _make_secret(
            "sk-xxx",
            known_secret=True,
            incident_url="https://dashboard.gitguardian.com/incidents/1",
        )
        message = AIHookScanner._message_from_secrets([secret], payload)
        assert "Incident URL: https://dashboard.gitguardian.com/incidents/1" in message
        assert "resolve the incident" not in message

    def test_resolve_incident_step_is_plural_for_several_known_secrets(self):
        """When more than one secret is a known incident, the remediation
        step uses the plural "incidents"."""
        payload = self._payload(event_type=EventType.POST_TOOL_USE, tool=Tool.BASH)
        message = AIHookScanner._message_from_secrets(
            [
                _make_secret(
                    "sk-xxx",
                    known_secret=True,
                    incident_url="https://dashboard.gitguardian.com/incidents/1",
                ),
                _make_secret(
                    "sk-yyy",
                    known_secret=True,
                    incident_url="https://dashboard.gitguardian.com/incidents/2",
                ),
            ],
            payload,
        )
        assert (
            "resolve the incidents linked above in your GitGuardian dashboard."
            in message
        )

    @pytest.mark.parametrize(
        "event_type, tool",
        [
            (EventType.USER_PROMPT, None),
            (EventType.PRE_TOOL_USE, Tool.BASH),
            (EventType.PRE_TOOL_USE, Tool.READ),
            (EventType.PRE_TOOL_USE, Tool.OTHER),
            (EventType.POST_TOOL_USE, Tool.BASH),
            (EventType.POST_TOOL_USE, Tool.READ),
            (EventType.POST_TOOL_USE, Tool.OTHER),
            (EventType.OTHER, None),
        ],
    )
    def test_message_always_ends_with_false_positive_block(
        self, event_type: EventType, tool: Optional[Tool]
    ):
        """Every message ends with the false positive escape hatch."""
        payload = self._payload(event_type=event_type, tool=tool)
        message = AIHookScanner._message_from_secrets([_make_secret("sk-xxx")], payload)
        assert message.endswith("    ggshield secret ignore --last-found")
        assert "> If this is a false positive, run:" in message

    def test_false_positive_block_is_plural_for_several_secrets(self):
        """The false positive block says "these are false positives" when
        several secrets were detected."""
        payload = self._payload(event_type=EventType.USER_PROMPT, tool=None)
        message = AIHookScanner._message_from_secrets(
            [_make_secret("sk-xxx"), _make_secret("sk-yyy")], payload
        )
        assert "> If these are false positives, run:" in message


class TestSendSecretNotification:
    """Unit tests for AIHookScanner._send_secret_notification."""

    def _result(
        self,
        nbr_secrets: int,
        tool: Tool,
        agent: Agent,
        input_command: str = "",
    ) -> HookResult:
        return HookResult(
            block=True,
            message="",
            nbr_secrets=nbr_secrets,
            payload=HookPayload(
                event_type=EventType.PRE_TOOL_USE,
                tool=tool,
                content="",
                identifier="",
                agent=agent,
                raw={"tool_input": {"command": input_command}},
            ),
        )

    @patch("ggshield.verticals.ai.hooks._send_desktop_notification")
    def test_notification_for_bash_tool(self, mock_send: MagicMock):
        """GIVEN a BASH-tool result
        WHEN a notification is sent
        THEN the message says 'running the command' with the command run."""
        AIHookScanner._send_secret_notification(
            self._result(1, Tool.BASH, Claude(), input_command="ls -la")
        )
        title, message = mock_send.call_args.args
        assert title == "ggshield - Secrets Detected"
        assert "running the command `ls -la`" in message
        assert "Claude Code" in message

    @patch("ggshield.verticals.ai.hooks._send_desktop_notification")
    def test_notification_for_read_tool(self, mock_send: MagicMock):
        """GIVEN a READ-tool result
        WHEN a notification is sent
        THEN the message says 'reading a file'."""
        AIHookScanner._send_secret_notification(self._result(2, Tool.READ, Cursor()))
        _, message = mock_send.call_args.args
        assert "reading a file" in message
        assert "2" in message

    @patch("ggshield.verticals.ai.hooks._send_desktop_notification")
    def test_notification_for_other_tool(self, mock_send: MagicMock):
        """GIVEN an OTHER-tool result
        WHEN a notification is sent
        THEN the message says 'using a tool'."""
        AIHookScanner._send_secret_notification(self._result(1, Tool.OTHER, Copilot()))
        _, message = mock_send.call_args.args
        assert "using a tool" in message

    @patch("ggshield.verticals.ai.hooks._send_desktop_notification")
    def test_notification_failure_never_propagates(self, mock_send: MagicMock):
        """GIVEN a notifier backend that raises (e.g. missing binary on brew)
        WHEN a notification is sent
        THEN the exception is swallowed so the hook can still emit its block."""
        mock_send.side_effect = Exception("BinaryNotFound")
        # Must not raise.
        AIHookScanner._send_secret_notification(self._result(1, Tool.BASH, Claude()))


class TestSendDesktopNotification:
    """Unit tests for the per-OS desktop notification backends."""

    @patch("ggshield.verticals.ai.hooks.subprocess.run")
    @patch("ggshield.verticals.ai.hooks.sys")
    def test_macos_uses_native_osascript(
        self, mock_sys: MagicMock, mock_run: MagicMock
    ):
        """GIVEN a macOS host
        WHEN a desktop notification is sent
        THEN it invokes osascript, passing the (attacker-influenced) message
        and title as run-handler arguments rather than interpolating them into
        the AppleScript source (injection- and unicode-safe)."""
        mock_sys.platform = "darwin"
        from ggshield.verticals.ai.hooks import _send_desktop_notification

        # Message with a quote, an accent, an emoji and a tab: none of these
        # can be represented in an AppleScript string literal, so they must be
        # passed as arguments, not baked into the script.
        message = 'ran `café` ❤\ttell app "Finder"'
        _send_desktop_notification("ggshield - Secrets Detected", message)

        args = mock_run.call_args.args[0]
        assert args[0] == "osascript"
        # Uses a run handler reading from argv; the raw strings are the trailing
        # argv items, never embedded in any "-e" script fragment.
        assert "on run argv" in args
        assert message == args[-2]
        assert "ggshield - Secrets Detected" == args[-1]
        script_fragments = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
        assert not any(message in frag for frag in script_fragments)
        # A hook must never hang or read stdin from a notifier subprocess.
        assert mock_run.call_args.kwargs["stdin"] is subprocess.DEVNULL
        assert mock_run.call_args.kwargs["timeout"] == 10

    @patch("ggshield.verticals.ai.hooks.Notify")
    @patch("ggshield.verticals.ai.hooks.sys")
    def test_non_macos_uses_notifypy(
        self, mock_sys: MagicMock, mock_notify_cls: MagicMock
    ):
        """GIVEN a non-macOS host
        WHEN a desktop notification is sent
        THEN it uses the notifypy backend."""
        mock_sys.platform = "linux"
        from ggshield.verticals.ai.hooks import _send_desktop_notification

        _send_desktop_notification("title", "message")

        instance = mock_notify_cls.return_value
        assert instance.title == "title"
        assert instance.message == "message"
        assert instance.application_name == "ggshield"
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

    def test_claude_pre_tool_use_mcp_scans_tool_input(self):
        """PreToolUse for an MCP tool scans the serialized tool_input, so a
        secret in an MCP argument is caught before it reaches the server
        (NHI-1845)."""
        data = {
            "session_id": "3b7ae0c5-0862-4e14-aa2c-12fad909c323",
            "transcript_path": "/home/user1/.claude/projects/foo/3b7ae0c5.jsonl",
            "cwd": "/home/user1/foo",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__github__create_issue",
            "tool_input": {"title": "creds", "body": "token=abc123secret"},
            "tool_use_id": "toolu_01WabtWJpzf1ZJ8GJ3JfQEmq",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.MCP
        assert not payload.empty
        assert "token=abc123secret" in payload.scannable.content
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

    def test_vscode_user_prompt(self):
        """Test VSCode UserPromptSubmit parsing."""
        data = {
            "timestamp": "2026-02-26T11:28:53.112Z",
            "hook_event_name": "UserPromptSubmit",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
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
        assert isinstance(payload.agent, VSCode)

    def test_vscode_pre_tool_use_run_in_terminal(self):
        """Test VSCode PreToolUse with run_in_terminal (shell) parsing."""
        # From raw_hooks_logs: Copilot PreToolUse run_in_terminal
        data = {
            "timestamp": "2026-02-26T11:29:05.821Z",
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
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
        assert isinstance(payload.agent, VSCode)

    def test_vscode_pre_tool_use_read_file(self, tmp_file: Path):
        """Test VSCode PreToolUse with read_file parsing."""
        # From raw_hooks_logs: VSCode PreToolUse read_file (nonexistent path for deterministic test)
        data = {
            "timestamp": "2026-02-26T11:53:49.593Z",
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
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
        assert isinstance(payload.agent, VSCode)

    def test_vscode_post_tool_use_run_in_terminal(self):
        """Test VSCode PostToolUse with run_in_terminal (simulated cat result)."""
        # From raw_hooks_logs: Copilot PostToolUse run_in_terminal - tool_response is string
        data = {
            "timestamp": "2026-02-26T11:53:47.392Z",
            "hook_event_name": "PostToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
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
        assert isinstance(payload.agent, VSCode)

    def test_copilot_user_prompt(self):
        """Test Copilot UserPromptSubmit parsing."""
        data = {
            "timestamp": "2026-02-26T11:28:53.112Z",
            "hook_event_name": "UserPromptSubmit",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "prompt": "hello world",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert "hello world" in payload.content
        assert payload.tool is None
        assert isinstance(payload.agent, Copilot)

    def test_copilot_user_prompt_submitted(self):
        """Test Copilot CLI's own 'userPromptSubmitted' event name parsing.

        Copilot CLI fires the camelCase ``userPromptSubmitted`` event, not the
        VS Code ``UserPromptSubmit``. If it is not mapped, the prompt content is
        never scanned and ggshield wrongly returns ``{"continue": true}``.
        """
        data = {
            "timestamp": "2026-02-26T11:28:53.112Z",
            "hook_event_name": "userPromptSubmitted",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "prompt": "hello world",
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.USER_PROMPT
        assert "hello world" in payload.content
        assert payload.tool is None
        assert isinstance(payload.agent, Copilot)

    def test_copilot_pre_tool_use_run_in_terminal(self):
        """Test Copilot PreToolUse with bash parsing."""
        data = {
            "timestamp": "2026-02-26T11:29:05.821Z",
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "tool_name": "bash",
            "tool_input": {
                "command": "whoami",
                "description": "whoami to test preToolUse hook",
                "mode": "sync",
                "initial_wait": 30,
            },
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
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "tool_name": "view",
            "tool_input": {
                "path": tmp_file.as_posix(),
            },
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == tmp_file.as_posix()
        assert payload.content == ""
        assert payload.scannable.content == "this is the content"
        assert isinstance(payload.agent, Copilot)

    def test_copilot_pre_tool_use_mcp(self):
        """Test Copilot PreToolUse is correctly overriden to MCP."""
        data = {
            "timestamp": "2026-02-26T11:53:49.593Z",
            "hook_event_name": "PreToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "tool_name": "server-name-tool-name",
            "tool_input": {
                "arg": "value",
            },
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.MCP
        # Copilot MCP tools are only identified in post_process_payload, after
        # content selection, so the catch-all input scan must cover them.
        assert not payload.empty
        assert "value" in payload.scannable.content
        assert isinstance(payload.agent, Copilot)

    def test_copilot_post_tool_use_run_in_terminal(self):
        """Test Copilot PostToolUse with bash"""
        data = {
            "timestamp": "2026-02-26T11:53:47.392Z",
            "hook_event_name": "PostToolUse",
            "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
            "tool_name": "run_in_terminal",
            "tool_input": {
                "command": "whoami",
                "explanation": "whoami to test postToolUse hook",
                "goal": "whoami to test postToolUse hook",
                "isBackground": False,
                "timeout": 0,
            },
            "tool_result": {
                "result_type": "success",
                "text_result_for_llm": "user1\n<exited with exit code 0>",
            },
            "cwd": "/home/user1/foo",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.BASH
        assert "user1" in payload.content
        assert isinstance(payload.agent, Copilot)

    def test_raises_if_no_agent_recognized(self):
        """Test raises if no agent can be recognized."""
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
        }
        with pytest.raises(ValueError, match="Unrecognized agent"):
            parse_hook_input(json.dumps(data))

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

    def test_codex_pre_tool_use_null_transcript_path(self):
        """Codex sends transcript_path as a present-but-null field; detection
        must fall back to turn_id instead of crashing on the None."""
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": None,
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

    def test_post_tool_use_read_extracts_file_path(self):
        """POST_TOOL_USE with tool_name 'Read' extracts the file path from
        tool_input into the identifier, mirroring the PRE_TOOL_USE Read
        branch, so the block message can name the file instead of falling
        back to a content hash."""
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/nonexistent/path"},
            "tool_response": {"content": "file content"},
            "cursor_version": "1.2.3",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.POST_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == "/nonexistent/path"

    def test_pre_tool_use_other_tool(self):
        """PRE_TOOL_USE with unknown tool yields Tool.OTHER and scans its input."""
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "SomeUnknownTool",
            "tool_input": {"arg": "value"},
            "cursor_version": "1.2.3",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.OTHER
        assert "value" in payload.content

    def test_pre_tool_use_other_tool_empty_input(self):
        """PRE_TOOL_USE with an unknown tool and no input stays empty, so no
        scan API call is made."""
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "SomeUnknownTool",
            "tool_input": {},
            "cursor_version": "1.2.3",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.tool == Tool.OTHER
        assert payload.empty

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

    def test_windows_GetContent_parsing(self):
        """The Bash/Get-Content tool use in windows is parsed as file reading."""
        # This case was observed with Codex on Windows.
        data = {
            "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
            "transcript_path": "/home/user/.codex/sessions/2026/04/30/session.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "PreToolUse",
            "turn_id": "turn_123",
            "model": "gpt-5.4",
            "tool_name": "Bash",
            "tool_input": {"command": "Get-Content README.md"},
            "tool_use_id": "call_123",
        }
        payload = parse_hook_input(json.dumps(data))[0]
        assert payload.event_type == EventType.PRE_TOOL_USE
        assert payload.tool == Tool.READ
        assert payload.identifier == "README.md"


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

    @patch("ggshield.verticals.ai.agents.copilot.click.echo")
    def test_copilot_output_result_user_prompt_block(self, mock_echo: MagicMock):
        """Copilot USER_PROMPT block: {"decision": "block"} to stdout, return 0.

        Copilot CLI cancels a prompt before it reaches the model when the hook
        emits ``{"decision": "block"}`` (verified against Copilot CLI 1.0.61).
        The inherited ``{"continue": false}`` is ignored on the prompt event.
        """
        result = HookResult(
            block=True,
            message="Remove secrets from prompt",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.USER_PROMPT),
        )
        code = Copilot().output_result(result)
        assert code == 0
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert kwargs.get("err", False) is False  # stdout (default)
        out = json.loads(args[0])
        assert out["decision"] == "block"
        assert out["reason"] == "Remove secrets from prompt"

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
        # No systemMessage: Codex already shows the decision reason, setting
        # both would display the message twice.
        assert "systemMessage" not in out
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
        assert "systemMessage" not in out
        assert out["decision"] == "block"
        assert out["reason"] == "Secrets detected in prompt"

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_post_tool_use_block(self, mock_echo: MagicMock):
        """Codex POST_TOOL_USE with block=True: block decision JSON, return 0."""
        result = HookResult(
            block=True,
            message="Secrets detected in tool output",
            nbr_secrets=1,
            payload=_dummy_payload(EventType.POST_TOOL_USE),
        )
        code = Codex().output_result(result)
        assert code == 0
        args, _ = mock_echo.call_args
        out = json.loads(args[0])
        assert "systemMessage" not in out
        assert out["decision"] == "block"
        assert out["reason"] == "Secrets detected in tool output"

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

    @patch("ggshield.verticals.ai.agents.claude_code.click.echo")
    def test_claude_output_result_allow_with_warning(self, mock_echo: MagicMock):
        """Claude allow with a warning: continue true plus systemMessage."""
        result = HookResult.allow_with_warning(
            _dummy_payload(EventType.PRE_TOOL_USE), "could not scan"
        )
        code = Claude().output_result(result)
        assert code == 0
        out = json.loads(mock_echo.call_args[0][0])
        assert out["continue"] is True
        assert out["systemMessage"] == "could not scan"

    @patch("ggshield.verticals.ai.agents.vscode.click.echo")
    def test_vscode_output_result_allow_with_warning(self, mock_echo: MagicMock):
        """VSCode allow with a warning: continue true plus systemMessage."""
        result = HookResult.allow_with_warning(
            _dummy_payload(EventType.PRE_TOOL_USE), "could not scan"
        )
        code = VSCode().output_result(result)
        assert code == 0
        out = json.loads(mock_echo.call_args[0][0])
        assert out["continue"] is True
        assert out["systemMessage"] == "could not scan"

    @patch("ggshield.verticals.ai.agents.codex.click.echo")
    def test_codex_output_result_allow_with_warning(self, mock_echo: MagicMock):
        """Codex allow with a warning: systemMessage only, no block fields."""
        result = HookResult.allow_with_warning(
            _dummy_payload(EventType.PRE_TOOL_USE), "could not scan"
        )
        code = Codex().output_result(result)
        assert code == 0
        out = json.loads(mock_echo.call_args[0][0])
        assert out == {"systemMessage": "could not scan"}

    @patch("ggshield.verticals.ai.agents.cursor.click.echo")
    def test_cursor_output_result_allow_with_warning(self, mock_echo: MagicMock):
        """Cursor allow with a warning: permission allow plus user_message."""
        result = HookResult.allow_with_warning(
            _dummy_payload(EventType.PRE_TOOL_USE), "could not scan"
        )
        code = Cursor().output_result(result)
        assert code == 0
        out = json.loads(mock_echo.call_args[0][0])
        assert out["permission"] == "allow"
        assert out["user_message"] == "could not scan"


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
        ("File can contain underscores: @my_file.txt", {"my_file.txt"}),
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
        ("VSCode-style path: @file:file.txt", {"file.txt"}),
        ("VSCode-style path with folder: @file:folder/file.txt", {"folder/file.txt"}),
    ],
)
def test_find_filepaths(prompt: str, filepaths: Set[str]):
    """Test filepath regex."""
    assert find_filepaths(prompt) == filepaths, prompt
