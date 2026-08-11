import json
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner
from pygitguardian.config import DOCUMENT_SIZE_THRESHOLD_BYTES, MAXIMUM_PAYLOAD_SIZE
from pygitguardian.models import (
    AgentInfo,
    AIDiscovery,
    MCPConfiguration,
    MCPServer,
    MultiScanResult,
    ScanResult,
    UserInfo,
)

from ggshield.__main__ import cli
from ggshield.cmd.ai.discover import print_summary
from ggshield.core.errors import APIKeyCheckError, MissingTokenError
from ggshield.verticals.ai.agent_activity.orchestrator import AgentActivityReport
from ggshield.verticals.ai.history import BackfillReport
from ggshield.verticals.ai.models import Scope, Transport


CLAUDE_PRE_TOOL_USE_PAYLOAD = json.dumps(
    {
        "session_id": "abc123",
        "transcript_path": "/home/user/.claude/projects/p/transcript.jsonl",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hello"},
    }
)


SOURCE_UUID = "11111111-1111-1111-1111-111111111111"


def _scanning_client() -> MagicMock:
    """A client that answers every scan with "nothing found"."""
    client = MagicMock()
    # The verdict cache key is built from both, and joins them as strings.
    client.base_uri = "https://api.example.com"
    client.api_key = "some-api-key"
    client.maximum_payload_size = MAXIMUM_PAYLOAD_SIZE
    client.secret_scan_preferences.maximum_document_size = DOCUMENT_SIZE_THRESHOLD_BYTES
    client.secret_scan_preferences.maximum_documents_per_scan = 20

    def multi_content_scan(documents, *args, **kwargs):
        result = MultiScanResult(
            [
                ScanResult(policy_break_count=0, policy_breaks=[], policies=[])
                for _ in documents
            ]
        )
        result.status_code = 200
        return result

    client.multi_content_scan.side_effect = multi_content_scan
    return client


def _user():
    return UserInfo(
        hostname="host", username="user", machine_id="mid", user_email="u@e.com"
    )


def _discovery(
    servers: Optional[List[MCPServer]] = None,
    agents: Optional[List[AgentInfo]] = None,
):
    return AIDiscovery(
        user=_user(),
        servers=servers or [],
        agents=agents or [],
        discovery_duration=0.1,
    )


def _server(
    name: str,
    display_name: Optional[str] = None,
    configurations: Optional[List[MCPConfiguration]] = None,
) -> MCPServer:
    return MCPServer(
        name=name,
        display_name=display_name,
        configurations=configurations or [],
    )


def _config(
    name: str = "srv",
    agent: str = "cursor",
    scope: Scope = Scope.PROJECT,
    project: Optional[str] = None,
) -> MCPConfiguration:
    return MCPConfiguration(
        name=name,
        agent=agent,
        scope=scope,
        transport=Transport.STDIO,
        project=project,
    )


# ---------------------------------------------------------------------------
# ggshield secret scan ai-hook
# ---------------------------------------------------------------------------


class TestAiHookCmd:
    @patch("ggshield.cmd.secret.scan.ai_hook.AIHookScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.SecretScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.create_client_from_config")
    def test_valid_json_stdin(
        self,
        mock_client: MagicMock,
        mock_scanner_cls: MagicMock,
        mock_hook_scanner: MagicMock,
    ):
        instance = mock_hook_scanner.return_value
        instance.scan.return_value = 0

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["secret", "scan", "ai-hook"],
            input='{"event_type": "test"}',
        )

        assert result.exit_code == 0
        instance.scan.assert_called_once()

    @patch("ggshield.cmd.secret.scan.ai_hook.AIHookScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.SecretScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.create_client_from_config")
    def test_empty_stdin_returns_error(
        self,
        mock_client: MagicMock,
        mock_scanner_cls: MagicMock,
        mock_hook_scanner: MagicMock,
    ):
        instance = mock_hook_scanner.return_value
        instance.scan.side_effect = ValueError("Empty input")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["secret", "scan", "ai-hook"],
            input="",
        )

        assert result.exit_code == 1

    @patch("ggshield.cmd.secret.scan.ai_hook.AIHookScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.SecretScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.create_client_from_config")
    def test_large_stdin_does_not_crash(
        self,
        mock_client: MagicMock,
        mock_scanner_cls: MagicMock,
        mock_hook_scanner: MagicMock,
    ):
        instance = mock_hook_scanner.return_value
        instance.scan.return_value = 0

        runner = CliRunner()
        large_input = "x" * (1024 * 1024)  # 1 MB
        result = runner.invoke(
            cli,
            ["secret", "scan", "ai-hook"],
            input=large_input,
        )

        assert result.exit_code == 0

    @patch(
        "ggshield.cmd.secret.scan.ai_hook.create_client_from_config",
        side_effect=MissingTokenError(instance="https://dashboard.gitguardian.com"),
    )
    def test_auth_failure_fails_open_with_warning(self, mock_client: MagicMock):
        """An auth failure must not crash the hook: it allows the action and
        warns the user through the agent."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["secret", "scan", "ai-hook"],
            input=CLAUDE_PRE_TOOL_USE_PAYLOAD,
        )

        assert result.exit_code == 0
        # These fail-open cases print a warning to stderr; on click < 8.2 the default
        # runner merges it into stdout, so parse the JSON payload from the last line.
        response = json.loads(result.stdout.strip().splitlines()[-1])
        assert response["continue"] is True
        assert "NOT scanned" in response["systemMessage"]
        assert "ggshield auth login" in response["systemMessage"]

    @patch("ggshield.cmd.secret.scan.ai_hook.AIHookScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.SecretScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.create_client_from_config")
    def test_scan_failure_fails_open_with_warning(
        self,
        mock_client: MagicMock,
        mock_scanner_cls: MagicMock,
        mock_hook_scanner: MagicMock,
    ):
        """A scan-time failure (e.g. network error) also fails open."""
        instance = mock_hook_scanner.return_value
        instance.scan.side_effect = ConnectionError("server unreachable")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["secret", "scan", "ai-hook"],
            input=CLAUDE_PRE_TOOL_USE_PAYLOAD,
        )

        assert result.exit_code == 0
        # These fail-open cases print a warning to stderr; on click < 8.2 the default
        # runner merges it into stdout, so parse the JSON payload from the last line.
        response = json.loads(result.stdout.strip().splitlines()[-1])
        assert response["continue"] is True
        assert "NOT scanned" in response["systemMessage"]

    @patch(
        "ggshield.cmd.secret.scan.ai_hook.create_client_from_config",
        side_effect=MissingTokenError(instance="https://dashboard.gitguardian.com"),
    )
    def test_auth_failure_with_unknown_agent_returns_error(
        self, mock_client: MagicMock
    ):
        """If the agent cannot be identified we cannot emit a well-formed
        response; exit 1 (a non-blocking error for most agents)."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["secret", "scan", "ai-hook"],
            input='{"hook_event_name": "PreToolUse"}',
        )

        assert result.exit_code == 1

    @pytest.mark.parametrize(
        "extra_args",
        [[], ["--source-uuid", SOURCE_UUID]],
        ids=["without-source-uuid", "with-source-uuid"],
    )
    @patch("ggshield.verticals.secret.secret_scanner.check_client_api_key")
    @patch("ggshield.cmd.secret.scan.ai_hook.create_client_from_config")
    def test_hook_never_creates_incidents(
        self,
        mock_create_client: MagicMock,
        mock_check_api_key: MagicMock,
        extra_args: List[str],
    ):
        """GIVEN `secret.source_uuid` set (or not)
        WHEN the AI hook scans
        THEN it scans with multi_content_scan and all_secrets, and never creates
        incidents: scan_and_create_incidents cannot request all_secrets, which the
        hook needs to block on an already-known secret."""
        client = _scanning_client()
        mock_create_client.return_value = client

        result = CliRunner().invoke(
            cli,
            ["secret", "scan", "ai-hook", *extra_args],
            input=CLAUDE_PRE_TOOL_USE_PAYLOAD,
        )

        assert result.exit_code == 0
        client.scan_and_create_incidents.assert_not_called()
        client.multi_content_scan.assert_called_once()
        assert client.multi_content_scan.call_args.kwargs["all_secrets"] is True

    @patch("ggshield.cmd.secret.scan.ai_hook.AIHookScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.SecretScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.create_client_from_config")
    def test_only_source_uuid_is_dropped_from_the_config(
        self,
        mock_client: MagicMock,
        mock_scanner_cls: MagicMock,
        mock_hook_scanner: MagicMock,
    ):
        """GIVEN a config where source_uuid sits next to other secret settings
        WHEN the AI hook builds its scanner
        THEN only source_uuid is cleared; every other setting reaches the scanner."""
        mock_hook_scanner.return_value.scan.return_value = 0

        result = CliRunner().invoke(
            cli,
            [
                "secret",
                "scan",
                "ai-hook",
                "--source-uuid",
                SOURCE_UUID,
                "--ignore-known-secrets",
                "--all-secrets",
                "--show-secrets",
                "--filename-only",
                "--banlist-detector",
                "dummy_detector",
            ],
            input=CLAUDE_PRE_TOOL_USE_PAYLOAD,
        )

        assert result.exit_code == 0
        secret_config = mock_scanner_cls.call_args.kwargs["secret_config"]
        assert secret_config.source_uuid is None
        assert secret_config.ignore_known_secrets is True
        assert secret_config.all_secrets is True
        assert secret_config.show_secrets is True
        assert secret_config.filename_only is True
        assert secret_config.ignored_detectors == {"dummy_detector"}


# ---------------------------------------------------------------------------
# ggshield ai discover
# ---------------------------------------------------------------------------


class TestDiscoverCmd:
    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.create_client_from_config")
    @patch(
        "ggshield.cmd.ai.discover.submit_ai_discovery",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.save_discovery_cache")
    def test_default_output(
        self,
        mock_save: MagicMock,
        mock_submit: MagicMock,
        mock_client: MagicMock,
        mock_discover: MagicMock,
    ):
        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover"])

        assert result.exit_code == 0
        mock_discover.assert_called_once()

    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.create_client_from_config")
    @patch(
        "ggshield.cmd.ai.discover.submit_ai_discovery",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.save_discovery_cache")
    def test_json_flag(
        self,
        mock_save: MagicMock,
        mock_submit: MagicMock,
        mock_client: MagicMock,
        mock_discover: MagicMock,
    ):
        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.stdout)
        assert "agents" in parsed
        assert "servers" in parsed

    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
        return_value=_discovery(),
    )
    @patch(
        "ggshield.cmd.ai.discover.create_client_from_config",
        side_effect=APIKeyCheckError("https://api.gitguardian.com", "no key"),
    )
    def test_auth_failure_shows_warning(
        self, mock_client: MagicMock, mock_discover: MagicMock
    ):
        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover"])

        assert result.exit_code == 0
        assert "Skipping upload" in result.output or "warning" in result.output.lower()

    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.create_client_from_config")
    @patch(
        "ggshield.cmd.ai.discover.submit_ai_discovery",
        side_effect=RuntimeError("API error"),
    )
    def test_api_submission_failure_shows_warning(
        self, mock_submit: MagicMock, mock_client: MagicMock, mock_discover: MagicMock
    ):
        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover"])

        assert result.exit_code == 0
        assert "Could not upload" in result.output or "warning" in result.output.lower()

    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
    )
    @patch("ggshield.cmd.ai.discover.create_client_from_config")
    @patch(
        "ggshield.cmd.ai.discover.submit_ai_discovery",
    )
    @patch("ggshield.cmd.ai.discover.save_discovery_cache")
    def test_text_output_with_servers(
        self,
        mock_save: MagicMock,
        mock_submit: MagicMock,
        mock_client: MagicMock,
        mock_discover: MagicMock,
    ):
        """Text output lists agents, servers, scope, and projects."""
        discovery = _discovery(
            servers=[
                _server(
                    "my-mcp",
                    display_name="My MCP",
                    configurations=[
                        _config(
                            agent="cursor",
                            scope=Scope.USER,
                        ),
                    ],
                ),
                _server(
                    "project-srv",
                    display_name="Project Server",
                    configurations=[
                        _config(
                            agent="cursor",
                            scope=Scope.PROJECT,
                            project="/home/user/project-a",
                        ),
                        _config(
                            agent="cursor",
                            scope=Scope.PROJECT,
                            project="/home/user/project-b",
                        ),
                    ],
                ),
            ]
        )
        mock_discover.return_value = discovery
        mock_submit.return_value = discovery

        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover"])

        assert result.exit_code == 0
        assert "Cursor" in result.output
        assert "2 servers" in result.output
        assert "My MCP" in result.output
        assert "Scope: user" in result.output
        assert "Project Server" in result.output
        assert "Scope: project" in result.output
        assert "/home/user/project-a" in result.output
        assert "/home/user/project-b" in result.output

    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
    )
    @patch("ggshield.cmd.ai.discover.create_client_from_config")
    @patch(
        "ggshield.cmd.ai.discover.submit_ai_discovery",
    )
    @patch("ggshield.cmd.ai.discover.save_discovery_cache")
    def test_json_output_with_servers(
        self,
        mock_save: MagicMock,
        mock_submit: MagicMock,
        mock_client: MagicMock,
        mock_discover: MagicMock,
    ):
        """JSON output contains structured data for agents and servers."""
        discovery = _discovery(
            servers=[
                _server(
                    "my-mcp",
                    display_name="My MCP",
                    configurations=[
                        _config(agent="cursor", scope=Scope.USER),
                    ],
                ),
            ],
            agents=[AgentInfo(name="cursor", hooks_installed=True)],
        )
        mock_discover.return_value = discovery
        mock_submit.return_value = discovery

        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.stdout)
        assert parsed["agents"] == [{"name": "Cursor", "hooks_installed": True}]
        assert len(parsed["servers"]) == 1
        assert parsed["servers"][0]["name"] == "My MCP"
        assert parsed["servers"][0]["installed_globally"] is True

    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.create_client_from_config")
    @patch("ggshield.cmd.ai.discover.submit_ai_discovery")
    @patch("ggshield.cmd.ai.discover.save_discovery_cache")
    @patch(
        "ggshield.cmd.ai.discover.backfill_mcp_history",
        return_value=BackfillReport(parsed=3, ingested=3),
    )
    def test_history_flag_invokes_backfill_and_surfaces_summary(
        self,
        mock_backfill: MagicMock,
        mock_save: MagicMock,
        mock_submit: MagicMock,
        mock_client: MagicMock,
        mock_discover: MagicMock,
    ):
        discovery = _discovery(
            servers=[
                _server(
                    "my-mcp",
                    display_name="My MCP",
                    configurations=[
                        _config(agent="cursor", scope=Scope.USER),
                    ],
                ),
            ]
        )
        mock_submit.return_value = discovery

        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover", "--history"])

        assert result.exit_code == 0
        mock_backfill.assert_called_once()
        # Human-readable summary should reflect the parsed count.
        assert "3" in result.output and "MCP" in result.output

    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.create_client_from_config")
    @patch("ggshield.cmd.ai.discover.submit_ai_discovery")
    @patch("ggshield.cmd.ai.discover.save_discovery_cache")
    @patch("ggshield.cmd.ai.discover.backfill_mcp_history")
    def test_history_skipped_without_flag(
        self,
        mock_backfill: MagicMock,
        mock_save: MagicMock,
        mock_submit: MagicMock,
        mock_client: MagicMock,
        mock_discover: MagicMock,
    ):
        mock_submit.return_value = _discovery()

        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover"])

        assert result.exit_code == 0
        mock_backfill.assert_not_called()

    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.create_client_from_config")
    @patch(
        "ggshield.cmd.ai.discover.submit_ai_discovery",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.save_discovery_cache")
    @patch(
        "ggshield.cmd.ai.discover.backfill_mcp_history",
        return_value=BackfillReport(parsed=4, ingested=2, skipped=1),
    )
    def test_json_output_includes_history_block(
        self,
        mock_backfill: MagicMock,
        mock_save: MagicMock,
        mock_submit: MagicMock,
        mock_client: MagicMock,
        mock_discover: MagicMock,
    ):
        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover", "--json", "--history"])

        assert result.exit_code == 0
        parsed = json.loads(result.stdout)
        assert parsed["history"] == {
            "parsed": 4,
            "ingested": 2,
            "skipped": 1,
        }

    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.create_client_from_config")
    @patch("ggshield.cmd.ai.discover.submit_ai_discovery")
    @patch("ggshield.cmd.ai.discover.save_discovery_cache")
    @patch(
        "ggshield.cmd.ai.discover.collect_agent_activity",
        return_value=AgentActivityReport(parsed=7, ingested=7, failed_batches=0),
    )
    def test_activity_flag_collects_agent_activity(
        self,
        mock_collect: MagicMock,
        mock_save: MagicMock,
        mock_submit: MagicMock,
        mock_client: MagicMock,
        mock_discover: MagicMock,
    ):
        discovery = _discovery(
            servers=[
                _server(
                    "my-mcp",
                    display_name="My MCP",
                    configurations=[_config(agent="cursor", scope=Scope.USER)],
                )
            ]
        )
        mock_submit.return_value = discovery

        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover", "--activity"])
        assert result.exit_code == 0, result.output
        mock_collect.assert_called_once()
        assert "7" in result.output

    @patch(
        "ggshield.cmd.ai.discover.discover_ai_configuration",
        return_value=_discovery(),
    )
    @patch("ggshield.cmd.ai.discover.create_client_from_config")
    @patch("ggshield.cmd.ai.discover.submit_ai_discovery")
    @patch("ggshield.cmd.ai.discover.save_discovery_cache")
    @patch(
        "ggshield.cmd.ai.discover.collect_agent_activity",
        return_value=AgentActivityReport(parsed=10, ingested=8, failed_batches=2),
    )
    def test_agent_activity_surfaces_failed_batches(
        self,
        mock_collect: MagicMock,
        mock_save: MagicMock,
        mock_submit: MagicMock,
        mock_client: MagicMock,
        mock_discover: MagicMock,
    ):
        discovery = _discovery(
            servers=[
                _server(
                    "my-mcp",
                    display_name="My MCP",
                    configurations=[_config(agent="cursor", scope=Scope.USER)],
                )
            ]
        )
        mock_submit.return_value = discovery

        runner = CliRunner()
        result = runner.invoke(cli, ["ai", "discover", "--activity"])
        assert result.exit_code == 0, result.output
        assert "Failed batches: 2" in result.output


# ---------------------------------------------------------------------------
# print_summary (unit tests)
# ---------------------------------------------------------------------------


class TestPrintSummary:
    def test_empty_servers(self):
        """No servers: prints a 'no servers' message."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                _echo_summary_cmd,
                args=[],
                input=json.dumps({"agents": [], "servers": []}),
            )
        assert "No MCP servers discovered" in result.output

    def test_single_global_server(self):
        summary: Dict[str, Any] = {
            "agents": [{"name": "Cursor", "hooks_installed": True}],
            "servers": [
                {
                    "name": "my-server",
                    "installed_globally": True,
                    "projects": [],
                }
            ],
        }
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                _echo_summary_cmd, args=[], input=json.dumps(summary)
            )
        assert "1 server" in result.output
        assert "1 agent" in result.output
        assert "my-server" in result.output
        assert "Scope: user" in result.output
        assert "hooks installed" in result.output

    def test_agent_without_hooks_shows_no_hooks(self):
        summary: Dict[str, Any] = {
            "agents": [{"name": "Cursor", "hooks_installed": False}],
            "servers": [
                {
                    "name": "my-server",
                    "installed_globally": True,
                    "projects": [],
                }
            ],
        }
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                _echo_summary_cmd, args=[], input=json.dumps(summary)
            )
        assert "no hooks" in result.output

    def test_multiple_servers_with_projects(self):
        summary: Dict[str, Any] = {
            "agents": [
                {"name": "Cursor", "hooks_installed": True},
                {"name": "Claude Code", "hooks_installed": False},
            ],
            "servers": [
                {
                    "name": "server-a",
                    "installed_globally": False,
                    "projects": ["/path/to/proj1", "/path/to/proj2"],
                },
                {
                    "name": "server-b",
                    "installed_globally": True,
                    "projects": [],
                },
            ],
        }
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                _echo_summary_cmd, args=[], input=json.dumps(summary)
            )
        output = result.output
        assert "2 servers" in output
        assert "2 agents" in output
        assert "server-a" in output
        assert "server-b" in output
        assert "/path/to/proj1" in output
        assert "/path/to/proj2" in output
        assert "├─" in output
        assert "└─" in output

    def test_server_name_fallback(self):
        """Servers with missing name get 'unknown'."""
        summary: Dict[str, Any] = {
            "agents": [],
            "servers": [
                {
                    "installed_globally": False,
                    "projects": [],
                }
            ],
        }
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                _echo_summary_cmd, args=[], input=json.dumps(summary)
            )
        assert "unknown" in result.output


@click.command()
@click.pass_context
def _echo_summary_cmd(ctx: click.Context) -> None:
    """Helper command that reads a summary from stdin and prints it."""
    import sys

    data = json.load(sys.stdin)
    print_summary(data)
