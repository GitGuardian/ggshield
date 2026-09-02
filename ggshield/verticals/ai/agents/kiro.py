from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Literal, Optional, Tuple

import click
from pygitguardian.models import AIDiscovery, MCPActivityRequest

from ggshield.core.dirs import get_editor_user_data_dir, get_user_home_dir

from ..agent_activity.sources import JSONLActivitySource
from ..models import (
    Agent,
    EventType,
    HookPayload,
    HookResult,
    MCPConfiguration,
    ReadRange,
    Scope,
)


#: Every trigger Kiro can fire a command hook on, in both spellings: the CLI
#: writes them in camelCase, the IDE in PascalCase.
TRIGGERS = frozenset(
    {
        "userPromptSubmit",
        "UserPromptSubmit",
        "preToolUse",
        "PreToolUse",
        "postToolUse",
        "PostToolUse",
        "agentSpawn",
        "SessionStart",
        "stop",
        "Stop",
        "PreTaskExec",
        "PostTaskExec",
        "PostFileCreate",
        "PostFileSave",
        "PostFileDelete",
    }
)

#: Keys another assistant sends and Kiro never does. Several trigger names are
#: shared, so the event name alone would let Kiro claim their payloads. Junie
#: CLI is the reason `project_path` is here: it mirrors Claude Code's wire
#: protocol deliberately, which leaves it with no marker of its own either.
FOREIGN_KEYS = (
    "transcript_path",
    "cursor_version",
    "turn_id",
    "timestamp",
    "project_path",
)

#: Kiro compiles a hook's `matcher` as a regular expression and drops the hook
#: when it does not compile. A bare "*" is not a valid regex ("nothing to
#: repeat"), so it leaves a hook that exists, installs cleanly, and never runs.
ALL_TOOLS = ".*"

#: What the Kiro IDE prefixes an MCP tool call with. The CLI writes "@" instead.
MCP_PREFIX = "mcp_"


def _mangle_server_name(name: str) -> str:
    """Mangle a server name the way the Kiro IDE does in a tool name."""
    return "".join(char if char.isalnum() else "_" for char in name)


def _is_mcp_tool_name(raw_tool_name: str) -> bool:
    """Whether a tool name is one of Kiro's two MCP spellings."""
    return raw_tool_name.startswith(("@", MCP_PREFIX))


class KiroActivitySource(JSONLActivitySource):
    """Every Kiro session transcript line, shipped raw.

    Both surfaces append one JSON object per line to
    ~/.kiro/sessions/<workspace-hash>/sess_<uuid>/messages.jsonl (prompts,
    assistant turns, tool calls, tool results). The line is shipped verbatim;
    GitGuardian scans and strips secrets server-side before storing it.
    """

    kind = "5_session_transcript"

    def discover(self) -> Iterator[Path]:
        return iter(
            sorted(
                (get_user_home_dir() / ".kiro").glob("sessions/*/sess_*/messages.jsonl")
            )
        )


class Kiro(Agent):
    """Behavior specific to Amazon Kiro, both the IDE and the CLI.

    One adapter for two surfaces: they share the payload schema, the settings
    file, the session store and the exit-code contract, and differ only in the
    spelling of a few tool and trigger names, which are matched in both forms.
    """

    agent_activity_sources = [KiroActivitySource()]

    @property
    def name(self) -> str:
        return "kiro"

    @property
    def display_name(self) -> str:
        return "Kiro"

    @property
    def config_folder(self) -> Path:
        return get_user_home_dir() / ".kiro"

    def output_result(self, result: HookResult) -> int:
        """Kiro reads the exit code, and only the exit code.

        There is no JSON verdict protocol on either surface: 2 blocks and sends
        stderr to the model, anything else does not. Stdout on a zero exit is
        appended to the agent's context, which is not where a verdict belongs.
        """
        if result.block:
            # PostToolUse cannot be blocked (the tool has run) and neither can
            # the triggers that carry nothing to scan.
            if result.payload.event_type in (
                EventType.USER_PROMPT,
                EventType.PRE_TOOL_USE,
            ):
                click.echo(result.message, err=True)
                return 2
            return 0
        if result.warning:
            click.echo(result.warning, err=True)
        return 0

    def is_caller(self, hook_payload: Dict[str, Any]) -> bool:
        return hook_payload.get("hook_event_name") in TRIGGERS and not any(
            key in hook_payload for key in FOREIGN_KEYS
        )

    def read_range(self, tool_input: Dict[str, Any]) -> Optional[ReadRange]:
        """Kiro's `read_file` takes `offset`, the first line counted from zero,
        and `limit`, a number of lines. Measured against a numbered file:
        `offset` 49 with `limit` 11 returns lines 50 to 60.

        Claude spells the same two parameters, but counts `offset` from one, so
        the arms cannot be shared. A zero `offset` is a real read from the top
        rather than an absent one, hence the explicit None check.

        The CLI's own `fs_read` names its files under `operations` and carries
        no bounds we have seen, so it reads whole files and lands here with
        neither parameter.
        """
        offset = tool_input.get("offset")
        limit = tool_input.get("limit")
        first = offset + 1 if isinstance(offset, int) and offset >= 0 else 1
        if isinstance(limit, int) and limit > 0:
            return first, first + limit - 1
        return None if first == 1 else (first, None)

    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        # A directory of standalone files rather than one settings file, so
        # ggshield owns a file of its own instead of merging into the user's.
        return Path(".kiro") / "hooks" / "ggshield.json"

    def post_install_warning(self, mode: Literal["local", "global"]) -> Optional[str]:
        return (
            "Kiro loads hooks when a session starts: restart Kiro, or open a new "
            "chat, for these to take effect. The Kiro CLI reads this file in v3 "
            "mode only (kiro-cli --v3); older sessions take their hooks from the "
            "agent configuration instead."
        )

    @property
    def settings_template(self) -> Dict[str, Any]:
        def hook(name: str, trigger: str, **extra: Any) -> Dict[str, Any]:
            return {
                "name": name,
                "trigger": trigger,
                **extra,
                "action": {"type": "command", "command": "<COMMAND>"},
            }

        return {
            "version": "v1",
            "hooks": [
                # No matcher on the prompt trigger: there it filters on the
                # prompt text, and every prompt has to be scanned.
                hook("ggshield-prompt", "UserPromptSubmit"),
                hook("ggshield-pre-tool", "PreToolUse", matcher=ALL_TOOLS),
                hook("ggshield-post-tool", "PostToolUse", matcher=ALL_TOOLS),
            ],
        }

    def settings_locate(
        self, candidates: List[Dict[str, Any]], template: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        # One entry per trigger, and they all carry the same matcher, so the
        # trigger is what tells them apart.
        trigger = template.get("trigger")
        return next(
            (
                candidate
                for candidate in candidates
                if candidate.get("trigger") == trigger
            ),
            None,
        )

    @property
    def user_mcp_file(self) -> Path:
        return self.config_folder / "settings" / "mcp.json"

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".kiro" / "settings" / "mcp.json"

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        """Yield user-scoped servers, including the ones a power contributed.

        `kiro-cli mcp add` keeps the user's own servers under "mcpServers" and
        the ones installed powers bring under "powers", in the same file and the
        same shape. A power's server is as much a live MCP server as any other,
        so it is reported too.
        """
        yield from super()._get_user_mcp_configurations()
        if not (data := self._load_file(self.user_mcp_file)):
            return
        powers = data.get("powers")
        if not isinstance(powers, dict):
            return
        # One block for all of them, which is the shape observed, or one block
        # per power. A file that maps a power straight to a server definition,
        # with no block of its own, is not read: telling that apart from the
        # nested shape means guessing, and a guess here invents servers.
        if configurations := list(self._parse_servers_block(powers, Scope.USER, None)):
            yield from configurations
            return
        for entry in powers.values():
            if isinstance(entry, dict):
                yield from self._parse_servers_block(entry, Scope.USER, None)

    def discover_project_directories(self) -> Iterator[Path]:
        # The IDE is a VS Code fork and keeps the same workspace records.
        for file in get_editor_user_data_dir("Kiro").glob(
            "workspaceStorage/*/workspace.json"
        ):
            if (data := self._load_file(file)) and "folder" in data:
                path = Path(data["folder"].removeprefix("file://"))
                if path.is_dir():
                    yield path.resolve()

    def _split_mcp_tool_name(
        self, raw_tool_name: str, ai_config: Optional[AIDiscovery]
    ) -> Tuple[str, str]:
        """Split one of Kiro's two MCP tool-name spellings into server and tool.

        The CLI sends "@{server}/{tool}", which is unambiguous. The IDE sends
        "mcp_{server}_{tool}" with every non-alphanumeric character of the
        server name replaced by "_", so only a configured name tells the server
        apart from the tool; with none matching, the whole name is reported as
        the tool rather than split at a guess.
        """
        if raw_tool_name.startswith("@"):
            server_name, _, tool_name = raw_tool_name[1:].partition("/")
            return server_name, tool_name

        if raw_tool_name.startswith(MCP_PREFIX) and ai_config is not None:
            remainder = raw_tool_name.removeprefix(MCP_PREFIX)
            names = {
                configuration.name
                for server in ai_config.servers
                for configuration in server.configurations
                if configuration.agent == self.name
            }
            # Longest first: a server named "git" must not claim a call to one
            # named "github", whose mangled name starts with it.
            for name in sorted(names, key=len, reverse=True):
                prefix = f"{_mangle_server_name(name)}_"
                if remainder.startswith(prefix):
                    return name, remainder.removeprefix(prefix)

        return "", raw_tool_name

    def parse_mcp_activity(
        self, payload: HookPayload, ai_config: AIDiscovery
    ) -> MCPActivityRequest:
        raw_tool_name = payload.raw.get("tool_name", "")
        server_name, tool_name = self._split_mcp_tool_name(raw_tool_name, ai_config)
        return MCPActivityRequest(
            user=self._user_or_default(ai_config),
            tool=tool_name,
            server=server_name,
            agent=self.name,
            model="",
            cwd=payload.raw.get("cwd", ""),
            input=payload.raw.get("tool_input", {}),
            timestamp=payload.timestamp,
        )

    def iter_history_events(
        self, ai_config: Optional[AIDiscovery]
    ) -> Iterator[MCPActivityRequest]:
        """Walk every Kiro session transcript and yield its MCP tool calls.

        Both surfaces write the same store, so one walk covers the IDE and the
        CLI. The workspace is a hash in the path and the transcript names no
        model, so neither is reported rather than invented.
        """
        for path in sorted(self.config_folder.glob("sessions/*/sess_*/messages.jsonl")):
            for entry in self._load_jsonl_file(path):
                if (event := self._parse_history_entry(entry, ai_config)) is not None:
                    yield event

    def _parse_history_entry(
        self, entry: Dict[str, Any], ai_config: Optional[AIDiscovery]
    ) -> Optional[MCPActivityRequest]:
        """Turn one transcript line into an MCPActivityRequest, or None.

        None for anything that is not an MCP tool call: the store records every
        turn, prompt and first-party tool call too.
        """
        payload = entry.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "tool_call":
            return None

        raw_tool_name = payload.get("toolName")
        if not isinstance(raw_tool_name, str) or not _is_mcp_tool_name(raw_tool_name):
            return None

        try:
            timestamp = datetime.fromisoformat(
                entry["timestamp"].replace("Z", "+00:00")
            )
        except (KeyError, AttributeError, TypeError, ValueError):
            return None

        server_name, tool_name = self._split_mcp_tool_name(raw_tool_name, ai_config)
        arguments = payload.get("args")
        return MCPActivityRequest(
            user=self._user_or_default(ai_config),
            tool=tool_name,
            server=server_name,
            agent=self.name,
            model="",
            cwd="",
            input=arguments if isinstance(arguments, dict) else {},
            timestamp=timestamp,
        )
