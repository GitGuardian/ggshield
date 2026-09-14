import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Literal, Optional

from pygitguardian.models import AIDiscovery, MCPActivityRequest

from ggshield.core.dirs import get_user_home_dir

from ..agent_activity.sources import JSONLActivitySource
from ..models import Agent, HookPayload, HookResult


#: The events Junie fires that carry something to scan. It also fires
#: SessionStart, Stop, StopFailure, SessionEnd and PermissionRequest, none of
#: which carries a prompt or a tool input, and it has no PostToolUse at all.
SCANNED_EVENTS = ("UserPromptSubmit", "PreToolUse")


class JunieActivitySource(JSONLActivitySource):
    """Every Junie CLI session event line, shipped raw.

    One JSON object per line under
    ~/.junie/sessions/<sessionId>/events.jsonl. The line is shipped verbatim;
    GitGuardian scans and strips secrets server-side before storing it.
    """

    kind = "5_session_events"

    def discover(self) -> Iterator[Path]:
        return iter(
            sorted((get_user_home_dir() / ".junie").glob("sessions/*/events.jsonl"))
        )


class Junie(Agent):
    """Behavior specific to Junie CLI, JetBrains' standalone terminal agent.

    Installation, MCP discovery and activity only: the hook itself is served by
    `rust/hook/`, so nothing here parses a payload or emits a verdict.

    Junie inside a JetBrains IDE is a different surface and not covered: hooks
    are dispatched by the interactive TUI and batch hosts only, and the IDE
    embeds Junie over ACP, which invokes none.
    """

    agent_activity_sources = [JunieActivitySource()]

    @property
    def name(self) -> str:
        return "junie"

    @property
    def display_name(self) -> str:
        return "Junie CLI"

    @property
    def config_folder(self) -> Path:
        return get_user_home_dir() / ".junie"

    def is_caller(self, hook_payload: Dict[str, Any]) -> bool:
        """Never: the Rust hook answers Junie's payloads.

        Detection and verdicts live in `rust/hook/`, which is what
        `ggshield secret scan ai-hook` runs. This adapter carries only what the
        Rust hook does not do: installation, MCP discovery and activity.
        """
        return False

    def output_result(self, result: HookResult) -> int:
        raise NotImplementedError("the Rust hook emits Junie's verdicts")

    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        return Path(".junie") / "config.json"

    def post_install_warning(self, mode: Literal["local", "global"]) -> Optional[str]:
        if mode == "local":
            return (
                "Junie ignores `hooks` in a project's .junie/config.json: a "
                "repository must not be able to run shell commands on checkout. "
                "Install for the user instead (`ggshield machine setup`), or "
                "pass this file explicitly with `junie --config-location`."
            )
        return (
            "Junie loads hooks when a session starts, so restart it for these to "
            "take effect. Two gaps to know about: hooks are an Early Access "
            "feature, so a stable build may ignore this file entirely, and the "
            "prompt event fires in the interactive TUI only, so prompts "
            "submitted in batch (-p) or ACP mode are not scanned. Tool calls are "
            "scanned in both TUI and batch."
        )

    @property
    def settings_template(self) -> Dict[str, Any]:
        # No matcher on either entry: Junie matches it against the tool name and
        # refuses to load an entry whose matcher matches nothing, and every tool
        # call has to be scanned anyway. The prompt event takes no matcher at all.
        command = {"hooks": [{"type": "command", "command": "<COMMAND>"}]}
        return {"hooks": {event: [command] for event in SCANNED_EVENTS}}

    def settings_locate(
        self, candidates: List[Dict[str, Any]], template: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Locate the matcher entry that already carries a ggshield command.

        Junie nests one list inside another: an event maps to matcher entries,
        and each entry holds its own list of commands. The entries carry no
        matcher of ours to recognise, so the ggshield command one list down is
        what identifies the entry to update rather than duplicate.
        """
        if "hooks" not in template:
            return super().settings_locate(candidates, template)
        for candidate in candidates:
            commands = candidate.get("hooks")
            if not isinstance(commands, list):
                continue
            if any(
                isinstance(command, dict)
                and isinstance(command.get("command"), str)
                and (
                    "ggshield" in command["command"]
                    or command["command"] == "<COMMAND>"
                )
                for command in commands
            ):
                return candidate
        return None

    @property
    def user_mcp_file(self) -> Path:
        return self.config_folder / "mcp" / "mcp.json"

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".junie" / "mcp" / "mcp.json"

    def discover_project_directories(self) -> Iterator[Path]:
        """The projects Junie has opened a session for.

        ~/.junie/sessions/index.jsonl holds one session summary per line, each
        naming its own `projectDir`. A malformed line is skipped rather than
        taken down the whole walk: the file is appended to by a running CLI, so
        a half-written last line is expected.
        """
        index = self.config_folder / "sessions" / "index.jsonl"
        try:
            lines = index.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        seen = set()
        for line in lines:
            try:
                summary = json.loads(line)
            except ValueError:
                continue
            directory = summary.get("projectDir") if isinstance(summary, dict) else None
            if not isinstance(directory, str) or directory in seen:
                continue
            seen.add(directory)
            path = Path(directory)
            if path.is_dir():
                yield path.resolve()

    def parse_mcp_activity(
        self, payload: HookPayload, ai_config: AIDiscovery
    ) -> MCPActivityRequest:
        # How Junie spells an MCP tool in a hook payload is unverified: the
        # permission matcher documents "an MCP tool name" and no prefix scheme.
        # The whole name is reported as the tool rather than split at a guess.
        return MCPActivityRequest(
            user=self._user_or_default(ai_config),
            tool=payload.raw.get("tool_name", ""),
            server="",
            agent=self.name,
            model="",
            cwd=payload.raw.get("cwd", ""),
            input=payload.raw.get("tool_input", {}),
            timestamp=payload.timestamp,
        )
