import json
import re
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from enum import Enum, auto
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Dict, List, Literal, Optional, Tuple


if TYPE_CHECKING:
    from ggshield.verticals.ai.agent_activity import ActivitySource, AgentActivityEvent

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib
from pygitguardian.models import AIDiscovery, MCPActivityRequest
from pygitguardian.models import MCPConfiguration as BaseMCPConfiguration
from pygitguardian.models import MCPServer, UserInfo

from ggshield.core.scan import File, Scannable, StringScannable
from ggshield.utils.files import is_path_binary


@dataclass
class MCPConfiguration(BaseMCPConfiguration):
    """MCP configuration that can store a human-readable name for its server."""

    display_name: Optional[str] = None

    def __eq__(self, other: object) -> bool:
        """Compare on the base fields, across both classes.

        A freshly walked discovery holds these instances, one read back from the
        cache or the API holds plain `BaseMCPConfiguration`, and the generated
        __eq__ refuses to compare across classes — which made change detection
        always answer "changed".

        `display_name` is excluded: it is local, not part of the wire schema, so
        it can never survive a round trip.
        """
        if not isinstance(other, BaseMCPConfiguration):
            return NotImplemented
        return all(
            getattr(self, f.name) == getattr(other, f.name)
            for f in fields(BaseMCPConfiguration)
        )


# Small re-exports arount Py-gitguardian models to make our life easier.
Transport = MCPConfiguration.Transport
Scope = MCPConfiguration.Scope


class EventType(Enum):
    """Event type constants for hook events."""

    USER_PROMPT = auto()
    PRE_TOOL_USE = auto()
    POST_TOOL_USE = auto()
    # We are not interested in other less generic events for now
    # (most of the time, one of the three above will also be called anyway)
    OTHER = auto()


class Tool(Enum):
    """Tool constants for hook events."""

    BASH = auto()
    READ = auto()
    MCP = auto()
    # We are not interested in other tools for now
    OTHER = auto()


# (first, last), 1-based and inclusive, `last` being None for "to the end".
ReadRange = Tuple[int, Optional[int]]


def line_slice(content: str, first: int, last: Optional[int]) -> str:
    """Return lines `first` to `last` of `content`, 1-based and inclusive.

    Split on "\\n" only, the way agents number lines: str.splitlines() also
    breaks on \\v, \\f and U+2028, which would shift every line number past the
    first such character and move the window off what the agent reads.

    One line of slack on each side, hence the -2/+1: we cannot check every
    agent's convention against a real agent, and being one line out must not
    leave content unscanned. An extra line costs nothing, a missing one is a
    miss.
    """
    lines = content.split("\n")
    return "\n".join(lines[max(0, first - 2) : None if last is None else last + 1])


def markdown_hard_breaks(text: str) -> str:
    """Turn single newlines into markdown hard breaks (two trailing spaces)."""
    lines = text.split("\n")
    return "\n".join(
        f"{line}  " if line and i + 1 < len(lines) and lines[i + 1] else line
        for i, line in enumerate(lines)
    )


@dataclass
class HookResult:
    """Result of a scan: allow or not."""

    block: bool
    message: str
    nbr_secrets: int
    payload: "HookPayload"
    # Set when the action is allowed but the user must be warned,
    # typically because the scan could not run at all.
    warning: str = ""

    @classmethod
    def allow(cls, payload: "HookPayload") -> "HookResult":
        return cls(block=False, message="", nbr_secrets=0, payload=payload)

    @classmethod
    def allow_with_warning(cls, payload: "HookPayload", warning: str) -> "HookResult":
        return cls(
            block=False, message="", nbr_secrets=0, payload=payload, warning=warning
        )


#: NAME_MAX and PATH_MAX. Nothing over them can name an existing file.
_NAME_MAX = 255
_PATH_MAX = 4096


def _cannot_be_a_path(identifier: str) -> bool:
    """Whether `identifier` is too long for the filesystem to hold such a file.

    A candidate read path can be a whole shell command (a heredoc, a pipeline),
    which no filesystem can name. Answering from the length keeps that off the
    syscall, whose failure is platform-dependent: `stat` reports ENAMETOOLONG,
    which `Path.is_file()` raises before Python 3.13 and swallows after.
    """
    return len(identifier) > _PATH_MAX or any(
        len(component) > _NAME_MAX for component in re.split(r"[\\/]", identifier)
    )


@dataclass
class HookPayload:
    event_type: EventType
    tool: Optional[Tool]
    content: str
    identifier: str
    agent: "Agent"
    raw: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # Lines a Tool.READ is about to expose; None means the whole file.
    read_range: Optional[ReadRange] = None

    @cached_property
    def scannable(self) -> Scannable:
        """Return the appropriate Scannable for the payload.

        Cached: a ranged read builds the slice by reading the file, and callers
        ask for the scannable more than once (`empty`, then the scan itself).
        """
        if self.tool == Tool.READ and not _cannot_be_a_path(self.identifier):
            # The identifier is not always a real path: it can be a whole shell
            # command (a heredoc, a pipeline...) that a caller guessed was a
            # file name. Path.is_file() only swallows "not found" errors, so it
            # still raises on such identifiers (embedded NULs, a too-long name on
            # Python < 3.13...). Never let that abort the scan: fall back to
            # scanning the content.
            try:
                path = Path(self.identifier)
                if path.is_file() and not is_path_binary(path):
                    file = File(path=self.identifier)
                    if self.read_range is not None:
                        try:
                            # Scanning the slice rather than the file is also
                            # the difference between scanning and not scanning
                            # at all: SecretScanner silently skips any document
                            # over maximum_document_size, so over-scanning a
                            # large file ends up allowing an unscanned read.
                            return StringScannable(
                                url=self.identifier,
                                content=line_slice(file.content, *self.read_range),
                            )
                        except Exception:
                            # Unreadable or undecodable: let the scanner skip it
                            # and say why, rather than deciding here.
                            pass
                    return file
            except (OSError, ValueError):
                pass
        return StringScannable(url=self.identifier, content=self.content)

    @property
    def empty(self) -> bool:
        """Return True if the payload is empty."""
        return not self.scannable.is_longer_than(0)


class Agent(ABC):
    """
    Class that can be derived to implement behavior specific to some AI code assistants.
    """

    # Properties

    @property
    @abstractmethod
    def display_name(self) -> str:
        """A user-friendly name for the agent."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the agent."""

    @property
    @abstractmethod
    def config_folder(self) -> Path:
        """The folder where the assistant's config files are stored."""

    # Hooks

    @abstractmethod
    def output_result(self, result: HookResult) -> int:
        """How to output the result of a scan.

        This method is expected to have side effects, like printing to stdout or stderr.

        Args:
            result: the result of the scan.

        Returns: the exit code.
        """

    @abstractmethod
    def is_caller(self, hook_payload: Dict[str, Any]) -> bool:
        """Whether the agent is the caller of the hook."""

    def has_secret_already_leaked(self, payload: HookPayload) -> bool:
        """Whether the secret has already been leaked to the agent.

        By default, this is in PostToolUse hooks, but it can depend on the agent.
        """
        return payload.event_type == EventType.POST_TOOL_USE

    def event_cwd(self, data: Dict[str, Any]) -> str:
        """The directory the event happened in, used to resolve relative file
        paths to absolute ones so a file mentioned in a prompt and the same file
        read by a tool share one verdict-cache key.

        Most agents (Claude, Codex, Copilot CLI, VSCode) put it in "cwd"; Cursor
        overrides this to read "workspace_roots". Returns "" when unknown, in
        which case callers leave paths untouched rather than guess.
        """
        return data.get("cwd", "") or ""

    def read_range(self, tool_input: Dict[str, Any]) -> Optional[ReadRange]:
        """The lines a read tool call is about to expose, 1-based and inclusive.

        None — the default — means the whole file, and stays the answer for
        every agent whose range parameters we have not established from a real
        payload: over-scanning is a scope problem, under-scanning lets content
        reach the model unscanned. Absent parameters mean everything too.
        """
        return None

    def post_process_payload(self, payload: HookPayload):
        """Post-process the payload.

        This method is called after the payload has been parsed, but before it is scanned.
        """

    # Settings

    @abstractmethod
    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        """Path to the settings file for this AI coding tool."""

    @property
    def settings_format(self) -> Literal["json", "toml"]:
        """Serialization format used by the assistant's hook settings file."""
        return "json"

    def post_install_warning(self, mode: Literal["local", "global"]) -> Optional[str]:
        """Warning to show after a successful install, if the assistant needs
        one more step before it will actually load the hooks."""
        return None

    @property
    def settings_template(self) -> Dict[str, Any]:
        """
        Template for the settings file for this AI coding tool.
        Use the sentinel "<COMMAND>" for the places where the command should be inserted.
        """
        return {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "<COMMAND>",
                            }
                        ],
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "<COMMAND>",
                            }
                        ],
                    }
                ],
                "UserPromptSubmit": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "<COMMAND>",
                            }
                        ],
                    }
                ],
            }
        }

    def settings_locate(
        self, candidates: List[Dict[str, Any]], template: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Callback used to help locate the correct object to update in the settings.

        We don't want to overwrite other hooks nor create duplicates, so when the existing
        hook configuration is traversed and we end up in a list, this callback is used to
        locate the correct object to update.

        Args:
            candidates: the list of objects at the level currently traversed.
            template: the template of the expected object.

        Returns: the object to update, or None if no object was found.
        """
        # We have two kind of lists: at the root of each hook (with a matcher)
        # and in each hook (with a list of commands).
        if "matcher" in template:
            for obj in candidates:
                if obj.get("matcher") == template["matcher"]:
                    return obj
            return None
        for obj in candidates:
            command = obj.get("command", "")
            if "ggshield" in command or "<COMMAND>" in command:
                return obj
        return None

    # Discovery

    @abstractmethod
    def project_mcp_file(self, directory: Path) -> Path:
        """The file where MCP servers are configured at the project level."""

    @property
    @abstractmethod
    def user_mcp_file(self) -> Path:
        """The file where MCP servers are configured at the user level."""

    @abstractmethod
    def discover_project_directories(self) -> Iterator[Path]:
        """Discover project directories by scraping config or history files."""

    def _parse_servers_block(
        self,
        data: Dict[str, Any],
        scope: Scope,
        project: Optional[Path],
        display_name: Optional[str] = None,
        base_dir: Optional[Path] = None,
        _in_list: bool = False,
    ) -> Iterator[MCPConfiguration]:
        """Utility function to parse a "mcpServer" block and return the MCP server entries.

        The format is standard across all assistants.
        """
        # Lookup the two usual conventions
        servers = data.get(
            "mcpServers", data.get("servers", data.get("mcp_servers", {}))
        )
        # Handle path to a config file
        if isinstance(servers, str):
            path = Path(servers)
            if not path.is_absolute():
                if base_dir is None:
                    # Without an anchor a relative location would resolve
                    # against the process cwd; drop it instead.
                    return
                path = base_dir / path
            if (loaded := self._load_file(path)) is None:
                return
            # The official shape is {"mcpServers": {...}}, but non-wrapped configs are sometimes leniently supported.
            # Also we expect only the dict shape for referenced config files.
            # This also prevents a potential infinite loop if the referenced file points back to the original file.
            servers = loaded.get(
                "mcpServers", loaded.get("servers", loaded.get("mcp_servers", loaded))
            )
        # Handle list of servers. Nested lists are undocumented, so we don't support them.
        elif isinstance(servers, list):
            if _in_list:
                return
            for server in servers:
                # An element may itself be a wrapped block: don't double-wrap.
                if not (
                    isinstance(server, dict)
                    and server.keys() & {"mcpServers", "servers", "mcp_servers"}
                ):
                    server = {"mcpServers": server}
                yield from self._parse_servers_block(
                    server, scope, project, display_name, base_dir, _in_list=True
                )
            return
        if not isinstance(servers, dict):
            return
        for name, entry in servers.items():
            if not isinstance(entry, dict):
                continue
            if "url" in entry:
                # The transport key is spelled "transport" or "type" depending
                # on the assistant.
                if entry.get("transport", entry.get("type")) == "sse":
                    transport = Transport.SSE
                else:
                    transport = Transport.HTTP
            else:
                transport = Transport.STDIO

            yield MCPConfiguration(
                name=name,
                agent=self.name,
                scope=scope,
                transport=transport,
                project=str(project) if project else None,
                command=entry.get("command"),
                args=entry.get("args", []),
                env=entry.get("env", {}),
                url=entry.get("url"),
                headers=entry.get("headers", {}),
                display_name=display_name,
            )

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        """Return the MCP server entries for user-level (global) config files.

        Default implementation loads the user's config file.
        """
        # Load config file
        if not (data := self._load_file(self.user_mcp_file)):
            return
        yield from self._parse_servers_block(data, Scope.USER, None)

    def _get_project_mcp_configurations(
        self, directory: Path
    ) -> Iterator[MCPConfiguration]:
        """Return the MCP server entries for project-level config files."""
        if data := self._load_file(self.project_mcp_file(directory)):
            yield from self._parse_servers_block(data, Scope.PROJECT, directory)

    def discover_mcp_configurations(
        self, directories: Iterable[Path]
    ) -> List[MCPConfiguration]:
        """Discover MCP configurations from user and project config files.

        Iterates over user-level paths, then project-level paths for each
        directory in *directories*.
        """
        results: List[MCPConfiguration] = []

        # User-level configs
        results.extend(self._get_user_mcp_configurations())

        # Project-level configs
        for directory in directories:
            results.extend(self._get_project_mcp_configurations(directory))

        return results

    def discover_capabilities(self, server: MCPServer) -> bool:
        """Discover capabilities for the given server.

        Returns whether the capabilities were discovered.
        """
        return False

    @abstractmethod
    def parse_mcp_activity(
        self, payload: HookPayload, ai_config: AIDiscovery
    ) -> MCPActivityRequest:
        """Parse the MCP activity from an MCP hook payload.

        Implementations can assume that the payload is an MCP pre-tool use.
        """

    # History parsing — agents that can find past MCP usage on disk override this.

    def iter_history_events(
        self, ai_config: Optional[AIDiscovery]
    ) -> Iterator[MCPActivityRequest]:
        """Yield historical MCP tool calls this agent can recover from its on-disk state.

        Default: empty (this agent does not know how to surface its history).
        Implementations decide how to source the events: JSONL transcripts,
        SQLite databases, etc.
        """
        return iter(())

    agent_activity_sources: ClassVar[List["ActivitySource"]] = []
    """Subclasses set this to the list of agent-activity sources they expose.

    Each entry is an ActivitySource instance (see
    ggshield.verticals.ai.agent_activity). The default implementation of
    iter_agent_activity_events walks every source.
    """

    def iter_agent_activity_events(self) -> Iterator["AgentActivityEvent"]:
        """Yield every AgentActivityEvent this agent can recover from disk.

        Default implementation: iterate self.agent_activity_sources, passing
        self.config_folder as the path_root so each event's source_path is
        recorded relative to the agent's config dir.
        """
        for source in self.agent_activity_sources:
            yield from source.iter_events(
                agent_name=self.name, path_root=self.config_folder
            )

    def _user_or_default(self, ai_config: Optional[AIDiscovery]) -> UserInfo:
        """Return ``ai_config.user`` or a blank ``UserInfo`` if no config is provided."""
        if ai_config is not None:
            return ai_config.user
        return UserInfo(hostname="", username="", machine_id="")

    def subscription_email(self) -> Optional[str]:
        """Email of the assistant subscription this agent is signed into, or None.

        Never approximated: `git config user.email` names the repository, not the
        subscription, so an agent on a personal plan would report a work address.
        """
        return None

    # Helper methods

    def _load_file(self, path: Path) -> Optional[Dict[str, Any]]:
        """Load a file and return the data, or None if the file doesn't exist."""
        try:
            if not path.is_file():
                return None
            raw = path.read_text()
            # Fallback to JSON
            if path.suffix == ".toml":
                data = tomllib.loads(raw)
            else:
                data = json.loads(raw)
            if not isinstance(data, dict):
                return None
            return data
        except (OSError, ValueError):
            return None

    def _load_jsonl_file(self, path: Path) -> Iterator[Dict[str, Any]]:
        """Load a JSONL file and return the data line by line,
        or nothing if the file doesn't exist (or is not a JSON object)."""
        if not path.is_file():
            yield from []
        try:
            for line in open(path, "r"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
        except OSError:
            yield from []

    def is_present(self) -> bool:
        """Whether the agent is present on the machine"""
        return self.config_folder.exists()
