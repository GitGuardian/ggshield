import json
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pygitguardian.models import (
    AIDiscovery,
    MCPActivityRequest,
    MCPConfiguration,
    MCPServer,
)

from ggshield.core.scan import File, Scannable, StringScannable
from ggshield.utils.files import is_path_binary


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


@dataclass
class HookResult:
    """Result of a scan: allow or not."""

    block: bool
    message: str
    nbr_secrets: int
    payload: "HookPayload"

    @classmethod
    def allow(cls, payload: "HookPayload") -> "HookResult":
        return cls(block=False, message="", nbr_secrets=0, payload=payload)


@dataclass
class HookPayload:
    event_type: EventType
    tool: Optional[Tool]
    content: str
    identifier: str
    agent: "Agent"
    raw: Dict[str, Any]

    @property
    def scannable(self) -> Scannable:
        """Return the appropriate Scannable for the payload."""
        if self.tool == Tool.READ:
            path = Path(self.identifier)
            if path.is_file() and not is_path_binary(path):
                return File(path=self.identifier)
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

    # Settings

    @abstractmethod
    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        """Path to the settings file for this AI coding tool."""

    @property
    @abstractmethod
    def settings_template(self) -> Dict[str, Any]:
        """
        Template for the settings file for this AI coding tool.
        Use the sentinel "<COMMAND>" for the places where the command should be inserted.
        """

    @abstractmethod
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
        return None

    # Discovery

    @abstractmethod
    def project_mcp_file(self, directory: Path) -> Path:
        """The file where MCP servers are configured at the project level."""

    @abstractmethod
    def discover_project_directories(self) -> Iterator[Path]:
        """Discover project directories by scraping config or history files."""

    def _parse_servers_block(
        self,
        data: Dict[str, Dict[str, Any]],
        scope: Scope,
        project: Optional[Path],
    ) -> Iterator[MCPConfiguration]:
        """Utility function to parse a "mcpServer" block and return the MCP server entries.

        The format is standard across all assistants.
        """
        # Lookup the two usual conventions
        servers = data.get("mcpServers", data.get("servers", {}))
        for name, entry in servers.items():
            if "url" in entry:
                if entry.get("transport") == "sse":
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
            )

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        """Return the MCP server entries for user-level (global) config files.

        Default implementation looks in the config folder for a file named "mcp.json".
        """
        # Load config file
        filepath = self.config_folder / "mcp.json"
        if not (data := self._load_json_file(filepath)):
            return
        yield from self._parse_servers_block(data, Scope.USER, None)

    def _get_project_mcp_configurations(
        self, directory: Path
    ) -> Iterator[MCPConfiguration]:
        """Return the MCP server entries for project-level config files."""
        if data := self._load_json_file(self.project_mcp_file(directory)):
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

    # Helper methods

    def _load_json_file(self, path: Path) -> Optional[Dict[str, Any]]:
        """Load a JSON file and return the data, or None if the file doesn't exist (or is not a JSON object)."""
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        return data

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
