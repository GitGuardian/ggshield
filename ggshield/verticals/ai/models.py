from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from ggshield.core.scan import File, Scannable, StringScannable
from ggshield.utils.files import is_path_binary


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


class Transport(Enum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


class Scope(Enum):
    USER = "user"
    PROJECT = "project"


class MCPArgumentInfo(BaseModel):
    name: str
    type: str
    description: Optional[str] = None
    required: bool = False


class MCPToolInfo(BaseModel):
    name: str
    description: Optional[str] = None
    arguments: Optional[List[MCPArgumentInfo]] = None


class MCPResourceInfo(BaseModel):
    uri: str
    name: Optional[str] = None
    description: Optional[str] = None
    mime_type: Optional[str] = None


class MCPPromptInfo(BaseModel):
    name: str
    description: Optional[str] = None


ConfigurationKey = Tuple[str, Scope, Optional[Path], str]


class MCPConfiguration(BaseModel):
    name: str
    agent: str
    scope: Scope
    transport: Transport
    project: Optional[Path] = None
    # stdio fields
    command: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    env: Dict[str, str] = Field(default_factory=dict)
    # remote fields
    url: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)


class MCPServer(BaseModel):
    name: str
    display_name: Optional[str] = None
    tools: List[MCPToolInfo] = Field(default_factory=list)
    resources: List[MCPResourceInfo] = Field(default_factory=list)
    prompts: List[MCPPromptInfo] = Field(default_factory=list)
    configurations: List[MCPConfiguration] = Field(default_factory=list)


class UserInfo(BaseModel):
    hostname: str
    username: str
    machine_id: str
    user_email: Optional[str] = None


class AIDiscovery(BaseModel):
    user: UserInfo
    servers: List[MCPServer] = Field(default_factory=list)
    # Metadata for analytics
    discovery_duration: float  # in s


class MCPActivityResponse(BaseModel):
    allowed: bool
    reason: str


class MCPActivityRequest(BaseModel):
    user: UserInfo
    tool: str
    server: str
    agent: str
    model: str
    cwd: Path
    input: Dict[str, Any]


class Agent(ABC):
    """
    Class that can be derived to implement behavior specific to some AI code assistants.
    """

    # Metadata

    @property
    @abstractmethod
    def display_name(self) -> str:
        """A user-friendly name for the agent."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the agent."""

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

    @property
    @abstractmethod
    def settings_path(self) -> Path:
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
