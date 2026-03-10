import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

from notifypy import Notify

from ggshield.core.filter import censor_match
from ggshield.core.scan import StringScannable
from ggshield.core.scanner_ui import create_message_only_scanner_ui
from ggshield.core.text_utils import pluralize, translate_validity
from ggshield.verticals.secret import SecretScanner
from ggshield.verticals.secret.ai_hook.copilot import Copilot
from ggshield.verticals.secret.secret_scan_collection import Secret

from .claude_code import Claude
from .cursor import Cursor
from .models import MAX_READ_SIZE, EventType, Flavor, Payload, Result, Tool


class AIHookScanner:
    """AI hook scanner.

    It is called with the payload of a hook event.
    Note that instead of having a base class with common method and a subclass per supported AI tool,
    we instead have a single class which detects which protocol to use (called "flavor").
    This is because some tools sloppily support hooks from others. For instance,
    Cursor will call hooks defined in the Claude Code format, but send payload in its own format.
    So we can't assume which tool will call us based on the command line/hook configuration only.

    Raises:
        ValueError: If the input is not valid.
    """

    def __init__(self, scanner: SecretScanner):
        self.scanner = scanner

    def scan(self, content: str) -> int:
        """Scan the content, print the result and return the exit code."""

        payload = self._parse_input(content)
        result = self._scan_content(payload)

        # Special case: in post-tool use, the action is already done, we can only notify the user
        if result.block and payload.event_type == EventType.POST_TOOL_USE:
            # Too late, but at least notify the user
            self._send_secret_notification(
                result.nbr_secrets, payload.tool or Tool.OTHER, payload.flavor.name
            )
            return payload.flavor.output_result(
                Result(
                    event_type=payload.event_type,
                    block=False,
                    message="",
                    nbr_secrets=0,
                )
            )

        return payload.flavor.output_result(result)

    def _parse_input(self, content: str) -> Payload:
        """Parse the input content. Raises a ValueError if the input is not valid."""
        # Parse the content as JSON
        if not content.strip():
            raise ValueError("Error: No input received on stdin")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Error: Failed to parse JSON from stdin: {e}") from e

        # Infer the event type
        event_name = lookup(data, ["hook_event_name", "hookEventName"], None)
        if event_name is None:
            raise ValueError("Error: couldn't find event type")
        event_type = HOOK_NAME_TO_EVENT_TYPE.get(event_name.lower(), EventType.OTHER)

        identifier = ""
        content = ""
        tool = None

        # Extract the identifier and content based on the event type
        if event_type == EventType.USER_PROMPT:
            content = data.get("prompt", "")

        elif event_type == EventType.PRE_TOOL_USE:
            tool_name = data.get("tool_name", "").lower()
            tool = TOOL_NAME_TO_TOOL.get(tool_name, Tool.OTHER)
            tool_input = data.get("tool_input", {})
            # Select the content based on the tool
            if tool == Tool.BASH:
                content = tool_input.get("command", "")
                identifier = content
            elif tool == Tool.READ:
                identifier = lookup(tool_input, ["file_path", "filePath"], "")
                # Read the file before the AI tool
                file = Path(identifier)
                if file.is_file() and file.stat().st_size <= MAX_READ_SIZE:
                    try:
                        content = file.read_text()
                    except (UnicodeDecodeError, OSError):
                        pass

        elif event_type == EventType.POST_TOOL_USE:
            tool_name = data.get("tool_name", "").lower()
            tool = TOOL_NAME_TO_TOOL.get(tool_name, Tool.OTHER)
            content = data.get("tool_output", "") or data.get("tool_response", {})
            # Claude Code returns a dict for the tool output
            if isinstance(content, (dict, list)):
                content = json.dumps(content)

        # If identifier was not set, hash the content
        if not identifier:
            identifier = hashlib.sha256(content.encode()).hexdigest()

        # Try to guess which AI coding assistant is calling us
        if "cursor_version" in data:
            flavor = Cursor()
        elif "github.copilot-chat" in data.get("transcript_path", "").lower():
            flavor = Copilot()
        # no .lower() here to reduce the risk of false positives (this is also why this check is last)
        elif "session_id" in data and "claude" in data.get("transcript_path", ""):
            flavor = Claude()
        else:
            # Fallback that respect base conventions
            flavor = Flavor()

        return Payload(
            event_type=event_type,
            tool=tool,
            content=content,
            identifier=identifier,
            flavor=flavor,
        )

    def _scan_content(
        self,
        payload: Payload,
    ) -> Result:
        """Scan content for secrets using the SecretScanner."""
        # Short path: if there is no content, no need to do an API call
        if not payload.content:
            return Result(
                event_type=payload.event_type,
                block=False,
                message="",
                nbr_secrets=0,
            )

        scannable = StringScannable(url=payload.identifier, content=payload.content)

        with create_message_only_scanner_ui() as scanner_ui:
            results = self.scanner.scan([scannable], scanner_ui=scanner_ui)
        # Collect all secrets from results
        secrets: List[Secret] = []
        for result in results.results:
            secrets.extend(result.secrets)

        if not secrets:
            return Result(
                event_type=payload.event_type,
                block=False,
                message="",
                nbr_secrets=0,
            )

        message = self._message_from_secrets(
            secrets,
            payload,
            escape_markdown=True,
        )
        return Result(
            event_type=payload.event_type,
            block=True,
            message=message,
            nbr_secrets=len(secrets),
        )

    @staticmethod
    def _message_from_secrets(
        secrets: List[Secret], payload: Payload, escape_markdown: bool = False
    ) -> str:
        """
        Format detected secrets into a user-friendly message.

        Args:
            secrets: List of detected secrets
            payload: Text to display after the secrets output
            escape_markdown: If True, escape asterisks to prevent markdown interpretation

        Returns:
            Formatted message describing the detected secrets
        """
        count = len(secrets)
        header = f"**🚨 Detected {count} {pluralize('secret', count)} 🚨**"

        secret_lines = []
        for secret in secrets:
            validity = translate_validity(secret.validity).lower()
            if validity == "valid":
                validity = f"**{validity}**"
            match_str = ", ".join(censor_match(m) for m in secret.matches)
            if escape_markdown:
                match_str = match_str.replace("*", "•")
            secret_lines.append(
                f"  - {secret.detector_display_name} ({validity}): {match_str}"
            )

        if payload.event_type == EventType.USER_PROMPT:
            message = "Please remove the secrets from your prompt before submitting."
        elif payload.tool == Tool.BASH:
            message = (
                "Please remove the secrets from the command before executing it. "
                "Consider using environment variables or a secrets manager instead."
            )
        elif payload.tool == Tool.READ:
            message = (
                "Please remove the secrets from the file content before reading it."
            )
        else:
            message = (
                "Please remove the secrets from the tool input before executing. "
                "Consider using environment variables or a secrets manager instead."
            )

        secrets_block = "\n".join(secret_lines)
        return f"{header}\n{secrets_block}\n\n{message}"

    @staticmethod
    def _send_secret_notification(
        nbr_secrets: int, tool: Tool, agent_name: str
    ) -> None:
        """
        Send desktop notification when secrets are detected.

        Args:
            nbr_secrets: Number of detected secrets
            tool: Tool used to detect the secrets
            agent_name: Name of the agent that detected the secrets
        """
        source = "using a tool"
        if tool == Tool.READ:
            source = "reading a file"
        elif tool == Tool.BASH:
            source = "running a command"
        notification = Notify()
        notification.title = "ggshield - Secrets Detected"
        notification.message = (
            f"{agent_name} got access to {nbr_secrets}"
            f" {pluralize('secret', nbr_secrets)} by {source}"
        )
        notification.application_name = "ggshield"
        try:
            notification.send()
        except Exception:
            # This is best effort, we don't want to propagate an error
            # if the notification fails.
            pass


HOOK_NAME_TO_EVENT_TYPE = {
    "userpromptsubmit": EventType.USER_PROMPT,
    "beforesubmitprompt": EventType.USER_PROMPT,
    "pretooluse": EventType.PRE_TOOL_USE,
    "posttooluse": EventType.POST_TOOL_USE,
}

TOOL_NAME_TO_TOOL = {
    "shell": Tool.BASH,  # Cursor
    "bash": Tool.BASH,  # Claude Code
    "run_in_terminal": Tool.BASH,  # Copilot
    "read": Tool.READ,  # Claude/Cursor
    "read_file": Tool.READ,  # Copilot
}


def lookup(data: Dict[str, Any], keys: Sequence[str], default: Any = None) -> Any:
    """Returns the value of the first key found in a dictionary."""
    for key in keys:
        if key in data:
            return data[key]
    return default
