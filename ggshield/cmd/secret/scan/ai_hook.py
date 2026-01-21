import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import click
from notifypy import Notify

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.claude_code import ClaudeCodeEventType, ClaudeCodeToolName
from ggshield.core.client import create_client_from_config
from ggshield.core.cursor import CursorEventType
from ggshield.core.filter import censor_match
from ggshield.core.scan import ScanContext, ScanMode, StringScannable
from ggshield.core.scanner_ui import create_message_only_scanner_ui
from ggshield.core.text_utils import pluralize, translate_validity
from ggshield.verticals.secret import SecretScanner
from ggshield.verticals.secret.secret_scan_collection import Secret


def scan_content(ctx: click.Context, content: str, identifier: str) -> List[Secret]:
    """
    Scan content for secrets using the SecretScanner.

    Args:
        ctx: Click context with client and config
        content: The content to scan for secrets
        identifier: A unique identifier for the content (used for reporting)

    Returns:
        List of detected secrets
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    scan_context = ScanContext(
        scan_mode=ScanMode.AI_HOOK,
        command_path=ctx.command_path,
    )

    scanner = SecretScanner(
        client=ctx_obj.client,
        cache=ctx_obj.cache,
        scan_context=scan_context,
        secret_config=config.user_config.secret,
    )

    scannable = StringScannable(url=identifier, content=content)

    with create_message_only_scanner_ui() as scanner_ui:
        results = scanner.scan([scannable], scanner_ui=scanner_ui)

    # Collect all secrets from results
    secrets: List[Secret] = []
    for result in results.results:
        secrets.extend(result.secrets)

    return secrets


def format_secrets_for_message(
    secrets: List[Secret], message: str, escape_markdown: bool = False
) -> str:
    """
    Format detected secrets into a user-friendly message.

    Args:
        secrets: List of detected secrets
        message: Text to display after the secrets output
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

    secrets_block = "\n".join(secret_lines)
    return f"{header}\n{secrets_block}\n\n{message}"


def send_secret_notification(secrets: List[Secret], source: str, ai_tool: str) -> None:
    """
    Send desktop notification when secrets are detected.

    Args:
        secrets: List of detected secrets
        source: Description of the source (e.g., "shell command", "MCP tool")
        ai_tool: Name of the AI tool (e.g., "Cursor", "Claude Code")
    """
    secret_count = len(secrets)
    notification = Notify()
    notification.title = "ggshield - Secrets Detected"
    notification.message = (
        f"{ai_tool} got access to {pluralize('secret', secret_count)} via {source}"
    )
    notification.application_name = "ggshield"
    notification.icon = "scripts/chocolatey/icon.png"
    notification.send()


def handle_before_shell_execution(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle beforeShellExecution hook event.

    Input fields:
        - command: full terminal command
        - cwd: current working directory

    Returns permission decision with optional messages.
    """
    command = event_data.get("command", "")

    if not command:
        return {"permission": "allow"}

    secrets = scan_content(ctx, command, "shell-command")

    if secrets:
        message = format_secrets_for_message(
            secrets,
            "Please remove the secrets from the command before executing it. "
            "Consider using environment variables or a secrets manager instead.",
            escape_markdown=True,
        )
        return {
            "permission": "deny",
            "user_message": f"{message}\n\nThe command has been blocked.",
            "agent_message": message,
        }

    return {"permission": "allow"}


def handle_before_mcp_execution(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle beforeMCPExecution hook event.

    Input fields:
        - tool_name: name of the MCP tool
        - tool_input: JSON params string
        - url or command: server identifier

    Returns permission decision with optional messages.
    """
    tool_input = event_data.get("tool_input", "")
    tool_name = event_data.get("tool_name", "unknown")

    if not tool_input:
        return {"permission": "allow"}

    secrets = scan_content(ctx, tool_input, f"mcp-tool:{tool_name}")

    if secrets:
        message = format_secrets_for_message(
            secrets,
            "Please remove the secrets from the tool input before executing. "
            "Consider using environment variables or a secrets manager instead.",
            escape_markdown=True,
        )
        return {
            "permission": "deny",
            "user_message": f"{message}\n\nThe MCP tool execution has been blocked.",
            "agent_message": message,
        }

    return {"permission": "allow"}


def handle_before_read_file(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle beforeReadFile hook event (for Agent file reads).

    Input fields:
        - file_path: absolute path to the file
        - content: file contents
        - attachments: list of file/rule attachments

    Returns permission decision.
    """
    content = event_data.get("content", "")
    file_path = event_data.get("file_path", "unknown")

    if not content:
        return {"permission": "allow"}

    secrets = scan_content(ctx, content, file_path)

    if secrets:
        return {"permission": "deny"}

    return {"permission": "allow"}


def handle_before_tab_file_read(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle beforeTabFileRead hook event (for Tab inline completions).

    Input fields:
        - file_path: absolute path to the file
        - content: file contents

    Returns permission decision.
    """
    content = event_data.get("content", "")
    file_path = event_data.get("file_path", "unknown")

    if not content:
        return {"permission": "allow"}

    secrets = scan_content(ctx, content, file_path)

    if secrets:
        return {"permission": "deny"}

    return {"permission": "allow"}


def handle_before_submit_prompt(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle beforeSubmitPrompt hook event.

    Input fields:
        - prompt: user prompt text
        - attachments: list of file/rule attachments

    Returns continue decision with optional user message.
    """
    all_secrets: List[Secret] = []

    # Scan the prompt text
    prompt = event_data.get("prompt", "")
    if prompt:
        all_secrets.extend(scan_content(ctx, prompt, "user-prompt"))

    # Scan attached files
    attachments = event_data.get("attachments", [])
    for attachment in attachments:
        if attachment.get("type") == "file":
            file_path = attachment.get("file_path", "")
            if file_path:
                try:
                    content = Path(file_path).read_text()
                    all_secrets.extend(scan_content(ctx, content, file_path))
                except (OSError, IOError, UnicodeDecodeError):
                    # Skip files that cannot be read
                    pass

    if all_secrets:
        message = format_secrets_for_message(
            all_secrets,
            "Please remove the secrets from your prompt or attached files before submitting.",
            escape_markdown=True,
        )
        return {
            "continue": False,
            "user_message": message,
        }

    return {"continue": True}


def handle_after_shell_execution(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle afterShellExecution hook event.

    Input fields:
        - command: full terminal command
        - cwd: current working directory
        - output: stdout/stderr content
        - exit_code: command exit code

    Returns empty dict (no output fields supported, fire-and-forget).
    Sends desktop notification if secrets are detected.
    """
    output = event_data.get("output", "")

    if not output:
        return {}

    secrets = scan_content(ctx, output, "shell-output")

    if secrets:
        send_secret_notification(secrets, "shell command", "Cursor")

    return {}


def handle_after_mcp_execution(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle afterMCPExecution hook event.

    Input fields:
        - tool_name: name of the MCP tool
        - tool_input: JSON params string
        - url or command: server identifier
        - tool_output: tool execution result

    Returns empty dict (no output fields supported, fire-and-forget).
    Sends desktop notification if secrets are detected.
    """
    tool_output = event_data.get("tool_output", "")
    tool_name = event_data.get("tool_name", "unknown")

    if not tool_output:
        return {}

    secrets = scan_content(ctx, tool_output, f"mcp-tool-output:{tool_name}")

    if secrets:
        send_secret_notification(secrets, f"MCP tool '{tool_name}'", "Cursor")

    return {}


# =============================================================================
# Claude Code Handlers
# =============================================================================


def cc_handle_pre_tool_use(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle Claude Code PreToolUse hook event.

    Routes to appropriate handler based on tool_name.

    Input fields:
        - tool_name: Name of the tool (Bash, Write, Edit, Read, mcp__*)
        - tool_input: Dict with tool-specific parameters

    Returns decision with optional reason.
    """
    tool_name = event_data.get("tool_name", "")
    tool_input = event_data.get("tool_input", {})

    # Ensure tool_input is a dict
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except json.JSONDecodeError:
            tool_input = {}

    if tool_name == ClaudeCodeToolName.BASH:
        return cc_handle_bash_tool(ctx, tool_input)
    elif tool_name in (ClaudeCodeToolName.WRITE, ClaudeCodeToolName.EDIT):
        return cc_handle_write_edit_tool(ctx, tool_name, tool_input)
    elif tool_name == ClaudeCodeToolName.READ:
        return cc_handle_read_tool(ctx, tool_input)
    elif tool_name.startswith(ClaudeCodeToolName.MCP_PREFIX):
        return cc_handle_mcp_tool(ctx, tool_name, tool_input)

    # Allow unknown tools
    return {}


def cc_handle_bash_tool(
    ctx: click.Context, tool_input: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle Claude Code Bash tool PreToolUse.

    Input fields:
        - command: The shell command to execute

    Returns decision with optional reason.
    """
    command = tool_input.get("command", "")

    if not command:
        return {}

    secrets = scan_content(ctx, command, "shell-command")

    if secrets:
        message = format_secrets_for_message(
            secrets,
            "Please remove the secrets from the command before executing it. "
            "Consider using environment variables or a secrets manager instead.",
        )
        return {
            "decision": "block",
            "reason": message,
        }

    return {}


def cc_handle_write_edit_tool(
    ctx: click.Context, tool_name: str, tool_input: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle Claude Code Write/Edit tool PreToolUse.

    Input fields for Write:
        - file_path: Path to the file
        - content: Content to write

    Input fields for Edit:
        - file_path: Path to the file
        - old_string: String to replace
        - new_string: Replacement string

    Returns decision with optional reason.
    """
    file_path = tool_input.get("file_path", "unknown")

    # Get the content to scan
    if tool_name == ClaudeCodeToolName.WRITE:
        content = tool_input.get("content", "")
    else:  # Edit tool
        content = tool_input.get("new_string", "")

    if not content:
        return {}

    secrets = scan_content(ctx, content, file_path)

    if secrets:
        message = format_secrets_for_message(
            secrets,
            "Please remove the secrets from the file content before writing. "
            "Consider using environment variables or a secrets manager instead.",
        )
        return {
            "decision": "block",
            "reason": message,
        }

    return {}


def cc_handle_read_tool(
    ctx: click.Context, tool_input: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle Claude Code Read tool PreToolUse.

    For PreToolUse, we can only check if the file exists and optionally
    read it to scan for secrets before allowing the AI to access it.

    Input fields:
        - file_path: Path to the file to read

    Returns decision with optional reason.
    """
    file_path = tool_input.get("file_path", "") or tool_input.get("target_file", "")

    if not file_path:
        return {}

    # Try to read the file and scan it
    try:
        content = Path(file_path).read_text()
    except (OSError, IOError):
        # Cannot read file, let Claude Code handle the error
        return {}

    secrets = scan_content(ctx, content, file_path)

    if secrets:
        return {
            "decision": "block",
            "reason": "File contains secrets and cannot be read by the AI assistant.",
        }

    return {}


def cc_handle_mcp_tool(
    ctx: click.Context, tool_name: str, tool_input: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle Claude Code MCP tool PreToolUse.

    Input fields:
        - tool_name: mcp__<server>__<tool>
        - tool_input: Tool-specific parameters

    Returns decision with optional reason.
    """
    # Convert tool_input to string for scanning
    if isinstance(tool_input, dict):
        content = json.dumps(tool_input)
    else:
        content = str(tool_input)

    if not content or content == "{}":
        return {}

    secrets = scan_content(ctx, content, f"mcp-tool:{tool_name}")

    if secrets:
        message = format_secrets_for_message(
            secrets,
            "Please remove the secrets from the MCP tool input before executing. "
            "Consider using environment variables or a secrets manager instead.",
        )
        return {
            "decision": "block",
            "reason": message,
        }

    return {}


def cc_handle_post_tool_use(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle Claude Code PostToolUse hook event.

    Scans tool output for secrets and sends notifications if found.

    Input fields:
        - tool_name: Name of the tool
        - tool_input: Dict with tool-specific parameters
        - tool_result: Result/output from the tool (may be in different formats)

    Returns empty dict (fire-and-forget, notification only).
    """
    tool_name = event_data.get("tool_name", "unknown")

    # Try different possible field names for tool output
    # First check for nested tool_response (Bash tool returns {stdout, stderr, ...})
    tool_response = event_data.get("tool_response", {})
    if isinstance(tool_response, dict):
        # For Bash tool, get stdout from nested structure
        tool_output = tool_response.get("stdout", "")
    else:
        # For other tools, try top-level fields
        tool_output = (
            event_data.get("tool_result")
            or event_data.get("output")
            or tool_response  # tool_response might be a string
            or ""
        )

    # Handle dict output (convert to JSON string for scanning)
    if isinstance(tool_output, dict):
        tool_output = json.dumps(tool_output)

    if not tool_output:
        return {}

    secrets = scan_content(ctx, str(tool_output), f"tool-output:{tool_name}")

    if secrets:
        send_secret_notification(secrets, f"tool '{tool_name}'", ai_tool="Claude Code")

    return {}


def cc_handle_user_prompt_submit(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle Claude Code UserPromptSubmit hook event.

    Input fields:
        - prompt: The user's prompt text

    Returns decision with optional reason.
    """
    prompt = event_data.get("prompt", "")

    if not prompt:
        return {}

    secrets = scan_content(ctx, prompt, "user-prompt")

    if secrets:
        message = format_secrets_for_message(
            secrets,
            "Please remove the secrets from your prompt before submitting.",
        )
        return {
            "decision": "block",
            "reason": message,
        }

    return {}


def cc_handle_notification(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle Claude Code Notification hook event.

    This is a fire-and-forget event, no response needed.
    """
    return {}


# Claude Code event handlers mapping
CLAUDE_CODE_EVENT_HANDLERS = {
    ClaudeCodeEventType.PRE_TOOL_USE: cc_handle_pre_tool_use,
    ClaudeCodeEventType.POST_TOOL_USE: cc_handle_post_tool_use,
    ClaudeCodeEventType.USER_PROMPT_SUBMIT: cc_handle_user_prompt_submit,
    ClaudeCodeEventType.NOTIFICATION: cc_handle_notification,
}


def process_claude_code_event(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Process a Claude Code hook event and route to the appropriate handler.

    Claude Code provides event type via the hook_event_name field.

    Args:
        ctx: Click context with client and config
        event_data: The parsed JSON event from stdin

    Returns:
        The response dict to be written to stdout as JSON
    """
    event_type_str = event_data.get("hook_event_name")

    if event_type_str is None:
        # Try to infer from the data structure
        if "tool_name" in event_data:
            # Could be PreToolUse or PostToolUse - assume PreToolUse for blocking
            event_type_str = ClaudeCodeEventType.PRE_TOOL_USE.value
        elif "prompt" in event_data:
            event_type_str = ClaudeCodeEventType.USER_PROMPT_SUBMIT.value
        else:
            raise ValueError(
                "Cannot determine event type: missing 'hook_event_name' field"
            )

    try:
        event_type = ClaudeCodeEventType(event_type_str)
    except ValueError:
        raise ValueError(f"Unsupported Claude Code event type: {event_type_str}")

    handler = CLAUDE_CODE_EVENT_HANDLERS[event_type]
    return handler(ctx, event_data)


# Mapping of event types to their handler functions (Cursor)
EVENT_HANDLERS = {
    CursorEventType.BEFORE_SHELL_EXECUTION: handle_before_shell_execution,
    CursorEventType.BEFORE_MCP_EXECUTION: handle_before_mcp_execution,
    CursorEventType.BEFORE_READ_FILE: handle_before_read_file,
    CursorEventType.BEFORE_TAB_FILE_READ: handle_before_tab_file_read,
    CursorEventType.BEFORE_SUBMIT_PROMPT: handle_before_submit_prompt,
    CursorEventType.AFTER_SHELL_EXECUTION: handle_after_shell_execution,
    CursorEventType.AFTER_MCP_EXECUTION: handle_after_mcp_execution,
}


def process_hook_event(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Process a Cursor hook event and route to the appropriate handler.

    Args:
        ctx: Click context with client and config
        event_data: The parsed JSON event from stdin

    Returns:
        The response dict to be written to stdout as JSON
    """
    event_type_str = event_data.get("hook_event_name")

    if event_type_str is None:
        raise ValueError("Missing 'hook_event_name' field in event data")

    try:
        event_type = CursorEventType(event_type_str)
    except ValueError:
        raise ValueError(f"Unsupported event type: {event_type_str}")

    handler = EVENT_HANDLERS[event_type]
    return handler(ctx, event_data)


@click.command()
@click.option(
    "--mode",
    type=click.Choice(["cursor", "claude-code"]),
    required=True,
    help="The AI tool mode to use.",
)
@add_secret_scan_common_options()
@click.pass_context
def ai_hook_cmd(
    ctx: click.Context,
    mode: str,
    **kwargs: Any,
) -> int:
    """
    Scan AI tool interactions for secrets.

    Reads a hook event from stdin as JSON, processes it based on the
    event type and mode, and outputs the response to stdout as JSON.

    Supported modes:
    - cursor: Cursor IDE hooks
    - claude-code: Claude Code hooks
    """
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.client = create_client_from_config(ctx_obj.config)

    # Read JSON from stdin
    stdin_content = sys.stdin.read()

    if not stdin_content.strip():
        click.echo("Error: No input received on stdin", err=True)
        return 1

    try:
        event_data = json.loads(stdin_content)
    except json.JSONDecodeError as e:
        click.echo(f"Error: Failed to parse JSON from stdin: {e}", err=True)
        return 1

    try:
        if mode == "cursor":
            response = process_hook_event(ctx, event_data)
        else:  # claude-code
            response = process_claude_code_event(ctx, event_data)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        return 1

    # Output response as JSON to stdout
    # For Claude Code, empty dict means allow (exit code 0 is sufficient)
    if response:
        click.echo(json.dumps(response))
    return 0
