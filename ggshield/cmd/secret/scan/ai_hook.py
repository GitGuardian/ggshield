import json
import sys
from typing import Any, Dict, List

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.cursor import CursorEventType
from ggshield.core.scan import ScanContext, ScanMode, StringScannable
from ggshield.core.scanner_ui import create_message_only_scanner_ui
from ggshield.core.text_utils import pluralize
from ggshield.verticals.secret import SecretScanner
from ggshield.verticals.secret.output.secret_gitlab_webui_output_handler import (
    format_secret,
)
from ggshield.verticals.secret.secret_scan_collection import Secret


def scan_content(
    ctx: click.Context, content: str, identifier: str
) -> List[Secret]:
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


def format_secrets_for_message(secrets: List[Secret]) -> str:
    """
    Format detected secrets into a user-friendly message.

    Args:
        secrets: List of detected secrets

    Returns:
        Formatted message describing the detected secrets
    """
    formatted_secrets = {format_secret(s) for s in secrets}
    secrets_list = ", ".join(formatted_secrets)
    count = len(formatted_secrets)
    return f"ggshield detected {count} {pluralize('secret', count)}: {secrets_list}"


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
        message = format_secrets_for_message(secrets)
        return {
            "permission": "deny",
            "user_message": f"{message}. The command has been blocked.",
            "agent_message": (
                f"{message}. "
                "Please remove the secrets from the command before executing it. "
                "Consider using environment variables or a secrets manager instead."
            ),
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
        message = format_secrets_for_message(secrets)
        return {
            "permission": "deny",
            "user_message": f"{message}. The MCP tool execution has been blocked.",
            "agent_message": (
                f"{message}. "
                "Please remove the secrets from the tool input before executing. "
                "Consider using environment variables or a secrets manager instead."
            ),
        }

    return {"permission": "allow"}


def handle_before_tab_file_read(
    ctx: click.Context, event_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Handle beforeTabFileRead hook event.

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
    prompt = event_data.get("prompt", "")

    if not prompt:
        return {"continue": True}

    secrets = scan_content(ctx, prompt, "user-prompt")

    if secrets:
        message = format_secrets_for_message(secrets)
        return {
            "continue": False,
            "user_message": (
                f"{message}. "
                "Please remove the secrets from your prompt before submitting."
            ),
        }

    return {"continue": True}


# Mapping of event types to their handler functions
EVENT_HANDLERS = {
    CursorEventType.BEFORE_SHELL_EXECUTION: handle_before_shell_execution,
    CursorEventType.BEFORE_MCP_EXECUTION: handle_before_mcp_execution,
    CursorEventType.BEFORE_TAB_FILE_READ: handle_before_tab_file_read,
    CursorEventType.BEFORE_SUBMIT_PROMPT: handle_before_submit_prompt,
}


def process_hook_event(ctx: click.Context, event_data: Dict[str, Any]) -> Dict[str, Any]:
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
    type=click.Choice(["cursor"]),
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

    Reads a Cursor hook event from stdin as JSON, processes it based on the
    event type, and outputs the response to stdout as JSON.
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
        response = process_hook_event(ctx, event_data)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        return 1

    # Output response as JSON to stdout
    click.echo(json.dumps(response))
    return 0
