"""
MCP Monitor command - Logs MCP tool executions with server identification.

This command is called on beforeMCPExecution, afterMCPExecution, and sessionStart events.
It identifies which MCP server a tool belongs to and logs the activity.
"""

import json
import sys
from typing import Any, Dict

import click

from ggshield.core.cursor import CursorEventType
from ggshield.verticals.mcp_monitor import (
    MCPActivityMonitor,
    MCPIdentityMapper,
    MCPToolMappingBuilder,
)


def handle_before_mcp_execution(event_data: Dict[str, Any]) -> Dict[str, Any]:
    workspace_roots = event_data.get("workspace_roots", [])
    monitor = MCPActivityMonitor(workspace_roots=workspace_roots)
    return monitor.process_event(event_data)


def handle_after_mcp_execution(event_data: Dict[str, Any]) -> Dict[str, Any]:
    workspace_roots = event_data.get("workspace_roots", [])
    monitor = MCPActivityMonitor(workspace_roots=workspace_roots)
    return monitor.process_event(event_data)


def handle_session_start(event_data: Dict[str, Any]) -> Dict[str, Any]:
    workspace_roots = event_data.get("workspace_roots", [])

    tool_builder = MCPToolMappingBuilder(workspace_roots=workspace_roots)
    tool_builder.save_mapping()

    identity_mapper = MCPIdentityMapper(workspace_roots=workspace_roots)
    identity_mapper.build_mappings()

    return {"decision": "allow"}


MCP_MONITOR_EVENT_HANDLERS = {
    CursorEventType.BEFORE_MCP_EXECUTION: handle_before_mcp_execution,
    CursorEventType.AFTER_MCP_EXECUTION: handle_after_mcp_execution,
    CursorEventType.SESSION_START: handle_session_start,
}


def process_mcp_monitor_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
    event_type_str = event_data.get("hook_event_name")

    if event_type_str is None:
        raise ValueError("Missing 'hook_event_name' field in event data")

    try:
        event_type = CursorEventType(event_type_str)
    except ValueError:
        raise ValueError(f"Unsupported event type: {event_type_str}")

    handler = MCP_MONITOR_EVENT_HANDLERS.get(event_type)
    if handler is None:
        raise ValueError(f"Event type not handled by mcp-monitor: {event_type_str}")

    return handler(event_data)


@click.command()
@click.pass_context
def mcp_monitor_cmd(
    ctx: click.Context,
) -> None:
    """
    Monitor MCP tool executions and log activity.

    Reads a Cursor hook event from stdin as JSON, processes it based on the
    event type, and outputs the response to stdout as JSON. Logs MCP activity
    with server identification, identity, and scope information.

    Supported events:
    - beforeMCPExecution: Log and identify MCP tool execution
    - afterMCPExecution: Complete logging for MCP tool execution
    - sessionStart: Build tool and identity mappings
    """
    stdin_content = sys.stdin.read()

    if not stdin_content.strip():
        click.echo("Error: No input received on stdin", err=True)
        ctx.exit(1)

    try:
        event_data = json.loads(stdin_content)
    except json.JSONDecodeError as exc:
        click.echo(f"Error: Failed to parse JSON from stdin: {exc}", err=True)
        ctx.exit(1)

    try:
        response = process_mcp_monitor_event(event_data)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)

    click.echo(json.dumps(response))
