"""
MCP Discover command - Discovers MCP servers with their tools, identities, and scopes.
"""

import json
from pathlib import Path
from typing import Any, List, Optional

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.verticals.mcp_monitor.discovery import (
    MCPServerInfo,
    discover_mcp_servers,
    discover_mcp_servers_from_workspaces,
    get_discovery_cache_path,
    save_discovery_cache,
)


def format_server_text(server: MCPServerInfo) -> str:
    lines = [
        click.style(f"═══ {server.name} ", fg="cyan", bold=True)
        + "═" * (50 - len(server.name)),
        "",
        f"  Command:  {server.command} {' '.join(server.args)}",
        f"  Type:     {server.server_type or 'N/A'}",
        "",
    ]

    lines.append(f"  Tools ({len(server.tools)}):")
    if server.tools:
        for tool in server.tools[:15]:
            lines.append(f"    • {tool}")
        if len(server.tools) > 15:
            lines.append(f"    ... and {len(server.tools) - 15} more")
    else:
        lines.append("    (none discovered)")

    lines.append("")
    lines.append("  Identity:")
    if server.identity_repr:
        lines.append(f"    {server.identity_repr}")
    elif server.identity:
        for key, value in server.identity.items():
            lines.append(f"    {key}: {value}")
    else:
        lines.append("    (not available)")

    lines.append("")
    lines.append("  Scopes:")
    if server.scopes:
        for scope in server.scopes[:10]:
            lines.append(f"    • {scope}")
        if len(server.scopes) > 10:
            lines.append(f"    ... and {len(server.scopes) - 10} more")
    else:
        lines.append("    (not available)")

    lines.append("")
    return "\n".join(lines)


def format_servers_json(servers: List[MCPServerInfo]) -> str:
    return json.dumps([server.to_dict() for server in servers], indent=2)


@click.command(name="discover")
@click.option(
    "--mcp-config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Path to mcp.json file. Defaults to .cursor/mcp.json or ~/.cursor/mcp.json",
)
@click.option(
    "--workspace",
    "-w",
    type=click.Path(exists=True, path_type=Path),
    multiple=True,
    help="Workspace root(s) to search for .cursor/mcp.json",
)
@click.option(
    "--no-tools",
    is_flag=True,
    default=False,
    help="Skip fetching tools from MCP servers (faster)",
)
@click.option(
    "--no-identity",
    is_flag=True,
    default=False,
    help="Skip fetching identity and scopes (faster)",
)
@click.option(
    "--timeout",
    type=int,
    default=20,
    help="Timeout in seconds for querying MCP servers",
)
@click.option(
    "--json",
    "use_json",
    is_flag=True,
    default=False,
    help="Output as JSON",
)
@add_common_options()
@click.pass_context
def discover_cmd(
    ctx: click.Context,
    mcp_config: Optional[Path],
    workspace: tuple,
    no_tools: bool,
    no_identity: bool,
    timeout: int,
    use_json: bool,
    **kwargs: Any,
) -> int:
    """
    Discover MCP servers and their configuration.

    Parses the mcp.json configuration file and queries each MCP server to
    discover available tools, user identity, and OAuth scopes/permissions.

    \b
    Examples:
      ggshield mcp discover
      ggshield mcp discover --mcp-config .cursor/mcp.json
      ggshield mcp discover --json
      ggshield mcp discover --no-tools --no-identity  # Fast, config only
    """
    servers: List[MCPServerInfo] = []

    if mcp_config:
        servers = discover_mcp_servers(
            mcp_config,
            fetch_tools=not no_tools,
            fetch_identity=not no_identity,
            timeout=timeout,
        )
    elif workspace:
        servers = discover_mcp_servers_from_workspaces(
            list(str(w) for w in workspace),
            fetch_tools=not no_tools,
            fetch_identity=not no_identity,
            timeout=timeout,
        )
    else:
        cwd = Path.cwd()
        workspace_mcp = cwd / ".cursor" / "mcp.json"
        global_mcp = Path.home() / ".cursor" / "mcp.json"

        if workspace_mcp.exists():
            servers = discover_mcp_servers(
                workspace_mcp,
                fetch_tools=not no_tools,
                fetch_identity=not no_identity,
                timeout=timeout,
            )
        elif global_mcp.exists():
            servers = discover_mcp_servers(
                global_mcp,
                fetch_tools=not no_tools,
                fetch_identity=not no_identity,
                timeout=timeout,
            )
        else:
            click.echo(
                "No mcp.json found. Use --mcp-config to specify the path.", err=True
            )
            ctx.exit(1)

    if not servers:
        click.echo("No MCP servers found in configuration.", err=True)
        ctx.exit(1)

    save_discovery_cache(servers)
    total_tools = sum(len(s.tools) for s in servers)

    if use_json:
        click.echo(format_servers_json(servers))
    else:
        click.echo()
        click.echo(
            click.style("MCP Server Discovery", fg="green", bold=True)
            + f" - Found {len(servers)} server(s), {total_tools} tools"
        )
        click.echo()
        for server in servers:
            click.echo(format_server_text(server))

        click.echo(
            click.style("Cache saved to: ", fg="yellow")
            + str(get_discovery_cache_path())
        )

    return 0
