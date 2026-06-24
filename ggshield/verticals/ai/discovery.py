"""
MCP Discovery - Discovers MCP server configurations and manages probe result caches.
"""

from collections import defaultdict
from pathlib import Path
from time import perf_counter
from typing import Any, Dict, List, Optional

import click
from pygitguardian import GGClient
from pygitguardian.models import AgentInfo, AIDiscovery, Detail, MCPServer

from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.errors import APIKeyCheckError, UnexpectedError, UnknownInstanceError
from ggshield.core.text_utils import STYLE, format_text, pluralize

from .agents import AGENTS
from .cache import has_changed_from, load_discovery_cache, save_discovery_cache
from .history import BackfillReport, backfill_mcp_history
from .installation import are_hooks_installed_globally
from .models import MCPConfiguration, Scope
from .user import get_user_info


def refresh_and_maybe_submit_discovery(client: GGClient) -> AIDiscovery:
    """Always run discovery, compare with cache, submit only if changed."""
    cached = load_discovery_cache()
    # If we already have a machine id, reuse it.
    machine_id = cached.user.machine_id if cached is not None else None
    discovery = discover_ai_configuration(machine_id=machine_id)

    # Nothing changed,
    if cached is not None and not has_changed_from(discovery, cached):
        return cached

    try:
        # Get the updated version of the discovery, filled with data from the API.
        discovery = submit_ai_discovery(client, discovery)
        save_discovery_cache(discovery)
    except Exception:
        pass  # We don't want to display an error here, as we are in a hook.

    return discovery


def discover_ai_configuration(machine_id: Optional[str] = None) -> AIDiscovery:
    """
    Discover configurations from all supported assistants.

    Args:
        directories: additional project directories to scan.
    """
    start_time = perf_counter()
    mcp_configurations: List[MCPConfiguration] = []

    # Discovered project directories
    projects = {Path.cwd().resolve()}
    for agent in AGENTS.values():
        projects.update(agent.discover_project_directories())

    # Discover MCP configurations
    for agent in AGENTS.values():
        mcp_configurations.extend(agent.discover_mcp_configurations(projects))

    # Hook installation status
    agents = []
    for agent in AGENTS.values():
        if agent.is_present():
            installed, command = are_hooks_installed_globally(agent.name)
            agents.append(
                AgentInfo(
                    name=agent.name,
                    hooks_installed=installed,
                    hooks_command=command,
                )
            )

    # Merge MCP configurations into servers
    servers = _merge_mcp_configurations(mcp_configurations)

    # Try to find the servers' capabilities
    for server in servers:
        for agent in AGENTS.values():
            if agent.discover_capabilities(server):
                # Discovery succeeded for this server. Early return.
                break

    # Add user information
    user = get_user_info(machine_id=machine_id)
    discovery_duration = perf_counter() - start_time
    return AIDiscovery(
        user=user,
        servers=servers,
        agents=agents,
        discovery_duration=discovery_duration,
    )


def submit_ai_discovery(client: GGClient, discovery: AIDiscovery) -> AIDiscovery:
    """
    Send discovery results to the GitGuardian API.

    Returns the updated discovery. Raises an exception if the request fails.
    """
    response = client.send_ai_discovery(discovery)
    if isinstance(response, Detail):
        raise UnexpectedError(response.detail)
    return response


def _merge_mcp_configurations(
    mcp_configurations: List[MCPConfiguration],
) -> List[MCPServer]:
    """Merge MCP configurations into servers.

    This is a first naive deduplication of MCP configurations based on their name.
    Deduplicating is useful to avoid discovering capabilities for the same server multiple times.
    We expect it to be improved by GIM later.
    """
    servers: Dict[str, List[MCPConfiguration]] = defaultdict(list)
    for configuration in mcp_configurations:
        servers[configuration.name].append(configuration)

    return [
        MCPServer(
            name=name,
            configurations=configurations,  # type: ignore (we can safely assume covariance)
            display_name=_get_display_name(configurations),
        )
        for name, configurations in servers.items()
    ]


def _get_display_name(configurations: List[MCPConfiguration]) -> Optional[str]:
    """Get the first non-empty display name from a list of configurations"""
    for configuration in configurations:
        if configuration.display_name:
            return configuration.display_name
    return None


def run_discovery(
    config: Config, *, scan_history: bool = False
) -> Optional[Dict[str, Any]]:
    """Discover AI/MCP configuration, submit it to GitGuardian, return a summary.

    Shared by ``ggshield ai discover`` and ``ggshield machine audit``. Discovery
    itself is local; the upload is best-effort. Returns ``None`` (after warning) when
    no API client can be built — there is nothing to summarize without the server's
    enrichment. A failed *upload* (e.g. a missing scope) still returns the local
    summary, mirroring the previous ``ai discover`` behavior.
    """
    discovery = discover_ai_configuration()

    try:
        client = create_client_from_config(config)
    except (APIKeyCheckError, UnknownInstanceError) as exc:
        ui.display_warning(
            f"Skipping upload of AI discovery to GitGuardian ({exc}). "
            "Authenticate with `ggshield auth login` to enable upload."
        )
        return None

    backfill_report = BackfillReport()
    try:
        discovery = submit_ai_discovery(client, discovery)
        save_discovery_cache(discovery)
        if scan_history:
            backfill_report = backfill_mcp_history(client, discovery)
    except Exception as exc:
        if "missing the following scope:" in str(exc):
            scope = str(exc).split("missing the following scope:")[1].strip()
            reason = (
                f"this command requires the {scope} scope. "
                f'Run ggshield auth login --scopes "{scope}" to grant it.'
            )
        else:
            reason = str(exc)
        ui.display_warning(f"Could not upload AI discovery to GitGuardian: {reason}")

    # Summarize after sending to GIM, so we can benefit from its fixes.
    return _summarize_discovery(discovery, backfill_report)


def _summarize_discovery(config: AIDiscovery, report: BackfillReport) -> Dict[str, Any]:
    """Summarize what we want to show of the discovery."""
    servers = []
    for server in config.servers:
        projects = set()
        agents = set()
        installed_globally = False
        for conf in server.configurations:
            agents.add(conf.agent)
            if conf.scope == Scope.USER:
                installed_globally = True
            elif conf.project:
                projects.add(conf.project)
        servers.append(
            {
                # If we don't have a display name, any configuration name
                # is probably less confusing than our deduplication key
                "name": server.display_name or server.configurations[0].name,
                "installed_globally": installed_globally,
                "projects": sorted(projects),
                "agents": sorted(AGENTS[name].display_name for name in agents),
            }
        )
    servers = sorted(servers, key=lambda x: x["name"])
    agents = sorted(
        (
            {
                "name": AGENTS[agent.name].display_name,
                "hooks_installed": agent.hooks_installed,
            }
            for agent in config.agents
        ),
        key=lambda x: x["name"],
    )
    return {
        "agents": agents,
        "servers": servers,
        "history": {
            "parsed": report.parsed,
            "ingested": report.ingested,
            "duplicates": report.duplicates,
            "skipped": report.skipped,
        },
    }


def print_summary(summary: Dict[str, Any]) -> None:
    """Print the summary of the discovery."""
    agents: List[Dict[str, Any]] = summary.get("agents", [])
    servers: List[Dict[str, Any]] = summary.get("servers", [])

    nb_servers = len(servers)
    nb_agents = len(agents)

    if nb_servers == 0:
        click.echo(format_text("No MCP servers discovered", STYLE["no_secret"]))
        return

    def _format_agent(agent: Dict[str, Any]) -> str:
        name = format_text(agent.get("name", "unknown"), STYLE["heading"])
        status = "hooks installed" if agent.get("hooks_installed") else "no hooks"
        return f"{name} ({status})"

    click.echo(
        f"\n{format_text('Agents discovered:', STYLE['key'])} "
        f"{', '.join(_format_agent(agent) for agent in agents) if agents else 'none'} "
        f"({nb_agents} {pluralize('agent', nb_agents)})"
    )
    click.echo(
        f"{format_text('MCP servers found:', STYLE['key'])} "
        f"{nb_servers} {pluralize('server', nb_servers)}\n"
    )

    for server in servers:
        name = server.get("name", "unknown")
        installed_globally = server.get("installed_globally", False)
        projects: List[str] = server.get("projects", [])
        server_agents: List[str] = server.get("agents", [])

        start = format_text(">", STYLE["detector_line_start"])
        server_name = format_text(name, STYLE["detector"])
        agents_names = ", ".join(
            format_text(agent, STYLE["heading"]) for agent in server_agents
        )
        click.echo(f"{start} {server_name} ({agents_names})")

        indent = "   "
        scope = "user" if installed_globally else "project"
        click.echo(f"{indent}{format_text('Scope:', STYLE['key'])} {scope}")
        if projects:
            click.echo(f"{indent}{format_text('Projects:', STYLE['key'])}")
            for j, project in enumerate(projects):
                connector = "└─" if j == len(projects) - 1 else "├─"
                click.echo(f"{indent}{connector} {project}")

    click.echo()

    history = summary.get("history")
    if history and history.get("parsed"):
        click.echo(f"{format_text('Backfilling MCP usage history…', STYLE['key'])}")
        click.echo(f"  • Parsed {history['parsed']:,} events")
        click.echo(
            f"  • Recorded {history['ingested']:,} events "
            f"({history['duplicates']:,} already known, "
            f"{history.get('skipped', 0):,} skipped)"
        )
