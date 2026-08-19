"""
MCP Discovery - Discovers MCP server configurations and manages probe result caches.
"""

from collections import defaultdict
from pathlib import Path
from time import perf_counter
from typing import Dict, List, Optional

from pygitguardian import GGClient
from pygitguardian.models import AgentInfo, AIDiscovery, Detail, MCPServer

from ggshield.core.errors import UnexpectedError

from .agents import AGENTS
from .cache import (
    has_changed_from,
    is_discovery_cache_fresh,
    load_discovery_cache,
    save_discovery_cache,
    touch_discovery_cache,
)
from .installation import are_hooks_installed_globally
from .models import MCPConfiguration
from .user import get_user_info


def refresh_and_maybe_submit_discovery(client: GGClient) -> AIDiscovery:
    """Run discovery unless the cache is still fresh, compare with cache, submit only
    if changed."""
    cached = load_discovery_cache()

    # This runs on every MCP tool call: trust a recent walk rather than redo it.
    if cached is not None and is_discovery_cache_fresh():
        return cached

    # If we already have a machine id, reuse it.
    machine_id = cached.user.machine_id if cached is not None else None
    discovery = discover_ai_configuration(machine_id=machine_id)

    # Nothing changed,
    if cached is not None and not has_changed_from(discovery, cached):
        touch_discovery_cache()
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

    # Only the agents installed on this machine, because a configuration file can
    # belong to several agents (a project `.mcp.json` is read by both Claude Code
    # and Copilot). Reporting a configuration for an absent agent would attribute
    # it to an agent missing from `agents` below, which is what the API keys on.
    present_agents = [agent for agent in AGENTS.values() if agent.is_present()]

    # Discovered project directories
    projects = {Path.cwd().resolve()}
    for agent in present_agents:
        projects.update(agent.discover_project_directories())

    # Discover MCP configurations
    for agent in present_agents:
        mcp_configurations.extend(agent.discover_mcp_configurations(projects))

    # Hook installation status
    agents = []
    for agent in present_agents:
        installed, command = are_hooks_installed_globally(agent.name)
        agents.append(
            AgentInfo(
                name=agent.name,
                hooks_installed=installed,
                hooks_command=command,
                subscription_email=agent.subscription_email(),
            )
        )

    # Merge MCP configurations into servers
    servers = _merge_mcp_configurations(mcp_configurations)

    # Try to find the servers' capabilities
    for server in servers:
        for agent in present_agents:
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
