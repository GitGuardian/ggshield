import json
from typing import Dict, Optional, Tuple

from marshmallow.exceptions import ValidationError
from pygitguardian.models import AIDiscovery

from ggshield.core.dirs import get_cache_dir
from ggshield.utils.files import atomic_write_text

from .models import MCPConfiguration, MCPServer, Scope


AI_DISCOVERY_CACHE_FILENAME = "ai_discovery.json"


def save_discovery_cache(config: AIDiscovery) -> None:
    """
    Save probe results to cache.
    """
    cache_path = get_cache_dir() / AI_DISCOVERY_CACHE_FILENAME
    try:
        atomic_write_text(cache_path, json.dumps(config.to_dict(), indent=4))
    except OSError:
        pass


def load_discovery_cache() -> Optional[AIDiscovery]:
    """Load discovery cache if it exists.

    Returns None if the cache does not exist.
    """
    cache_path = get_cache_dir() / AI_DISCOVERY_CACHE_FILENAME
    if not cache_path.exists():
        return None
    try:
        return AIDiscovery.from_dict(json.loads(cache_path.read_text()))
    except (OSError, json.JSONDecodeError, ValidationError):
        return None


def has_changed_from(current: AIDiscovery, other: AIDiscovery) -> bool:
    """Check if the discovery has changed since a previous discovery."""
    # We compare :
    # 1. user info exactly
    if current.user != other.user:
        return True

    # 2. MCP configurations should be the same (both in number and content)
    other_configurations = _confs_by_key(other)
    new_configurations = _confs_by_key(current)
    if other_configurations != new_configurations:
        return True

    # 3. Servers may have been overriden by GIM, but we still want to detect
    #    whether we discovered new capabilities unknown to GIM.
    # First, build a map to find the server(s) to compare to
    # (we know that the keys will be exactly our configurations, thanks to step 2)
    other_servers: Dict[ConfigurationKey, MCPServer] = {}
    for server in other.servers:
        for configuration in server.configurations:
            other_servers[_key(configuration)] = server
    # Then, for each server we found, check if we have capabilities unknown to GIM
    for server in current.servers:
        # No data, no need to compare
        if not server.tools and not server.resources and not server.prompts:
            continue
        # We don't know how our naive deduplication have been overriden by GIM,
        # so we need to compare capabilities to each distinct destination.
        candidates_by_name: Dict[str, MCPServer] = {}
        for conf in server.configurations:
            other_server = other_servers[_key(conf)]
            candidates_by_name[other_server.name] = other_server
        # If at least one has our capabilities, then no need to update.
        # said otherwise, update if all candidates don't have our capabilities.
        if all(
            _server_has_capabilities_unknown_to(server, candidate)
            for candidate in candidates_by_name.values()
        ):
            return True

    return False


ConfigurationKey = Tuple[str, Scope, Optional[str], str]


def _key(conf: MCPConfiguration) -> ConfigurationKey:
    """Return a unique key for the configuration.

    We consider that their should be unicity over (agent, scope, project, name)
    """
    return (conf.agent, conf.scope, conf.project, conf.name)


def _confs_by_key(discovery: AIDiscovery) -> Dict[ConfigurationKey, MCPConfiguration]:
    by_key = {}
    for server in discovery.servers:
        for conf in server.configurations:
            by_key[_key(conf)] = conf
    return by_key


def _server_has_capabilities_unknown_to(server: MCPServer, other: MCPServer) -> bool:
    """Check if the server has capabilities unknown to the other server."""
    # Note: we assume that if we have discovered a capability,
    # then we have everything (name, description, etc.)
    # So we simply check if we have names the other doesn't.
    other_tools = {tool.name for tool in other.tools}
    for tool in server.tools:
        if tool.name not in other_tools:
            return True

    other_resources = {resource.uri for resource in other.resources}
    for resource in server.resources:
        if resource.uri not in other_resources:
            return True

    other_prompts = {prompt.name for prompt in other.prompts}
    for prompt in server.prompts:
        if prompt.name not in other_prompts:
            return True

    return False
