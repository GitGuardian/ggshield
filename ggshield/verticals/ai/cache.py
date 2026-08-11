import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from marshmallow.exceptions import ValidationError
from pygitguardian.models import AIDiscovery, MCPConfiguration, MCPServer

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.dirs import get_cache_dir

from .models import Scope


AI_DISCOVERY_CACHE_FILENAME = "ai_discovery.json"

VERDICT_CACHE_FILENAME = "ai_hook_verdicts.json"
# The key covers what we send (see verdict_key), so an entry can only go stale
# if the server's answer changes — hence a short TTL.
VERDICT_CACHE_TTL_SECONDS = 15 * 60
VERDICT_CACHE_MAX_ENTRIES = 500

# The walk inventories assistant configuration files, which change on the order of
# days, but it runs on *every* MCP tool call. One hour keeps staleness well under a
# coding session while making the walk negligible.
DISCOVERY_CACHE_TTL_SECONDS = 3600

# time.time() and the filesystem mtime do not come from the same clock source, so a
# just-touched file can read marginally in the future (the Windows system timer has a
# ~16ms granularity). Tolerate that much skew, while still treating a real clock jump
# as stale rather than pinning the cache fresh forever.
MTIME_SKEW_TOLERANCE_SECONDS = 5


def _discovery_cache_path() -> Path:
    return get_cache_dir() / AI_DISCOVERY_CACHE_FILENAME


def save_discovery_cache(config: AIDiscovery) -> None:
    """
    Save probe results to cache.
    """
    cache_path = _discovery_cache_path()
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(config.to_dict(), indent=4))
    except OSError:
        pass


def load_discovery_cache() -> Optional[AIDiscovery]:
    """Load discovery cache if it exists.

    Returns None if the cache does not exist.
    """
    cache_path = _discovery_cache_path()
    if not cache_path.exists():
        return None
    try:
        return AIDiscovery.from_dict(json.loads(cache_path.read_text()))
    except (OSError, json.JSONDecodeError, ValidationError):
        return None


def config_fingerprint(secret_config: SecretConfig) -> str:
    """The settings that change what we send or how we read the answer.

    Only these: a setting that merely changes what we print would cost cache
    misses without preventing a stale verdict.

    - filename_only rewrites the filename we send, and the key holds the local one
    - all_secrets moves locally-ignored breaks into `secrets` instead of
      `ignored_secrets_count_by_kind`, which is the guard that decides whether a
      verdict is cacheable at all
    - source_uuid switches the endpoint to scan_and_create_incidents; the hook
      clears it, so it is constant today, but stays in the key so a verdict from
      an older ggshield is never served here

    The ignore settings (ignored_matches, ignored_detectors,
    ignore_known_secrets) are deliberately absent: a verdict that depended on
    them is never stored, see AIHookScanner._scan_content.
    """
    return (
        f"all_secrets={int(secret_config.all_secrets)};"
        f"filename_only={int(secret_config.filename_only)};"
        f"source_uuid={secret_config.source_uuid or ''}"
    )


def verdict_key(
    instance: str,
    api_key: str,
    secret_config: SecretConfig,
    filename: str,
    content: str,
) -> str:
    """Cache key for one document: everything the API's answer depends on.

    The document we send (content and filename), the instance and token, because
    custom detectors and dashboard exclusions are per-workspace, and the config
    that shapes the request (see config_fingerprint).

    NUL separates the parts: it cannot appear in a URL, a token or a path.
    `surrogatepass` rather than `replace`: this key must not be lossy.
    """
    joined = "\0".join(
        (instance, api_key, config_fingerprint(secret_config), filename, content)
    )
    return hashlib.sha256(joined.encode("utf-8", "surrogatepass")).hexdigest()


def _verdict_cache_path() -> Path:
    return get_cache_dir() / VERDICT_CACHE_FILENAME


def _load_verdicts() -> Dict[str, float]:
    """Load the cached clean verdicts, or an empty mapping if the cache can't be trusted.

    Every failure path returns an empty mapping, so the caller scans: a broken
    or suspicious cache must never turn into an "allow". This only rules out
    *other* users; whoever can write as us could replace ggshield itself.
    """
    path = _verdict_cache_path()
    try:
        # Check the descriptor, not the path: O_NOFOLLOW refuses a symlink, and
        # fstat leaves no window for a swap between check and read.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r", encoding="utf-8") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode):
                return {}
            # Windows does not use these bits, and reports them set on every file.
            if os.name == "posix" and (
                info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or info.st_uid != os.getuid()
            ):
                # Group/other-writable, or somebody else's: not a file only we
                # could have produced.
                return {}
            data = json.loads(file.read())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Unbounded on purpose: store_clean_verdict() caps what we write, and
    # truncating before validation would let junk entries evict real ones.
    return {
        key: float(value)
        for key, value in data.items()
        if isinstance(key, str) and isinstance(value, (int, float))
    }


def _is_fresh(stored: float, now: float) -> bool:
    # A timestamp in the future is clock skew, or a forged never-expiring entry.
    return 0 <= now - stored < VERDICT_CACHE_TTL_SECONDS


def has_clean_verdict(key: str) -> bool:
    """Whether `key` (see `verdict_key`) was scanned clean recently enough to skip
    the API call."""
    stored = _load_verdicts().get(key)
    return stored is not None and _is_fresh(stored, time.time())


def store_clean_verdict(key: str) -> None:
    """Remember that `key` was scanned clean. Best effort, failures are ignored."""
    now = time.time()
    verdicts = _load_verdicts()
    verdicts[key] = now
    # Drop expired entries and keep the cache bounded, newest kept first.
    kept = sorted(
        ((key, ts) for key, ts in verdicts.items() if _is_fresh(ts, now)),
        key=lambda item: item[1],
        reverse=True,
    )[:VERDICT_CACHE_MAX_ENTRIES]
    path = _verdict_cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # 0600 on creation, and never through a symlink. No file lock: a lost or
        # torn write costs a cache miss, and a miss simply scans.
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(fd, "w") as file:
            # O_CREAT's mode only applies to a file we actually created: force
            # it, so a pre-existing loose-permission file — which _load_verdicts
            # refuses to read — doesn't disable the cache for good.
            if hasattr(os, "fchmod"):
                os.fchmod(file.fileno(), 0o600)
            json.dump(dict(kept), file)
    except OSError:
        pass


def is_discovery_cache_fresh() -> bool:
    """Tell whether the cached discovery was refreshed less than the TTL ago."""
    try:
        age = time.time() - _discovery_cache_path().stat().st_mtime
    except OSError:
        return False
    return -MTIME_SKEW_TOLERANCE_SECONDS <= age < DISCOVERY_CACHE_TTL_SECONDS


def touch_discovery_cache() -> None:
    """Reset the TTL of the cache, without rewriting its unchanged content."""
    try:
        _discovery_cache_path().touch()
    except OSError:
        pass


def has_changed_from(current: AIDiscovery, other: AIDiscovery) -> bool:
    """Check if the discovery has changed since a previous discovery."""
    # We compare :
    # 1. user info exactly
    if current.user != other.user:
        return True

    # 1b. agent hook installation status
    if current.agents != other.agents:
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
