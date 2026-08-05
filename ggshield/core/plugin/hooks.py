"""
Plugin hooks - utilities for integrating plugins into existing commands.
"""

import logging
from typing import Optional

from ggshield.core.plugin.registry import PluginRegistry


logger = logging.getLogger(__name__)

_global_registry: Optional[PluginRegistry] = None
_load_error: Optional[str] = None


def set_plugin_registry(registry: PluginRegistry) -> None:
    """Set the global plugin registry.

    Injection point for plugin code and tests only: in-tree code goes through
    `load_plugin_registry()`, which populates the global itself.
    """
    global _global_registry
    _global_registry = registry


def get_plugin_registry() -> Optional[PluginRegistry]:
    """Get the global plugin registry, without loading it.

    Returns None until something loads it, so in-tree code uses
    `load_plugin_registry()`; kept for plugin code that must not trigger a load.
    """
    return _global_registry


def load_plugin_registry() -> PluginRegistry:
    """Get the global plugin registry, loading enabled plugins if needed.

    This is the expensive path (plugin discovery + wheel signature
    verification), so it is called only when plugin commands or plugin status
    are actually needed, never on every ggshield invocation. A failure to load
    yields an empty registry rather than an error: individual load failures are
    reported by the registry itself.
    """
    global _global_registry
    if _global_registry is None:
        # Function-local imports: keep the loader (and sigstore & co) off the
        # import path of commands that never touch plugins.
        from ggshield.core.config.enterprise_config import EnterpriseConfig
        from ggshield.core.plugin.loader import PluginLoader

        try:
            enterprise_config = EnterpriseConfig.load_effective()
            _global_registry = PluginLoader(enterprise_config).load_enabled_plugins()
        except Exception as e:
            global _load_error
            _load_error = str(e)
            logger.warning("Failed to load plugins: %s", e)
            _global_registry = PluginRegistry()
    return _global_registry


def get_plugin_load_error() -> Optional[str]:
    """Why the last `load_plugin_registry()` gave up, if it did.

    The failure is swallowed there so a broken plugin install cannot take the
    CLI down, and logging is still disabled while commands are resolved, so
    the log line alone never reaches the user. Callers that can display it
    (and that know whether displaying it is safe -- shell completion parses
    stdout) ask for it here.
    """
    return _load_error
