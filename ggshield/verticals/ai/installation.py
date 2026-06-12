import json
import os
import shlex
import sys
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional

import click

from ggshield.core.dirs import get_user_home_dir
from ggshield.core.errors import UnexpectedError

from .agents import AGENTS


@dataclass
class InstallationStats:
    added: int
    already_present: int


def build_hook_command() -> str:
    """Build the AI hook command line written into the agent's settings.

    Pin the hook to the absolute path of the ggshield that is running
    ``install``, rather than a bare ``ggshield``. The hook runs as an
    agent-spawned process whose PATH is neither the user's shell PATH nor stable
    across launch contexts (a terminal-launched agent and a GUI-launched one can
    see different PATHs). On a machine with more than one ggshield install (e.g.
    Homebrew plus an MDM-managed copy on macOS), a bare command can resolve to a
    *different* binary than the one the user authenticated with, which then fails
    to read the stored token.

    We trust whatever executable ran ``install`` (``sys.argv[0]``); we only make
    it absolute and shell-quote it. ``abspath`` does not resolve symlinks, so a
    package manager's stable launcher (e.g. ``/opt/homebrew/bin/ggshield``) is
    kept rather than a version-pinned path that would break on upgrade.
    """
    executable = os.path.abspath(sys.argv[0])
    return f"{_quote_executable(executable)} secret scan ai-hook"


def _quote_executable(path: str) -> str:
    """Quote an executable path for use in a shell-run hook command string."""
    if os.name == "nt":
        # Agents run the command through a shell; quote only when needed to
        # avoid disturbing parsers that don't expect quoting.
        return f'"{path}"' if " " in path else path
    return shlex.quote(path)


def install_hooks(
    name: str, mode: Literal["local", "global"], force: bool = False
) -> int:
    """Install the hooks for the AI hook.

    Args:
        name: Name of the AI coding tool
        mode: Mode of the hook installation
        force: Whether to force the installation

    Returns an error code (0 on success, 1 on failure)
    """

    try:
        agent = AGENTS[name]
    except KeyError:
        raise ValueError(f"Unsupported agent: {name}")

    base_dir = get_user_home_dir() if mode == "global" else Path(".")
    settings_path = base_dir / agent.settings_path(mode)

    command = build_hook_command()

    # Load existing config or create new one
    existing_config: dict = {}

    if settings_path.exists():
        try:
            with settings_path.open("r", encoding="utf-8") as f:
                existing_config = json.load(f)
        except json.JSONDecodeError as e:
            raise UnexpectedError(
                f"Failed to parse {settings_path}: {e}. "
                "Please fix or remove the file before installing hooks."
            )

    # Track what we did for reporting
    stats = InstallationStats(
        added=0,
        already_present=0,
    )

    stats = _fill_dict(
        config=existing_config,
        template=agent.settings_template,
        command=command,
        overwrite=force,
        stats=stats,
        locator=agent.settings_locate,
    )

    # Ensure parent directory exists
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the updated config
    with settings_path.open("w", encoding="utf-8") as f:
        json.dump(existing_config, f, indent=2)
        f.write("\n")

    # Report what happened
    styled_path = click.style(settings_path, fg="yellow", bold=True)
    if stats.added == 0 and stats.already_present > 0:
        click.echo(f"{agent.display_name} hooks already installed in {styled_path}")
    elif stats.added > 0 and stats.already_present > 0:
        click.echo(f"{agent.display_name} hooks updated in {styled_path}")
    else:
        click.echo(f"{agent.display_name} hooks successfully added in {styled_path}")

    return 0


def _fill_dict(
    config: Dict[str, Any],
    template: Dict[str, Any],
    command: str,
    overwrite: bool,
    stats: InstallationStats,
    locator: Callable[[List[Dict[str, Any]], Dict[str, Any]], Optional[Dict[str, Any]]],
) -> InstallationStats:
    """
    Recursively fill a dictionary with the template, leaving other keys untouched.

    Inside lists, will look for a match by searching "ggshield" anywhere in the object, otherwise add a new element.
    This means that the template cannot have multiple hooks in the same list.
    In case the need arises, the algorithm will need to be adapted.

    Args:
        config: The dictionary to fill
        template: The template to use
        command: The command to use
        overwrite: Whether to overwrite existing keys
        stats: The statistics to update
    """
    for key, value in template.items():
        # Dictionary: recurse
        if isinstance(value, dict):
            new_config = config.setdefault(key, {})
            _fill_dict(new_config, value, command, overwrite, stats, locator)
        # List: locate the correct object
        elif isinstance(value, list):
            # but first, make sure we only have one object in the template
            if len(value) != 1:
                raise ValueError(f"Expected only one object in template for {key}")

            config_list = config.setdefault(key, [])
            existing_value = locator(config_list, value[0])
            if existing_value is not None:
                # Found it. Continue with this object.
                _fill_dict(existing_value, value[0], command, overwrite, stats, locator)
            else:
                # Not found. Add new object.
                config_list.append(deepcopy(value[0]))
                _fill_dict(
                    config_list[-1], value[0], command, overwrite, stats, locator
                )

        # Scalar value: if template is the string "<COMMAND>", replace it with the command.
        else:
            if key not in config:
                config[key] = value
            # for stats
            if "ggshield" in str(config.get(key, "")):
                stats.already_present += 1
            # Update if needed
            if overwrite:
                config[key] = value
            if config[key] == "<COMMAND>":
                config[key] = command
                stats.added += 1

    return stats
