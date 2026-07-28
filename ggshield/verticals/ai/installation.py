import json
import os
import shlex
import shutil
import sys
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence, Tuple

import click
from pygitguardian.models import HealthCheckResponse

from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.dirs import get_user_home_dir
from ggshield.core.errors import UnexpectedError
from ggshield.core.text_utils import pluralize

from .agents import AGENTS, Agent


@dataclass
class InstallationStats:
    added: int = 0
    already_present: int = 0
    command: str = ""


@dataclass
class BuildConfigResult:
    agent: Agent
    settings_path: Path
    new_config: Dict[str, Any]
    stats: InstallationStats


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

    How the path is recovered depends on the launch:

    - Frozen standalone bundle (``.pkg``/``.deb``/``.rpm``): ``sys.executable``.
    - Bare name (``ggshield``, the pip/pipx/Homebrew case): the shell does not
      absolutize ``sys.argv[0]``, so resolve it against PATH with
      ``shutil.which``.
    - Explicit or relative path (``/opt/homebrew/bin/ggshield``,
      ``./ggshield``): ``abspath``.

    Symlinks are kept unresolved so a package manager's stable launcher
    survives upgrades.
    """
    if getattr(sys, "frozen", False):
        executable = sys.executable
    else:
        argv0 = sys.argv[0]
        if os.path.dirname(argv0):
            executable = os.path.abspath(argv0)
        else:
            # On a PATH miss fall back to abspath, never sys.executable
            # (the Python interpreter, not ggshield).
            executable = shutil.which(argv0) or os.path.abspath(argv0)
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

    result = build_hook_config(name, mode, force)
    settings_path = result.settings_path
    new_config = result.new_config
    stats = result.stats
    display_name = result.agent.display_name
    # Ensure parent directory exists
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the updated config
    with settings_path.open("w", encoding="utf-8") as f:
        json.dump(new_config, f, indent=2)
        f.write("\n")

    # Report what happened
    styled_path = click.style(settings_path, fg="yellow", bold=True)
    if stats.added == 0 and stats.already_present > 0:
        click.echo(f"{display_name} hooks already installed in {styled_path}")
    elif stats.added > 0 and stats.already_present > 0:
        click.echo(f"{display_name} hooks updated in {styled_path}")
    else:
        click.echo(f"{display_name} hooks successfully added in {styled_path}")

    return 0


def build_hook_config(
    name: str, mode: Literal["local", "global"], force: bool = False
) -> BuildConfigResult:
    """Build the hook configuration for the AI hook.

    Args:
        name: Name of the AI coding tool
        mode: Mode of the hook installation

    Returns the updated hook configuration and statistics
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
        command="",
    )

    stats = _fill_dict(
        config=existing_config,
        template=agent.settings_template,
        command=command,
        overwrite=force,
        stats=stats,
        locator=agent.settings_locate,
    )

    return BuildConfigResult(
        agent=agent,
        settings_path=settings_path,
        new_config=existing_config,
        stats=stats,
    )


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
            cmd = config.get(key, "")
            if isinstance(cmd, str) and "ggshield" in cmd:
                stats.already_present += 1
                stats.command = cmd
            # Update if needed
            if overwrite:
                config[key] = value
            if config[key] == "<COMMAND>":
                config[key] = command
                stats.added += 1

    return stats


def are_hooks_installed_globally(agent_name: str) -> Tuple[bool, Optional[str]]:
    """Whether the ggshield AI hooks are installed in this agent's global settings file."""
    result = build_hook_config(agent_name, "global")
    return (
        result.stats.added == 0,
        result.stats.command if result.stats.added == 0 else None,
    )


@dataclass
class AgentHookStatus:
    """Whether the ggshield AI hook is installed for one detected assistant."""

    display_name: str
    installed: bool


def ai_hook_posture() -> List[AgentHookStatus]:
    """Read-only AI-hook status: for each detected assistant, is the hook installed?

    Only assistants present on this machine are reported; it never writes anything.
    Used by ``ggshield machine doctor``.
    """
    statuses = []
    for agent in AGENTS.values():
        if agent.is_present():
            installed, _command = are_hooks_installed_globally(agent.name)
            statuses.append(
                AgentHookStatus(display_name=agent.display_name, installed=installed)
            )
    return statuses


@dataclass
class SetupSummary:
    """Outcome of configuring AI hooks across one or more agents."""

    configured: int = 0
    failed: int = 0


def select_agents(only: Sequence[str], exclude: Sequence[str]) -> List[Agent]:
    """Pick which agents ``machine setup`` should configure.

    With no flags, returns every agent detected on this machine. ``only``
    restricts to an explicit list (configured even when not yet present, since
    the user named them). ``exclude`` drops agents from the detected set.
    """
    if only:
        return [AGENTS[name] for name in only]
    agents = [agent for agent in AGENTS.values() if agent.is_present()]
    if exclude:
        excluded = set(exclude)
        agents = [agent for agent in agents if agent.name not in excluded]
    return agents


def install_all_agent_hooks(
    only: Sequence[str] = (),
    exclude: Sequence[str] = (),
    force: bool = False,
) -> SetupSummary:
    """Install the ggshield AI hook for every selected agent (user/global scope).

    This is the engine behind ``ggshield machine setup``: one command that
    configures all detected AI coding assistants instead of one per agent.
    Per-agent results are printed by :func:`install_hooks`; the returned summary
    counts how many agents were configured and how many failed.
    """
    agents = select_agents(only, exclude)
    if not agents:
        click.echo(
            "No AI coding assistants detected on this machine. "
            "Use --only <assistant> to configure one explicitly "
            f"({', '.join(sorted(AGENTS))})."
        )
        return SetupSummary()

    click.echo(
        f"Configuring ggshield AI hooks for {len(agents)} "
        f"{pluralize('assistant', len(agents))}: "
        + ", ".join(agent.display_name for agent in agents)
    )

    summary = SetupSummary()
    for agent in agents:
        if install_hooks(name=agent.name, mode="global", force=force) == 0:
            summary.configured += 1
        else:
            summary.failed += 1
    return summary


def _is_interactive() -> bool:
    """Whether setup is running with a user present at a terminal."""
    return sys.stdout.isatty()


def check_ai_hook_authentication(config: Config) -> None:
    """Verify the freshly configured AI hook will be able to authenticate.

    The hook runs as an agent-spawned, non-interactive process, where an auth
    failure would otherwise only show up as a warning on every tool call.
    Checking now also makes the OS credentials store ask for access (e.g. the
    macOS Keychain authorization prompt) while the user can still answer it.

    Skip this in non-interactive runs (CI, automated fleet/MDM provisioning):
    there is no one to answer a credential-store popup or read the result, and
    triggering the prompt there would be disruptive.
    """
    if not _is_interactive():
        return
    try:
        client = create_client_from_config(config)
        response = client.health_check()
        if not isinstance(response, HealthCheckResponse) or response.status_code != 200:
            raise UnexpectedError(str(getattr(response, "detail", response)))
    except Exception as exc:
        ui.display_warning(
            f"The hook is installed but ggshield cannot reach GitGuardian: {exc}\n"
            "The hook will NOT scan anything until this is fixed. Run "
            "'ggshield auth login' to authenticate, then 'ggshield api-status' "
            "to check."
        )
    else:
        click.echo("ggshield successfully authenticated: the hook is ready to scan.")
