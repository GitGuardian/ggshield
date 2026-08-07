import json
import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import MutableMapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence, Tuple

import click
import tomlkit
from pygitguardian.models import HealthCheckResponse
from tomlkit.exceptions import TOMLKitError


if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

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
    new_config: MutableMapping[str, Any]
    stats: InstallationStats


_HOOK_ARGS = "secret scan ai-hook"


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
      PyInstaller derives it from the OS, so under the Rust dispatcher it names
      the internal ``ggshield-py`` launcher.
    - Bare name (``ggshield``, the pip/pipx/Homebrew case): the shell does not
      absolutize ``sys.argv[0]``, so resolve it against PATH with
      ``shutil.which``.
    - Explicit or relative path (``/opt/homebrew/bin/ggshield``,
      ``./ggshield``): ``abspath``.

    Whatever comes out, a sibling ``ggshield`` dispatcher wins over it — see
    :func:`_prefer_dispatcher_sibling`.

    Symlinks are left unresolved in the code paths that see them: the
    pip/pipx/Homebrew cases go through ``shutil.which``/``abspath``, which do not
    follow the final symlink, so a stable ``…/bin/ggshield`` launcher keeps
    working across upgrades.

    The frozen path is the one place where a symlink is already gone: the OS
    resolves ``sys.executable`` for PyInstaller, and on the macOS bundle it
    resolves into a *versioned* ``/opt/gitguardian/ggshield-<version>/``
    directory that the next upgrade deletes. A stable launcher
    (``/usr/local/bin/ggshield``, ``/usr/bin/ggshield``) is therefore preferred
    when it resolves to that same binary, so the hook survives upgrades.
    """
    return f"{_quote_executable(hook_executable())} {_HOOK_ARGS}"


def hook_executable() -> str:
    """The ggshield binary the hook should run. See `build_hook_command`."""
    frozen = getattr(sys, "frozen", False)
    if frozen:
        executable = sys.executable
    else:
        argv0 = sys.argv[0]
        if os.path.dirname(argv0):
            executable = os.path.abspath(argv0)
        else:
            # On a PATH miss fall back to abspath, never sys.executable
            # (the Python interpreter, not ggshield).
            executable = shutil.which(argv0) or os.path.abspath(argv0)
    executable = _prefer_dispatcher_sibling(executable)
    # The stable launcher points at the dispatcher, so it can only match once
    # the sibling preference has run. Only the frozen path needs it: elsewhere
    # the path never went through a symlink resolution.
    return _stable_launcher(executable) if frozen else executable


def _prefer_dispatcher_sibling(executable: str) -> str:
    """Return the Rust ``ggshield`` dispatcher next to ``executable``, if any.

    Every install that ships the dispatcher puts it next to the Python entry
    point, under the two names ``ggshield`` and ``ggshield-py``: the standalone
    bundles (where PyInstaller's ``sys.executable`` is the ``ggshield-py``
    launcher) and the platform wheels (where ``ggshield`` execs ``ggshield-py``,
    so by the time Python runs, ``sys.argv[0]`` is ``ggshield-py`` too). Writing
    that Python path into the hook works, but pays the whole Python startup on
    every agent tool call — the one cost the dispatcher exists to remove.

    Installs with no dispatcher (pure wheel, older bundles) keep ``executable``:
    there, it already *is* ``ggshield``.
    """
    dispatcher = os.path.join(
        os.path.dirname(executable),
        "ggshield" + (".exe" if os.name == "nt" else ""),
    )
    if os.path.normpath(dispatcher) != os.path.normpath(executable) and os.access(
        dispatcher, os.X_OK
    ):
        return dispatcher
    return executable


def _stable_launcher(executable: str) -> str:
    """A version-independent launcher for `executable`, or `executable` itself.

    Substitution requires the launcher to resolve to the very same file: on a
    machine carrying several ggshield installs (Homebrew alongside the bundle),
    the other one is a binary the user never authenticated. A launcher that does
    not exist resolves to itself, so the comparison simply fails.
    """
    if os.name == "nt":
        return executable
    target = os.path.realpath(executable)
    for launcher in ("/usr/local/bin/ggshield", "/usr/bin/ggshield"):
        if os.path.realpath(launcher) == target:
            return launcher
    return executable


def _hook_command_executable(command: str) -> Optional[str]:
    """The ggshield path in a hook command, or None when the command is not ours.

    Anything carrying extra arguments is the user's own command, not one we wrote.
    """
    suffix = f" {_HOOK_ARGS}"
    if not command.endswith(suffix):
        return None
    windows = os.name == "nt"
    try:
        # posix=False keeps Windows path separators, which posix mode would eat
        # as escapes; it also keeps the quotes, hence the strip below.
        parts = shlex.split(command[: -len(suffix)], posix=not windows)
    except ValueError:
        # Unbalanced quote in a hand-edited command: not one of ours.
        return None
    if len(parts) != 1:
        return None
    return parts[0].strip('"') if windows else parts[0]


def _is_outdated_hook_command(existing: str, command: str) -> bool:
    """Whether an installed hook command should be repointed at `command`.

    True for a ggshield command whose binary is gone (a versioned bundle
    directory an upgrade removed) or that reaches the same binary through a less
    stable path. Anything else belongs to the user and is left alone.
    """
    if existing == command:
        return False
    installed = _hook_command_executable(existing)
    new = _hook_command_executable(command)
    if installed is None or new is None:
        return False
    if "ggshield" not in os.path.basename(installed):
        return False
    return not os.path.exists(installed) or os.path.realpath(
        installed
    ) == os.path.realpath(new)


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

    # Write the updated config in the assistant's native format.
    with settings_path.open("w", encoding="utf-8") as f:
        if result.agent.settings_format == "toml":
            f.write(tomlkit.dumps(new_config))
        else:
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

    if warning := result.agent.post_install_warning(mode):
        ui.display_warning(warning)

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
    existing_config: MutableMapping[str, Any] = (
        tomlkit.document() if agent.settings_format == "toml" else {}
    )

    if settings_path.exists():
        try:
            with settings_path.open("r", encoding="utf-8") as f:
                if agent.settings_format == "toml":
                    raw_config = f.read()
                    # Two parsers on purpose, don't drop either one:
                    # - tomllib validates. tomlkit silently *repairs* some
                    #   malformed input ("[[hooks]" becomes "[[hooks]]"), so on
                    #   its own it would rewrite a broken file into a different
                    #   one instead of telling the user to fix it.
                    # - tomlkit then builds the editable document, because it is
                    #   the only one of the two that can write back, and it keeps
                    #   the comments and formatting of a file the user hand-edits.
                    tomllib.loads(raw_config)
                    existing_config = tomlkit.parse(raw_config)
                else:
                    existing_config = json.load(f)
        # TOMLKitError, not just its ParseError subclass: a duplicate key in an
        # inline table raises KeyAlreadyPresent, which is not a ParseError.
        except (json.JSONDecodeError, tomllib.TOMLDecodeError, TOMLKitError) as e:
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

    try:
        stats = _fill_dict(
            config=existing_config,
            template=agent.settings_template,
            command=command,
            overwrite=force,
            stats=stats,
            locator=agent.settings_locate,
        )
    except ValueError as e:
        # The file parsed but does not have the shape we can merge into.
        raise UnexpectedError(
            f"Failed to update {settings_path}: {e}. "
            "Please fix or remove the file before installing hooks."
        )

    return BuildConfigResult(
        agent=agent,
        settings_path=settings_path,
        new_config=existing_config,
        stats=stats,
    )


def _fill_dict(
    config: MutableMapping[str, Any],
    template: Dict[str, Any],
    command: str,
    overwrite: bool,
    stats: InstallationStats,
    locator: Callable[[List[Dict[str, Any]], Dict[str, Any]], Optional[Dict[str, Any]]],
) -> InstallationStats:
    """
    Recursively fill a dictionary with the template, leaving other keys untouched.

    Inside lists, `locator` finds the object to update, otherwise a new element is
    added. A template list may hold several objects: each is located independently,
    so an agent can declare more than one hook in the same list.

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
            config_list = config.setdefault(key, [])
            if not isinstance(config_list, list):
                raise ValueError(f"expected a list of objects at '{key}'")
            # Ignore anything that isn't an object: the file is hand-editable and a
            # stray scalar must not crash the install.
            candidates = [item for item in config_list if isinstance(item, dict)]
            for template_item in value:
                if not isinstance(template_item, dict):
                    raise ValueError(f"Expected objects in template list for {key}")
                existing_value = locator(candidates, template_item)
                if existing_value is not None:
                    # Found it. Continue with this object.
                    _fill_dict(
                        existing_value,
                        template_item,
                        command,
                        overwrite,
                        stats,
                        locator,
                    )
                else:
                    # Not found. Add a new object.
                    config_list.append(deepcopy(template_item))
                    _fill_dict(
                        config_list[-1],
                        template_item,
                        command,
                        overwrite,
                        stats,
                        locator,
                    )

        # Scalar value: if template is the string "<COMMAND>", replace it with the command.
        else:
            if key not in config:
                config[key] = value
            # For stats: only the command slot tells us whether ggshield is already
            # installed. Other scalars may legitimately contain "ggshield" — a hook
            # name, for instance — and must not be counted as an existing install.
            cmd = config.get(key, "")
            if value == "<COMMAND>" and isinstance(cmd, str) and "ggshield" in cmd:
                stats.already_present += 1
                stats.command = cmd
                # An upgrade invalidates a versioned bundle path, and the hook
                # then fails open: every prompt goes unscanned.
                if _is_outdated_hook_command(cmd, command):
                    config[key] = "<COMMAND>"
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
    _warm_hook_credential_store()


# An event the hook answers by scanning the prompt and nothing else: no file is
# named, so it reads its token, asks the API about this one line, and exits.
_WARM_UP_EVENT = json.dumps(
    {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "ggshield-machine-setup",
        "transcript_path": "ggshield-machine-setup/claude-code.jsonl",
        "prompt": "ggshield setup: checking the AI hook can read its token.",
    }
)


def _warm_hook_credential_store() -> None:
    """Have the hook binary itself read the token once, with the user present.

    Keychain ACLs are per code identity, and in the standalone bundle the hook is
    the Rust dispatcher, not the ``ggshield-py`` process running setup: the
    authentication check grants nothing to the binary that does the reading. Its
    own authorization dialog would first appear inside an agent-spawned hook,
    where the agent's timeout can kill the process before an answered "Always
    Allow" is recorded, so the dialog comes back on every turn.

    Only macOS grants per binary, and only the bundle runs the hook from another
    binary: everywhere else the token has already been read by the identity the
    hook will use.
    """
    if sys.platform != "darwin" or not getattr(sys, "frozen", False):
        return
    executable = hook_executable()
    if executable == sys.executable:
        return
    try:
        subprocess.run(
            [executable, "secret", "scan", "ai-hook"],
            input=_WARM_UP_EVENT,
            text=True,
            capture_output=True,
            # Room to answer a Keychain dialog, and a bound so setup cannot hang
            # on one nobody answers.
            timeout=60,
            check=False,
        )
    except Exception:
        pass
