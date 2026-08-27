import subprocess
from pathlib import Path
from typing import Any, Optional, Set, Tuple

import click
import requests
from packaging import version as packaging_version

from ggshield.cmd.honeytoken.plant import ALL_TYPES, plant_cmd
from ggshield.cmd.install import (
    get_default_global_hook_dir_path,
    get_default_system_hook_dir_path,
    get_global_hook_dir_path,
    get_shadowing_hooks_path,
    get_system_hook_dir_path,
    hook_invokes_ggshield,
    hook_is_outdated,
    install_global,
    install_system,
    upgrade_hook,
)
from ggshield.cmd.machine.registration import register_endpoint
from ggshield.cmd.utils.common_decorators import GitUsage, uses_git
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.dirs import get_system_plugins_dir
from ggshield.core.errors import GIT_INSTALL_HINT, AuthError
from ggshield.core.plugin.client import (
    PluginAPIClient,
    PluginAPIError,
    PluginInfo,
    PluginsNotEnabledError,
)
from ggshield.core.plugin.downloader import PluginDownloader
from ggshield.core.plugin.installer import install_plugin_from_platform
from ggshield.core.plugin.loader import PluginLoader, enable_installed_plugin
from ggshield.utils.git_shell import git, git_unavailable_reason
from ggshield.utils.os import is_root
from ggshield.verticals.ai.agents import AGENTS
from ggshield.verticals.ai.installation import (
    check_ai_hook_authentication,
    hook_executable,
    install_all_agent_hooks,
)


_GIT_HOOK_TYPES = ("pre-commit", "pre-push")


@uses_git(
    GitUsage.OPTIONAL,
    note="It is only needed for the git hooks; without it that step is skipped "
    "with a warning.",
)
@click.command()
@click.option(
    "--no-ai-hooks",
    is_flag=True,
    help="Do not configure the AI assistant hooks.",
)
@click.option(
    "--no-git-hooks",
    is_flag=True,
    help="Do not install the global git hooks.",
)
@click.option(
    "--no-honeytokens",
    is_flag=True,
    help="Do not plant a honeytoken on this machine.",
)
@click.option(
    "--no-plugins",
    is_flag=True,
    help="Do not install the plugins available to this account.",
)
@click.option(
    "--agent",
    "agents",
    type=click.Choice(sorted(AGENTS.keys())),
    multiple=True,
    metavar="ASSISTANT",
    help="Only configure the AI hook for these assistants (repeatable). "
    "Defaults to every assistant detected on this machine.",
)
@click.option(
    "--exclude-agent",
    "exclude_agents",
    type=click.Choice(sorted(AGENTS.keys())),
    multiple=True,
    metavar="ASSISTANT",
    help="Skip these assistants when configuring the AI hook (repeatable).",
)
@click.option(
    "--system",
    "system",
    is_flag=True,
    help="Install the git hooks machine-wide (all users) instead of for the "
    "current user. Implied when running as root, e.g. under an MDM.",
)
@add_common_options()
@click.pass_context
def setup_cmd(
    ctx: click.Context,
    no_ai_hooks: bool,
    no_git_hooks: bool,
    no_honeytokens: bool,
    no_plugins: bool,
    agents: Tuple[str, ...],
    exclude_agents: Tuple[str, ...],
    system: bool,
    **kwargs: Any,
) -> int:
    """
    Set up ggshield protection on this machine.

    Configures every protection in one idempotent run: the ggshield AI hook for
    each detected AI coding assistant, the global git pre-commit/pre-push hooks,
    the plugins this account is entitled to (e.g. `machine_scan`, which provides
    `ggshield machine scan`), and a honeytoken of each type the workspace offers
    (AWS, kubeconfig) to detect endpoint intrusion. It is safe to re-run as it
    adds what is missing and leaves existing entries untouched.

    Each protection is on by default; drop one with `--no-ai-hooks`,
    `--no-git-hooks`, `--no-plugins`, or `--no-honeytokens`. `--agent` /
    `--exclude-agent` narrow which assistants get the AI hook. When run as root
    (or with `--system`), the git hooks and the plugins are installed
    machine-wide for every user.

    Plugins are gated by the GitGuardian plan: an account with none available
    simply skips that step, it is not a setup failure.

    Finally, registers this machine and the honeytoken target users on the
    Endpoints page, even before the first scan. This best-effort step takes at
    most five seconds and never changes the exit code. It is skipped on CI, with
    `endpoint_registration: false` in .gitguardian.yaml, or when
    GGSHIELD_NO_ENDPOINT_REGISTRATION is set to a non-empty value.
    """
    if agents and exclude_agents:
        raise click.UsageError("--agent and --exclude-agent cannot be used together.")

    failed = False

    if not no_ai_hooks:
        if not _setup_ai_hooks(ctx, agents, exclude_agents):
            failed = True

    if not no_git_hooks:
        if not _setup_git_hooks(system):
            failed = True

    if not no_plugins:
        if not _setup_plugins(ctx, system):
            failed = True

    if not no_honeytokens:
        if not _setup_honeytokens(ctx):
            failed = True

    _setup_endpoint_registration(ctx)

    return 1 if failed else 0


def _setup_ai_hooks(
    ctx: click.Context,
    agents: Tuple[str, ...],
    exclude_agents: Tuple[str, ...],
) -> bool:
    """Configure the AI hook for the selected assistants. Returns False on failure.

    Additive/idempotent: adds a ggshield hook entry where one is missing and
    leaves any existing entry untouched.
    """
    click.echo(click.style("AI hooks", bold=True))
    summary = install_all_agent_hooks(only=agents, exclude=exclude_agents)
    # Run the auth preflight once, and only if we actually configured something.
    if summary.configured and not summary.failed:
        check_ai_hook_authentication(ContextObj.get(ctx).config)
        _warm_notifier()
    return summary.failed == 0


def _warm_notifier() -> None:
    """Raise one harmless desktop notification, now that the hooks are wired.

    macOS only asks for notification permission when an app first posts one, and
    until that prompt is answered the notification is delivered nowhere -- no
    error, no banner. Asking here puts the dialog in front of someone who is
    deliberately setting ggshield up. Left to the first real detection, it lands
    on top of a leaked secret, and a prompt nobody answers is a leak alert
    nobody sees.
    """
    try:
        subprocess.run(
            [hook_executable(), "secret", "scan", "ai-hook", "--warm-notifier"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except Exception:
        pass


def _setup_git_hooks(system: bool) -> bool:
    """Install the git pre-commit/pre-push hooks, idempotently.

    Per-user (``global``) by default. Machine-wide (``system``) when ``--system`` is
    given or ggshield runs as root: it sets git's system ``core.hooksPath`` once so
    every user on the machine is covered — the right behavior for MDM, where a
    per-user (root-only) install would protect nobody who actually commits.

    A hook already wired to ggshield and up to date is left as-is; one generated by
    an older ggshield has its generated block swapped for the current one, preserving
    the surrounding user-owned lines. A foreign hook is never overwritten. Returns
    False if any hook is missing, foreign, or too hand-edited to repair, since
    ``machine doctor`` fails on all three and MDM rollouts gate on the exit code.
    """
    click.echo(click.style("Git hooks", bold=True))
    reason = git_unavailable_reason()
    if reason is not None:
        ui.display_warning(f"  git hooks skipped: {reason}. {GIT_INSTALL_HINT}")
        return True
    use_system = system or is_root()
    if use_system:
        scope = "system"
        configured = get_system_hook_dir_path()
        hook_dir = configured or get_default_system_hook_dir_path()
        installer = install_system
    else:
        scope = "global"
        configured = get_global_hook_dir_path()
        hook_dir = configured or get_default_global_hook_dir_path()
        installer = install_global

    ok = True
    if configured is None:
        # A hook file protects nothing until core.hooksPath names its directory, and
        # the installer is the only other thing that sets it — which it never reaches
        # when a leftover hook is already sitting there.
        try:
            git(
                ["config", f"--{scope}", "core.hooksPath", str(hook_dir)],
                ignore_git_config=False,
            )
        except Exception as exc:
            ui.display_warning(f"  could not point git at {hook_dir}: {exc}")
            ok = False

    for hook_type in _GIT_HOOK_TYPES:
        hook_path = hook_dir / hook_type
        if hook_path.is_file():
            if not hook_invokes_ggshield(hook_path):
                ui.display_warning(
                    f"  a non-ggshield {scope} {hook_type} hook is present; "
                    "left untouched"
                )
                ok = False
            elif not hook_is_outdated(hook_path):
                click.echo(f"  {scope} {hook_type} hook already configured")
            elif upgrade_hook(hook_path, hook_type):
                click.echo(f"  {scope} {hook_type} hook updated to the current version")
            else:
                ui.display_warning(
                    f"  the {scope} {hook_type} hook was generated by an older "
                    f"ggshield and edited since; left untouched. Update {hook_path} "
                    "by hand, or delete it and re-run `ggshield machine setup`"
                )
                ok = False
            continue
        try:
            installer(hook_type=hook_type, force=False, append=False)
        except Exception as exc:  # one hook failure must not abort the whole setup
            ui.display_warning(f"  could not install {scope} {hook_type} hook: {exc}")
            ok = False

    # A higher-precedence core.hooksPath (repo-local or user-global, e.g. Husky)
    # silently shadows what we just installed — git would run it instead. We cannot
    # out-rank it (git precedence), so surface it rather than give false coverage.
    shadow = get_shadowing_hooks_path()
    if shadow is not None:
        ui.display_warning(
            f"  a core.hooksPath override ({shadow}) takes precedence here, so "
            "ggshield's hook will not run in that context. Integrate ggshield into "
            "that hook manager or unset the override (`ggshield machine doctor` flags "
            "this per repo)."
        )
    return ok


def _setup_plugins(ctx: click.Context, system: bool) -> bool:
    """Install every plugin this account is entitled to. Returns False on failure.

    Entitlement is the platform's answer, not a guess: the catalog marks each
    plugin `available`, with a `reason` when it is not. So there is nothing to
    hardcode about plans here — install what comes back available.

    Having no plugins available (free plan, or the plugin system off for the
    workspace) is a normal outcome and must not fail the setup, no more than
    having no AI assistant installed does. Only a plugin the account *is*
    entitled to failing to install counts as a failure, and so does an auth
    failure: without a valid token setup cannot tell what the account gets.

    Under root this installs machine-wide, like the git hooks: `PluginDownloader`
    lands the wheel in the system plugin dir so every user on the machine gets it.
    Where a plugin lands is decided by privilege, not by a flag, so `--system`
    without root cannot install plugins machine-wide: a plugin that still needs
    an install or an enable is reported as a failure rather than silently set up
    for the current user only. One already set up machine-wide passes, as the
    git hooks do.

    A plugin with no build for this machine (the catalog lists no artifact for
    this platform and arch) is skipped, like one the account cannot install.
    """
    click.echo(click.style("Plugins", bold=True))
    config = ContextObj.get(ctx).config

    try:
        client = create_client_from_config(config)
        plugin_api_client = PluginAPIClient(client)
        catalog = plugin_api_client.get_available_plugins()
    except PluginsNotEnabledError:
        click.echo("  the plugin system is not enabled on this workspace; skipped")
        return True
    except AuthError as exc:
        ui.display_warning(f"  could not authenticate to GitGuardian: {exc}")
        return False
    except PluginAPIError as exc:
        if _is_auth_failure(exc):
            ui.display_warning(
                f"  GitGuardian rejected the API key: {exc}. "
                "Run `ggshield auth login`, then re-run `ggshield machine setup`."
            )
            return False
        ui.display_warning(f"  could not fetch the plugin catalog: {exc}; skipped")
        return True
    except Exception as exc:  # noqa: BLE001 - an unreachable catalog is not a failure
        ui.display_warning(f"  could not fetch the plugin catalog: {exc}; skipped")
        return True

    available = [plugin for plugin in catalog.plugins if plugin.available]
    if not available:
        click.echo("  no plugins available for this account")
        for plugin in catalog.plugins:
            if plugin.reason:
                click.echo(f"    {plugin.name}: {plugin.reason}")
        return True

    machine_wide = system or is_root()
    needs_root = system and not is_root()
    downloader = PluginDownloader()
    enterprise_config = EnterpriseConfig.load()
    enabled_wheels = _enabled_wheel_paths()
    root_hint = "needs root: run `sudo ggshield machine setup`"

    ok = True
    for plugin in available:
        wheel_path = _installed_wheel(downloader, plugin.name, machine_wide)
        installed_version = downloader.get_installed_version(
            plugin.name, by_catalog_reference=True
        )
        if wheel_path is not None and installed_version is not None:
            if wheel_path.resolve() in enabled_wheels:
                click.echo(
                    f"  {plugin.name} already installed"
                    f"{_update_hint(plugin, installed_version)}"
                )
                continue
            # On disk but disabled, or with no config row: enable the wheel that
            # is there instead of claiming the plugin is set up.
            if needs_root:
                ui.display_warning(f"  enabling {plugin.name} machine-wide {root_hint}")
                ok = False
                continue
            try:
                name = enable_installed_plugin(
                    enterprise_config, plugin.name, installed_version, wheel_path
                )
                enterprise_config.save()
            except Exception as exc:  # noqa: BLE001 - one plugin must not abort
                ui.display_warning(f"  could not enable {plugin.name}: {exc}")
                ok = False
                continue
            click.echo(f"  enabled {name}{_update_hint(plugin, installed_version)}")
            continue
        if not plugin.has_artifact_for_platform:
            click.echo(f"  {plugin.name}: not available for this platform; skipped")
            continue
        if needs_root:
            ui.display_warning(f"  installing {plugin.name} machine-wide {root_hint}")
            ok = False
            continue
        try:
            installed = install_plugin_from_platform(
                plugin_api_client,
                plugin.name,
                downloader=downloader,
                enterprise_config=enterprise_config,
            )
        except Exception as exc:  # noqa: BLE001 - one plugin must not abort the rest
            ui.display_warning(f"  could not install {plugin.name}: {exc}")
            ok = False
            continue
        click.echo(f"  installed {installed.name} v{installed.version}")
    return ok


def _is_auth_failure(exc: PluginAPIError) -> bool:
    """True when the catalog call failed because the API key was rejected."""
    cause = exc.__cause__
    if isinstance(cause, requests.HTTPError) and cause.response is not None:
        return cause.response.status_code in (401, 403)
    return False


def _installed_wheel(
    downloader: PluginDownloader, catalog_reference: str, machine_wide: bool
) -> Optional[Path]:
    """The wheel installed for this catalog plugin, in the layer setup targets.

    A machine-wide setup (root, or `--system`) provisions every user, so only a
    machine-wide install counts: a copy in a per-user plugin dir (root's own,
    left by an older per-user install, or the current user's) is invisible to
    other users.
    """
    wheel_path = downloader.get_wheel_path(catalog_reference, by_catalog_reference=True)
    if wheel_path is None:
        return None
    if machine_wide and not wheel_path.resolve().is_relative_to(
        get_system_plugins_dir().resolve()
    ):
        return None
    return wheel_path


def _enabled_wheel_paths() -> Set[Path]:
    """Wheels of the plugins enabled for this user, as the loader sees them.

    Uses the effective (per-user + machine-wide) config, the same view
    `machine doctor` and the plugin loader use, so a plugin only counts as set
    up when it would actually load. A root run sets the machine up for every
    user, so there only the machine-wide config counts: an enablement in root's
    own config does not reach anyone else.
    """
    config = EnterpriseConfig.load() if is_root() else EnterpriseConfig.load_effective()
    loader = PluginLoader(config)
    return {
        plugin.wheel_path.resolve()
        for plugin in loader.discover_plugins()
        if plugin.is_enabled and plugin.wheel_path is not None
    }


def _update_hint(plugin: PluginInfo, installed_version: str) -> str:
    """Report the installed version, and point at `plugin update` if it is behind.

    `setup` deliberately does not upgrade: it adds what is missing and leaves
    what is there alone, so a re-run never swaps a working plugin out from under
    a machine. Upgrading stays an explicit `ggshield plugin update`.
    """
    if _is_newer_version(installed_version, plugin.latest_version):
        return (
            f" v{installed_version} (v{plugin.latest_version} available, "
            "run `ggshield plugin update --all`)"
        )
    return f" v{installed_version}"


def _is_newer_version(installed_version: str, latest_version: Optional[str]) -> bool:
    """True when ``latest_version`` is a newer release than ``installed_version``."""
    if not latest_version:
        return False
    try:
        return packaging_version.parse(latest_version) > packaging_version.parse(
            installed_version
        )
    except packaging_version.InvalidVersion:
        return False


def _setup_honeytokens(ctx: click.Context) -> bool:
    """Plant every honeytoken type on this machine (idempotent reconcile via `plant`)."""
    click.echo(click.style("Honeytokens", bold=True))
    return ctx.invoke(plant_cmd, token_type=ALL_TYPES) == 0


def _setup_endpoint_registration(ctx: click.Context) -> None:
    try:
        message = register_endpoint(ContextObj.get(ctx).config)
    except Exception:
        message = "warning: endpoint registration failed"
    click.echo(click.style("Endpoints", bold=True) + f": {message}")
