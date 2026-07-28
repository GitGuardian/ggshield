from typing import Any, Tuple

import click

from ggshield.cmd.honeytoken.plant import plant_cmd
from ggshield.cmd.install import (
    get_default_global_hook_dir_path,
    get_default_system_hook_dir_path,
    get_global_hook_dir_path,
    get_shadowing_hooks_path,
    get_system_hook_dir_path,
    hook_invokes_ggshield,
    install_global,
    install_system,
)
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.utils.os import is_root
from ggshield.verticals.ai.agents import AGENTS
from ggshield.verticals.ai.installation import (
    check_ai_hook_authentication,
    install_all_agent_hooks,
)


_GIT_HOOK_TYPES = ("pre-commit", "pre-push")


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
    agents: Tuple[str, ...],
    exclude_agents: Tuple[str, ...],
    system: bool,
    **kwargs: Any,
) -> int:
    """
    Set up ggshield protection on this machine.

    Configures every protection in one idempotent run: the ggshield AI hook for
    each detected AI coding assistant, the global git pre-commit/pre-push hooks,
    and a honeytoken to detect endpoint intrusion. Safe to re-run — it adds what
    is missing and leaves existing entries untouched.

    Each protection is on by default; drop one with `--no-ai-hooks`,
    `--no-git-hooks`, or `--no-honeytokens`. `--agent` / `--exclude-agent`
    narrow which assistants get the AI hook. When run as root (or with
    `--system`), the git hooks are installed machine-wide for every user.
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

    if not no_honeytokens:
        if not _setup_honeytokens(ctx):
            failed = True

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
    return summary.failed == 0


def _setup_git_hooks(system: bool) -> bool:
    """Install the git pre-commit/pre-push hooks, idempotently.

    Per-user (``global``) by default. Machine-wide (``system``) when ``--system`` is
    given or ggshield runs as root: it sets git's system ``core.hooksPath`` once so
    every user on the machine is covered — the right behavior for MDM, where a
    per-user (root-only) install would protect nobody who actually commits.

    A hook already wired to ggshield is left as-is; a foreign hook is never
    overwritten. Returns False if any hook failed to install.
    """
    click.echo(click.style("Git hooks", bold=True))
    use_system = system or is_root()
    if use_system:
        scope = "system"
        hook_dir = get_system_hook_dir_path() or get_default_system_hook_dir_path()
        installer = install_system
    else:
        scope = "global"
        hook_dir = get_global_hook_dir_path() or get_default_global_hook_dir_path()
        installer = install_global

    ok = True
    for hook_type in _GIT_HOOK_TYPES:
        hook_path = hook_dir / hook_type
        if hook_path.is_file():
            if hook_invokes_ggshield(hook_path):
                click.echo(f"  {scope} {hook_type} hook already configured")
            else:
                ui.display_warning(
                    f"  a non-ggshield {scope} {hook_type} hook is present; "
                    "left untouched"
                )
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


def _setup_honeytokens(ctx: click.Context) -> bool:
    """Plant a honeytoken on this machine (idempotent reconcile via `plant`)."""
    click.echo(click.style("Honeytoken", bold=True))
    return ctx.invoke(plant_cmd) == 0
