import os
from typing import Any, Optional, Tuple

import click

from ggshield.cmd.honeytoken.plant import plant_cmd
from ggshield.cmd.install import (
    get_default_global_hook_dir_path,
    get_default_system_hook_dir_path,
    get_global_hook_dir_path,
    get_system_hook_dir_path,
    install_global,
    install_system,
)
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client, safe_response_json
from ggshield.core.config.system_auth import write_system_auth
from ggshield.utils.os import is_root
from ggshield.verticals.ai.agents import AGENTS
from ggshield.verticals.ai.installation import (
    check_ai_hook_authentication,
    install_all_agent_hooks,
)


_GIT_HOOK_TYPES = ("pre-commit", "pre-push")

# Scopes the protections configured by `machine setup` need from the token.
_SCAN_SCOPE = "scan"  # the AI and git hooks run `ggshield secret scan`
# The AI hook also reports MCP activity / discovery. Still `nhi:send-inventory`
# today; will become a dedicated AI scope when the backend ships it.
_AI_DISCOVERY_SCOPE = "nhi:send-inventory"
_HONEYTOKEN_SCOPE = "honeytokens:write"  # plant honeytokens (Business/Enterprise)


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
@click.option(
    "--instance",
    "instance",
    metavar="URL",
    default=None,
    help="GitGuardian instance to authenticate against (used with a "
    "service-account token).",
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
    instance: Optional[str],
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

    For fleet/MDM deployment, provide a service-account token via the
    `GGSHIELD_SERVICE_ACCOUNT_TOKEN` environment variable (or piped on stdin) and
    `--instance`: setup stores it machine-wide so every account on the machine
    authenticates with it, without a per-user `ggshield auth login`. Requires root.
    """
    if agents and exclude_agents:
        raise click.UsageError("--agent and --exclude-agent cannot be used together.")

    if instance:
        ContextObj.get(ctx).config.cmdline_instance_name = instance

    failed = False

    # Provision machine-wide auth first (if a service-account token is supplied) so
    # the steps below authenticate with it.
    if not _setup_service_account_auth(
        ctx,
        no_ai_hooks=no_ai_hooks,
        no_git_hooks=no_git_hooks,
        no_honeytokens=no_honeytokens,
    ):
        failed = True

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
            if "ggshield secret scan" in hook_path.read_text(errors="ignore"):
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
    return ok


def _setup_honeytokens(ctx: click.Context) -> bool:
    """Plant a honeytoken on this machine (idempotent reconcile via `plant`)."""
    click.echo(click.style("Honeytoken", bold=True))
    return ctx.invoke(plant_cmd) == 0


def _read_service_account_token() -> Optional[str]:
    """Read the service-account token from the env var or piped stdin (never argv,
    so it does not leak into `ps` / shell history). None if not provided."""
    token = os.environ.get("GGSHIELD_SERVICE_ACCOUNT_TOKEN")
    if token and token.strip():
        return token.strip()
    stdin = click.get_text_stream("stdin")
    if not stdin.isatty():
        piped = stdin.read().strip()
        if piped:
            return piped
    return None


def _setup_service_account_auth(
    ctx: click.Context,
    *,
    no_ai_hooks: bool,
    no_git_hooks: bool,
    no_honeytokens: bool,
) -> bool:
    """Provision a machine-wide service-account token, if one was supplied.

    No-op (returns True) when no token is provided — `machine setup` keeps working
    without it. When provided, validates the token (reachable + carries the scopes
    the enabled protections need) and writes it to the machine-wide config so every
    account on the machine authenticates with it.

    `scan` is the hard requirement: without it the hooks cannot scan, so a missing
    `scan` scope fails. The other scopes only degrade their own feature, so a missing
    one is a warning, not a failure — the per-feature steps report their own outcome.
    Returns False on a bad token, a missing `scan` scope, or a failed write.
    """
    token = _read_service_account_token()
    if token is None:
        return True

    click.echo(click.style("Service-account authentication", bold=True))
    config = ContextObj.get(ctx).config
    instance = config.instance_name
    try:
        client = create_client(
            api_key=token,
            api_url=config.api_url,
            allow_self_signed=config.user_config.insecure,
        )
        response = client.get(endpoint="token")
    except Exception as exc:  # noqa: BLE001 - report any validation failure as a result
        ui.display_warning(f"  could not validate the service-account token: {exc}")
        return False

    if not response.ok:
        ui.display_warning(f"  the service-account token was rejected by {instance}.")
        return False

    scopes = set(safe_response_json(response).get("scope", []))

    # `scan` is required by the AI and git hooks — the core of setup.
    if (not no_ai_hooks or not no_git_hooks) and _SCAN_SCOPE not in scopes:
        ui.display_warning(
            f"  the service-account token is missing the `{_SCAN_SCOPE}` scope, "
            "required by the AI and git hooks."
        )
        return False

    # The remaining scopes only degrade their own feature — warn but still provision.
    if not no_ai_hooks and _AI_DISCOVERY_SCOPE not in scopes:
        ui.display_warning(
            f"  the service-account token is missing the `{_AI_DISCOVERY_SCOPE}` "
            "scope — the AI hook's MCP/discovery reporting will be skipped."
        )
    if not no_honeytokens and _HONEYTOKEN_SCOPE not in scopes:
        ui.display_warning(
            f"  the service-account token is missing the `{_HONEYTOKEN_SCOPE}` scope "
            "— honeytoken planting will fail (Business or Enterprise plans only)."
        )

    try:
        path = write_system_auth(instance, token)
    except OSError as exc:
        ui.display_warning(
            f"  could not write machine-wide auth (run as root for MDM): {exc}"
        )
        return False

    click.echo(f"  service-account token configured machine-wide in {path}")
    return True
