from typing import Any, Optional

import click

from ggshield.cmd.install import (
    get_default_global_hook_dir_path,
    get_global_hook_dir_path,
)
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.verticals.ai.discovery import print_summary, run_discovery
from ggshield.verticals.ai.installation import ai_hook_posture
from ggshield.verticals.honeytoken.posture import honeytoken_posture


_GIT_HOOK_TYPES = ("pre-commit", "pre-push")


@click.command(name="audit")
@click.option(
    "--no-ai",
    is_flag=True,
    help="Do not run AI/MCP discovery.",
)
@click.option(
    "--no-secrets",
    is_flag=True,
    help="Do not run the machine secret scan.",
)
@click.option(
    "--no-posture",
    is_flag=True,
    help="Do not report this machine's protection posture.",
)
@click.option(
    "--history",
    "scan_history",
    is_flag=True,
    help="Also backfill historical MCP tool calls during AI discovery.",
)
@add_common_options()
@click.pass_context
def audit_cmd(
    ctx: click.Context,
    no_ai: bool,
    no_secrets: bool,
    no_posture: bool,
    scan_history: bool,
    **kwargs: Any,
) -> int:
    """
    Audit this machine's exposure and protection posture (read-only).

    The read counterpart to `machine setup`: in one run it discovers AI/MCP usage,
    scans for secrets at rest (when the `machine_scan` plugin is installed), and
    reports which ggshield protections are in place. It never changes anything — run
    `ggshield machine setup` to fix any gaps.

    Each section is on by default; drop one with `--no-ai`, `--no-secrets`, or
    `--no-posture`.
    """
    exit_code = 0

    if not no_ai:
        _audit_ai(ctx, scan_history)

    if not no_secrets:
        # The secret scan is the only section that can flag findings/errors; its
        # exit code is the command's exit code so CI/MDM can gate on it. Discovery
        # and posture are informational — they warn but never change the result.
        exit_code = _audit_secrets(ctx) or exit_code

    if not no_posture:
        _audit_posture(ctx)

    return exit_code


def _audit_ai(ctx: click.Context, scan_history: bool) -> None:
    """Run AI/MCP discovery and print its summary (best-effort upload)."""
    click.echo(click.style("AI & MCP discovery", bold=True))
    config = ContextObj.get(ctx).config
    summary = run_discovery(config, scan_history=scan_history)
    if summary is not None:
        print_summary(summary)


def _audit_secrets(ctx: click.Context) -> int:
    """Run the native secret scan if the `machine_scan` plugin is installed.

    The scan is owned by the plugin and merged into this same `machine` group, so we
    reach it at runtime as a sibling command (the pattern `machine setup` uses to
    invoke `honeytoken plant`). Without the plugin there is nothing to run — print a
    hint and succeed rather than fail.
    """
    click.echo(click.style("Secret scan", bold=True))
    scan_cmd = _find_sibling_scan(ctx)
    if scan_cmd is None:
        ui.display_info(
            "Secret scanning needs the machine_scan plugin — run "
            "`ggshield plugin install machine_scan`."
        )
        return 0
    return ctx.invoke(scan_cmd) or 0


def _find_sibling_scan(ctx: click.Context) -> Optional[click.Command]:
    """Look up the plugin-provided `scan` command in this `machine` group, if present."""
    parent = ctx.parent
    group = parent.command if parent is not None else None
    if isinstance(group, click.Group):
        return group.commands.get("scan")
    return None


def _audit_posture(ctx: click.Context) -> None:
    """Report which protections are in place (read-only)."""
    click.echo(click.style("Protection posture", bold=True))
    _posture_ai_hooks()
    _posture_git_hooks()
    _posture_honeytoken(ctx)
    click.echo("Run `ggshield machine setup` to configure anything missing.")


def _posture_ai_hooks() -> None:
    statuses = ai_hook_posture()
    if not statuses:
        click.echo("  AI hooks: no AI coding assistants detected")
        return
    for status in statuses:
        state = "installed" if status.installed else "missing"
        click.echo(f"  AI hook [{status.display_name}]: {state}")


def _posture_git_hooks() -> None:
    hook_dir = get_global_hook_dir_path() or get_default_global_hook_dir_path()
    for hook_type in _GIT_HOOK_TYPES:
        hook_path = hook_dir / hook_type
        if hook_path.is_file():
            if "ggshield secret scan" in hook_path.read_text(errors="ignore"):
                state = "installed"
            else:
                state = "present but not ggshield"
        else:
            state = "missing"
        click.echo(f"  git {hook_type} hook: {state}")


def _posture_honeytoken(ctx: click.Context) -> None:
    config = ContextObj.get(ctx).config
    posture = honeytoken_posture(config)
    if not posture.checked:
        click.echo(f"  honeytoken: not checked ({posture.detail})")
        return
    if posture.planted == 0 and posture.missing == 0:
        click.echo("  honeytoken: none configured for this machine")
    elif posture.missing == 0:
        click.echo(f"  honeytoken: planted ({posture.planted})")
    else:
        click.echo(
            f"  honeytoken: {posture.planted} planted, {posture.missing} missing"
        )
