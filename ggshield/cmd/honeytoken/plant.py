from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import ExitCode
from ggshield.verticals.honeytoken.aws_profile import (
    ForceRefusal,
    RemoveOutcome,
    WriteOutcome,
    remove_aws_profile,
    resolve_placement,
    write_aws_profile,
)
from ggshield.verticals.honeytoken.endpoint_deployments import (
    ConfirmStatus,
    Deployment,
    DeploymentAction,
    EndpointDeploymentsClient,
    EndpointDeploymentsError,
)
from ggshield.verticals.honeytoken.targets import (
    Target,
    apply_perms_and_owner,
    is_root,
    machine_info_for,
    resolve_targets,
)


@dataclass
class _Outcome:
    """Per-target reconciliation result, aggregated into the final exit code."""

    success: bool = True
    api_failure: bool = False
    api_auth_failure: bool = False
    fs_failure: bool = False


@click.command()
@click.option("--type", "token_type", default="aws", help="Honeytoken type to plant.")
@click.option(
    "--method",
    type=click.Choice(["aws_credentials", "aws_config_profile"]),
    default=None,
    help="Placement method (steers creation of a new deployment only).",
)
@click.option(
    "--filename",
    default=None,
    help="Override the on-disk basename for a new deployment (safe charset only).",
)
@click.option(
    "--profile-name",
    "profile_name",
    default=None,
    help="Override the profile/section name for a new deployment.",
)
@click.option(
    "--user",
    default=None,
    help="Target OS user (defaults to the current user; as root, narrows the fan-out).",
)
@click.option(
    "--user-dir",
    "user_dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Override the resolved home directory (single-user; testing).",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite the honeytoken profile if it exists and is not ours.",
)
@click.option(
    "--list-targets",
    "list_targets",
    is_flag=True,
    help="Print the resolved planting targets and exit (no API call, no disk writes).",
)
@click.option(
    "--remove-only",
    "remove_only",
    is_flag=True,
    help="Cleanup-only: read current state (read-only) and apply only `delete` actions.",
)
@add_common_options()
@click.pass_context
def plant_cmd(
    ctx: click.Context,
    token_type: str,
    method: Optional[str],
    filename: Optional[str],
    profile_name: Optional[str],
    user: Optional[str],
    user_dir: Optional[Path],
    force: bool,
    list_targets: bool,
    remove_only: bool,
    **kwargs: Any,
) -> int:
    """
    Reconcile this machine's honeytokens against GitGuardian and apply the desired
    on-disk state: write/refresh the decoy AWS credentials profile for `write` entries,
    remove it for `delete` (revoked) entries — preserving any other profiles. ggshield
    never revokes a honeytoken; it only reports placement status.

    Authorize with the `honeytokens:write` scope.
    """
    try:
        targets = resolve_targets(user, user_dir)
    except LookupError as exc:
        click.echo(str(exc), err=True)
        return ExitCode.USAGE_ERROR
    except Exception as exc:  # noqa: BLE001 - never crash resolving targets (e.g. pwd)
        click.echo(f"could not resolve planting targets: {exc}", err=True)
        return ExitCode.UNEXPECTED_ERROR
    if not targets:
        click.echo("No target users to plant honeytokens for.", err=True)
        return ExitCode.USAGE_ERROR

    if list_targets:
        click.echo(f"Would plant for {len(targets)} user(s) [type={token_type}]:")
        for target in targets:
            uid = f"uid {target.uid}" if target.uid is not None else "uid -"
            click.echo(f"  {target.username}  ({uid})  at {target.home}")
        return ExitCode.SUCCESS

    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    gg_client = create_client_from_config(config)
    client = EndpointDeploymentsClient(
        gg_client.session, config.api_url, config.api_key
    )
    running_as_root = is_root()

    final = _Outcome()
    for target in targets:
        try:
            outcome = _reconcile_for_user(
                client,
                target,
                token_type=token_type,
                method=method,
                filename=filename,
                profile_name=profile_name,
                force=force,
                remove_only=remove_only,
                running_as_root=running_as_root,
            )
        except Exception as exc:  # noqa: BLE001 - one target must not abort the run
            # Per-deployment errors are handled inside _reconcile_for_user; this is the
            # last-resort net so an unexpected failure for one user (esp. in a root
            # fan-out) doesn't skip the remaining users.
            click.echo(f"[{target.username}] unexpected error: {exc}", err=True)
            final.fs_failure = True
            continue
        final.api_failure |= outcome.api_failure
        final.api_auth_failure |= outcome.api_auth_failure
        final.fs_failure |= outcome.fs_failure

    if final.api_auth_failure:
        return ExitCode.AUTHENTICATION_ERROR
    if final.api_failure or final.fs_failure:
        return ExitCode.UNEXPECTED_ERROR
    return ExitCode.SUCCESS


def _reconcile_for_user(
    client: EndpointDeploymentsClient,
    target: Target,
    *,
    token_type: str,
    method: Optional[str],
    filename: Optional[str],
    profile_name: Optional[str],
    force: bool,
    remove_only: bool,
    running_as_root: bool,
) -> _Outcome:
    outcome = _Outcome()
    try:
        if remove_only:
            deployments = client.list(
                machine_info_for(target.username)["machine_id"], target.username
            )
        else:
            deployments = client.reconcile(
                machine_info_for(target.username),
                token_type,
                method=method,
                filename=filename,
                profile_name=profile_name,
            )
    except EndpointDeploymentsError as exc:
        click.echo(f"[{target.username}] {exc}", err=True)
        outcome.api_failure = True
        outcome.api_auth_failure = exc.is_auth
        return outcome

    written = skipped = removed = force_refused = other_failed = 0

    # Pass 1: deletes first so a rotation (delete-old + write-new in the same response)
    # frees the profile slot before the write runs.
    for item in (d for d in deployments if d.action is DeploymentAction.DELETE):
        try:
            path, section = resolve_placement(item.method, item.config, target.home)
            expected = item.token.access_token_id if item.token else None
            result = remove_aws_profile(path, section, expected)
            if result is RemoveOutcome.FOREIGN_KEPT:
                click.echo(
                    f"[{target.username}] deployment {item.id}: profile holds a "
                    "different key, left untouched",
                    err=True,
                )
            elif result is RemoveOutcome.REMOVED and path.exists():
                # The removal rewrote the file (other profiles remain). As root the
                # temp-file swap leaves it root-owned, locking the target user out of
                # their own ~/.aws — re-assert their ownership (the mode is preserved).
                apply_perms_and_owner(path, target, running_as_root)
            _confirm(client, item, ConfirmStatus.REMOVED, target)
            removed += 1
        except Exception as exc:  # noqa: BLE001 - report + continue per deployment
            click.echo(f"[{target.username}] {exc}", err=True)
            _confirm(client, item, ConfirmStatus.FAILED, target)
            other_failed += 1

    # Pass 2: writes — suppressed in --remove-only mode.
    write_items = (
        []
        if remove_only
        else [d for d in deployments if d.action is DeploymentAction.WRITE]
    )
    for item in write_items:
        if item.token is None:
            click.echo(
                f"[{target.username}] 'write' entry missing credentials", err=True
            )
            _confirm(client, item, ConfirmStatus.FAILED, target)
            other_failed += 1
            continue
        try:
            path, section = resolve_placement(item.method, item.config, target.home)
            result = write_aws_profile(path, section, item.token, force)
            if result is WriteOutcome.WROTE:
                apply_perms_and_owner(path, target, running_as_root)
                _confirm(client, item, ConfirmStatus.PLANTED, target)
                written += 1
            else:  # ALREADY_CURRENT
                _confirm(client, item, ConfirmStatus.PLANTED, target)
                skipped += 1
        except ForceRefusal as exc:
            click.echo(f"[{target.username}] {exc}", err=True)
            _confirm(client, item, ConfirmStatus.FAILED, target)
            force_refused += 1
        except Exception as exc:  # noqa: BLE001 - report + continue per deployment
            # Includes PlacementError (e.g. a malformed ~/.aws file), OSError, and any
            # unexpected error: a fleet agent must never crash mid-run — report this
            # deployment as failed (the server retries on the next sync) and continue.
            click.echo(f"[{target.username}] {exc}", err=True)
            _confirm(client, item, ConfirmStatus.FAILED, target)
            other_failed += 1

    # Forward-compat: log (don't crash on) actions a newer backend introduced.
    for item in (d for d in deployments if d.action is DeploymentAction.UNKNOWN):
        click.echo(
            f"[{target.username}] ignoring unknown action for deployment {item.id} "
            "— client may be out of date",
            err=True,
        )

    suppressed = (
        sum(1 for d in deployments if d.action is DeploymentAction.WRITE)
        if remove_only
        else 0
    )
    suffix = (
        f" (remove-only: {suppressed} planting action(s) skipped)" if suppressed else ""
    )
    total_failed = force_refused + other_failed
    summary = (
        f"[{target.username}] reconciled — {written} written, {skipped} skipped, "
        f"{removed} removed{suffix}"
    )
    if total_failed:
        click.echo(
            f"[{target.username}] reconciled with {total_failed} failure(s) "
            f"({written} written, {skipped} skipped, {removed} removed){suffix}",
            err=True,
        )
        outcome.fs_failure = True
    else:
        click.echo(summary)
    return outcome


def _confirm(
    client: EndpointDeploymentsClient,
    item: Deployment,
    status: ConfirmStatus,
    target: Target,
) -> None:
    """Best-effort status confirmation: a failed confirm is logged, not fatal — the next
    reconcile re-syncs."""
    try:
        client.confirm(item.id, status)
    except EndpointDeploymentsError as exc:
        click.echo(
            f"[{target.username}] could not confirm deployment {item.id} as "
            f"{status.value}: {exc}",
            err=True,
        )
