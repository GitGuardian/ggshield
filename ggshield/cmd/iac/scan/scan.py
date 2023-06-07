from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.iac.scan.iac_scan_common_options import add_iac_scan_common_options
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.filter import init_exclusion_regexes
from ggshield.iac.scan.iac_diff_scan import execute_iac_diff_scan
from ggshield.iac.scan.iac_path_scan import execute_iac_scan


@click.command()
@click.option("--since", type=click.STRING, help="A git reference.")
@click.option(
    "--staged",
    is_flag=True,
    help="Include staged changes into the scan. Ignored if `--since` is not provided",
)
@add_iac_scan_common_options()
@click.pass_context
def scan_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    since: Optional[str],
    staged: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan a directory for IaC vulnerabilities.
    """
    if directory is None:
        directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)

    if since is None:
        return execute_iac_scan(ctx, directory)
    else:
        return execute_iac_diff_scan(ctx, directory, since, staged)


def update_context(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
) -> None:
    config: Config = ctx.obj["config"]
    ctx.obj["client"] = create_client_from_config(config)

    if ignore_paths is not None:
        config.user_config.iac.ignored_paths.update(ignore_paths)

    ctx.obj["exclusion_regexes"] = init_exclusion_regexes(
        config.user_config.iac.ignored_paths
    )

    if ignore_policies is not None:
        config.user_config.iac.ignored_policies.update(ignore_policies)

    if exit_zero is not None:
        config.user_config.exit_zero = exit_zero

    if minimum_severity is not None:
        config.user_config.iac.minimum_severity = minimum_severity
