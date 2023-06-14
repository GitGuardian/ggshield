from pathlib import Path
from typing import Any, Optional, Sequence

import click
from pygitguardian.iac_models import IaCScanParameters

from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    directory_argument,
    update_context,
)
from ggshield.cmd.iac.scan.iac_scan_utils import (
    create_output_handler,
    get_iac_tar,
    handle_scan_error,
)
from ggshield.core.clickutils.option_group import OptionGroup
from ggshield.core.config.config import Config
from ggshield.core.git_shell import INDEX_REF
from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.iac_scan_models import (
    IaCDiffScanResult,
    create_mock_client_from_config,
)
from ggshield.scan import ScanContext, ScanMode


@click.command()
@add_iac_scan_common_options()
@click.option(
    "--ref",
    type=click.STRING,
    cls=OptionGroup,
    not_required_if=["pre-commit", "pre-push", "pre-receive"],
    help="A git reference.",
)
@click.option(
    "--pre-commit",
    is_flag=True,
    type=click.STRING,
    cls=OptionGroup,
    not_required_if=["ref", "pre-push", "pre-receive"],
    help="This is an alias for `ggshield iac scan --ref=HEAD --staged`, intended to be used in a pre-commit hook.",
)
@click.option(
    "--pre-push",
    is_flag=True,
    type=click.STRING,
    cls=OptionGroup,
    not_required_if=["ref", "pre-commit", "pre-receive"],
    help="This is an alias for `ggshield iac scan --ref=@{upstream}`, intended to be used in a pre-push hook.",
)
@click.option(
    "--pre-receive",
    is_flag=True,
    type=click.STRING,
    cls=OptionGroup,
    not_required_if=["ref", "pre-commit", "pre-push"],
    help="This is an alias for `ggshield iac scan --ref=HEAD`, intended to be used in a pre-receive hook.",
)
@click.option(
    "--staged",
    is_flag=True,
    help="Whether staged changes should be included into the scan.",
)
@directory_argument
@click.pass_context
def scan_diff_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    ref: str,
    pre_commit: bool,
    pre_push: bool,
    pre_receive: bool,
    staged: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan all changes made since the provided Git ref for IaC vulnerabilities.
    """
    if directory is None:
        directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)

    # TODO: remove this once the GGClient is updated with the new diff function
    config: Config = ctx.obj["config"]
    ctx.obj["client"] = create_mock_client_from_config(config)

    if pre_commit:
        ref = "HEAD"
        staged = True
    elif pre_push:
        ref = "@{upstream}"
        staged = False
    elif pre_receive:
        ref = "HEAD"
        staged = False

    result = iac_scan_diff(ctx, directory, ref, staged)
    scan = IaCDiffScanCollection(id=str(directory), result=result)
    output_handler = create_output_handler(ctx)
    return output_handler.process_diff_scan(scan)


def iac_scan_diff(
    ctx: click.Context, directory: Path, ref: str, include_staged: bool
) -> Optional[IaCDiffScanResult]:
    config = ctx.obj["config"]
    client = ctx.obj["client"]

    reference_tar = get_iac_tar(directory, ref)
    current_ref = INDEX_REF if include_staged else "HEAD"
    current_tar = get_iac_tar(directory, current_ref)

    scan_parameters = IaCScanParameters(
        config.user_config.iac.ignored_policies, config.user_config.iac.minimum_severity
    )

    scan = client.mock_api_iac_diff_scan(
        reference_tar,
        current_tar,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=ScanMode.IAC_DIFF,
        ).get_http_headers(),
    )

    if not scan.success or not isinstance(scan, IaCDiffScanResult):
        handle_scan_error(client, scan)
        return None
    return scan
