from pathlib import Path
from typing import Any, Optional, Sequence, Type

import click
from pygitguardian import GGClient
from pygitguardian.iac_models import IaCScanParameters, IaCScanResult
from pygitguardian.models import Detail

from ggshield.cmd.common_options import use_json
from ggshield.cmd.iac.scan.iac_scan_common_options import add_iac_scan_common_options
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.errors import APIKeyCheckError
from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.git_shell import (
    INDEX_REF,
    get_filepaths_from_ref,
    get_staged_filepaths,
    tar_from_ref_and_filepaths,
)
from ggshield.core.text_utils import display_error
from ggshield.iac.filter import get_iac_files_from_paths, is_file_content_iac_file
from ggshield.iac.iac_scan_collection import IaCPathScanCollection
from ggshield.iac.iac_scan_models import IaCDiffScanResult, mock_api_iac_diff_scan
from ggshield.iac.output import (
    IaCJSONOutputHandler,
    IaCOutputHandler,
    IaCTextOutputHandler,
)
from ggshield.scan import ScanContext, ScanMode


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
    result = (
        iac_scan(ctx, directory)
        if since is None
        else iac_diff_scan(ctx, directory, since, staged)
    )

    # TODO: remove
    if since is not None:
        print("Diff scan ended. Display is WIP")
        return 0

    scan = IaCPathScanCollection(id=str(directory), result=result)

    # TODO: display
    output_handler_cls: Type[IaCOutputHandler]
    if use_json(ctx):
        output_handler_cls = IaCJSONOutputHandler
    else:
        output_handler_cls = IaCTextOutputHandler
    config: Config = ctx.obj["config"]
    output_handler = output_handler_cls(verbose=config.user_config.verbose)
    return output_handler.process_scan(scan)


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


def iac_scan(ctx: click.Context, directory: Path) -> Optional[IaCScanResult]:
    paths = get_iac_files_from_paths(
        path=directory,
        exclusion_regexes=ctx.obj["exclusion_regexes"],
        verbose=ctx.obj["config"].verbose,
        # If the repository is a git repository, ignore untracked files
        ignore_git=False,
    )

    config = ctx.obj["config"]
    client = ctx.obj["client"]

    scan_parameters = IaCScanParameters(
        config.user_config.iac.ignored_policies, config.user_config.iac.minimum_severity
    )

    scan = client.iac_directory_scan(
        directory,
        paths,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=ScanMode.IAC_DIRECTORY,
        ).get_http_headers(),
    )

    if not scan.success or not isinstance(scan, IaCScanResult):
        handle_scan_error(client, scan)
        return None
    return scan


def get_iac_tar(directory: Path, ref: str) -> bytes:
    filepaths = (
        get_staged_filepaths(str(directory))
        if ref == INDEX_REF
        else get_filepaths_from_ref(str(directory), ref)
    )
    return tar_from_ref_and_filepaths(
        str(directory), ref, filepaths, is_file_content_iac_file
    )


def iac_diff_scan(
    ctx: click.Context, directory: Path, since: str, include_staged: bool
) -> Optional[IaCDiffScanResult]:
    config = ctx.obj["config"]
    client = ctx.obj["client"]

    reference_tar = get_iac_tar(directory, since)
    current_ref = INDEX_REF if include_staged else "HEAD"
    current_tar = get_iac_tar(directory, current_ref)

    scan_parameters = IaCScanParameters(
        config.user_config.iac.ignored_policies, config.user_config.iac.minimum_severity
    )

    scan = mock_api_iac_diff_scan(
        client,
        reference_tar,
        current_tar,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=ScanMode.IAC_DIRECTORY,
        ).get_http_headers(),
    )

    if not scan.success or not isinstance(scan, IaCDiffScanResult):
        handle_scan_error(client, scan)
        return None
    return scan


def handle_scan_error(client: GGClient, detail: Detail) -> None:
    if detail.status_code == 401:
        raise APIKeyCheckError(client.base_uri, "Invalid API key.")
    display_error("\nError scanning.")
    display_error(str(detail))
