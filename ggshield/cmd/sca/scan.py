import re
from pathlib import Path
from typing import Any, List, Optional, Set, Tuple

import click
from pygitguardian.client import _create_tar

from ggshield.cmd.sca.scan_utils import create_output_handler
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.errors import APIKeyCheckError, UnexpectedError
from ggshield.core.git_shell import INDEX_REF
from ggshield.core.text_utils import display_error, display_info, display_warning
from ggshield.sca.client import ComputeSCAFilesResult, SCAClient
from ggshield.sca.collection import SCAScanAllVulnerabilityCollection
from ggshield.sca.file_selection import (
    get_all_files_from_sca_paths,
    tar_sca_files_from_git_repo,
)
from ggshield.sca.sca_scan_models import (
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAScanParameters,
)
from ggshield.scan import ScanContext, ScanMode


def display_sca_beta_warning(func):
    """
    Displays warning about SCA commands being in beta.
    """

    def func_with_beta_warning(*args, **kwargs):
        display_warning(
            "This feature is still in beta, its behavior may change in future versions."
        )
        return func(*args, **kwargs)

    return func_with_beta_warning


@click.group()
@click.pass_context
def scan_group(*args, **kwargs: Any) -> None:
    """Perform a SCA scan."""


@scan_group.command(name="diff")
@click.argument(
    "directory",
    type=click.Path(exists=True, readable=True, path_type=Path, file_okay=False),
    required=False,
)
@click.option(
    "--ref",
    metavar="REF",
    help="Git reference to compare working directory to.",
)
@click.pass_context
@display_sca_beta_warning
def scan_pre_commit_cmd(
    ctx: click.Context,
    directory: Optional[Path],
    ref: str,
    **kwargs: Any,
) -> SCAScanDiffOutput:
    """
    Find SCA vulnerabilities in a git working directory, compared to HEAD.
    """
    if directory is None:
        directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(ctx)

    result = sca_scan_diff(
        ctx=ctx, directory=directory, ref="HEAD", include_staged=True
    )

    # TODO, should be handled by an output_handler in the future
    return result


@scan_group.command(name="all")
@click.argument(
    "directory",
    type=click.Path(exists=True, readable=True, path_type=Path, file_okay=False),
    required=False,
)
@click.pass_context
@display_sca_beta_warning
def scan_all_cmd(
    ctx: click.Context,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan a directory for SCA vulnerabilities.
    """
    if directory is None:
        directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(ctx)

    result = sca_scan_all(ctx, directory)
    scan = SCAScanAllVulnerabilityCollection(id=str(directory), result=result)
    output_handler = create_output_handler(ctx)
    return output_handler.process_scan_all_result(scan)


def update_context(ctx: click.Context) -> None:
    """
    Basic implementation, should be populated with required parameters later.
    """
    config: Config = ctx.obj["config"]
    ctx.obj["client"] = create_client_from_config(config)

    # Empty for now
    ctx.obj["exclusion_regexes"] = set()


def sca_scan_all(ctx: click.Context, directory: Path) -> SCAScanAllOutput:
    """
    Scan an entire directory for SCA Vulnerabilities.

    - List SCA related files with a first call to SCA compute files API
    - Create a tar archive with the required files contents
    - Launches the scan with a call to SCA public API
    """
    client = SCAClient(ctx.obj["client"])

    sca_filepaths, sca_filter_status_code = get_sca_scan_all_filepaths(
        directory=directory,
        exclusion_regexes=ctx.obj["exclusion_regexes"],
        verbose=ctx.obj["config"].verbose,
        client=client,
    )

    if len(sca_filepaths) == 0:
        display_info("No file to scan.")
        # Not an error, return an empty SCAScanAllOutput
        # with the status code returned by first call
        empty_output = SCAScanAllOutput()
        empty_output.status_code = sca_filter_status_code
        return empty_output

    # empty for now
    scan_parameters = SCAScanParameters()

    tar = _create_tar(directory, sca_filepaths)

    # Call to full scan API and get results
    scan_result = client.sca_scan_directory(
        tar,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=ScanMode.SCA_DIRECTORY,
        ).get_http_headers(),
    )

    if not isinstance(scan_result, SCAScanAllOutput):
        if scan_result.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        display_error("Error scanning.")
        display_error(str(scan_result))
        raise UnexpectedError("Unexpected error while performing SCA scan all.")

    return scan_result


def get_sca_scan_all_filepaths(
    directory: Path,
    exclusion_regexes: Set[re.Pattern],
    verbose: bool,
    client: SCAClient,
) -> Tuple[List[str], int]:
    """
    Retrieve SCA related files of a directory.
    First get all filenames that are not in blacklisted directories, then calls SCA compute files
    API to filter SCA related files.
    """
    all_filepaths = get_all_files_from_sca_paths(
        path=directory,
        exclusion_regexes=exclusion_regexes,
        verbose=verbose,
        # If the repository is a git repository, ignore untracked files
        ignore_git=True,
    )

    # API Call to filter SCA files
    response = client.compute_sca_files(files=all_filepaths)

    # First check is required by pyright to know that status_code cannot be None
    if response.status_code is None or not isinstance(response, ComputeSCAFilesResult):
        if response.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        display_error("Error while filtering SCA related files.")
        display_error(str(response))
        raise UnexpectedError("Unexpected error while filtering SCA related files.")

    # Only sca_files field is useful in the case of a full_scan,
    # all the potential files already exist in `all_filepaths`

    return response.sca_files, response.status_code


def sca_scan_diff(
    ctx: click.Context,
    directory: Path,
    ref: str,
    include_staged: bool,
) -> SCAScanDiffOutput:
    client = SCAClient(ctx.obj["client"])
    current_ref = INDEX_REF if include_staged else "HEAD"
    if current_ref == ref:
        display_info("SCA scan diff comparing identical versions, scan skipped.")
        return SCAScanDiffOutput(scanned_files=[], added_vulns=[], removed_vulns=[])
    ref_tar = tar_sca_files_from_git_repo(directory, ref, client)
    current_tar = tar_sca_files_from_git_repo(directory, current_ref, client)
    response = client.scan_diff(reference=ref_tar, current=current_tar)

    if not isinstance(response, SCAScanDiffOutput):
        if response.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        display_error("Error while scanning diff.")
        display_error(str(response))
        raise UnexpectedError("Unexpected error while scanning diff.")

    return response
