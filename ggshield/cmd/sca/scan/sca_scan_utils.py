import re
from pathlib import Path
from typing import List, Optional, Set, Tuple, Type

import click
from pygitguardian.client import _create_tar

from ggshield.cmd.common_options import use_json
from ggshield.core.config import Config
from ggshield.core.config.user_config import SCAConfig
from ggshield.core.errors import APIKeyCheckError, UnexpectedError
from ggshield.core.file_utils import get_empty_tar
from ggshield.core.git_shell import INDEX_REF, tar_from_ref_and_filepaths
from ggshield.core.text_utils import display_error, display_info, display_warning
from ggshield.sca.client import SCAClient
from ggshield.sca.file_selection import (
    get_all_files_from_sca_paths,
    sca_files_from_git_repo,
)
from ggshield.sca.output.handler import SCAOutputHandler
from ggshield.sca.output.text_handler import SCATextOutputHandler
from ggshield.sca.sca_scan_models import (
    ComputeSCAFilesResult,
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAScanParameters,
)
from ggshield.scan.scan_context import ScanContext
from ggshield.scan.scan_mode import ScanMode


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


def get_scan_params_from_config(sca_config: SCAConfig) -> SCAScanParameters:
    return SCAScanParameters(
        minimum_severity=sca_config.minimum_severity,
        ignored_vulnerabilities=sca_config.ignored_vulnerabilities,
    )


def sca_scan_all(ctx: click.Context, directory: Path) -> SCAScanAllOutput:
    """
    Scan an entire directory for SCA Vulnerabilities.

    - List SCA related files with a first call to SCA compute files API
    - Create a tar archive with the required files contents
    - Launches the scan with a call to SCA public API
    """
    config: Config = ctx.obj["config"]
    client = SCAClient(ctx.obj["client"])

    sca_filepaths, sca_filter_status_code = get_sca_scan_all_filepaths(
        directory=directory,
        exclusion_regexes=ctx.obj["exclusion_regexes"],
        verbose=config.user_config.verbose,
        client=client,
    )

    if len(sca_filepaths) == 0:
        display_info("No file to scan.")
        # Not an error, return an empty SCAScanAllOutput
        # with the status code returned by first call
        empty_output = SCAScanAllOutput(scanned_files=[], found_package_vulns=[])
        empty_output.status_code = sca_filter_status_code
        return empty_output

    scan_parameters = get_scan_params_from_config(config.user_config.sca)

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


def create_output_handler(ctx: click.Context) -> SCAOutputHandler:
    """Read objects defined in ctx.obj and create the appropriate OutputHandler
    instance"""
    output_handler_cls: Type[SCAOutputHandler]
    if use_json(ctx):
        raise NotImplementedError(
            "JSON output is not currently supported for SCA scan."
        )
    else:
        output_handler_cls = SCATextOutputHandler
    config: Config = ctx.obj["config"]
    return output_handler_cls(
        verbose=config.user_config.verbose, exit_zero=config.user_config.exit_zero
    )


def sca_scan_diff(
    ctx: click.Context,
    directory: Path,
    previous_ref: Optional[str],
    include_staged: bool = False,
    current_ref: Optional[str] = None,
) -> SCAScanDiffOutput:
    """
    Performs a diff scan for SCA vulnerabilities,
    comparing two git reference. Vulnerabilities are flagged as new, removed or
    remaining depending on whether they appear in the `current_ref` and `previous_ref`
    git references.

    :param ctx: click.Context with CLI arguments
    :param directory: path to the location we want to scan.
    :param previous_ref: git reference to the state of reference for the analysis
    :param include_staged: bool whether or not we want to consider the staged files
    only when the current reference is set to None.
    :param current_ref: optional git reference to the current state, defaults to None.
    When set to None, the current state is the indexed files currently on disk.
    :return: SCAScanDiffOutput object.
    """
    config: Config = ctx.obj["config"]
    client = SCAClient(ctx.obj["client"])
    exclusion_regexes = ctx.obj["exclusion_regexes"]

    if current_ref is None:
        current_ref = INDEX_REF if include_staged else "HEAD"
    if current_ref == previous_ref:
        display_info("SCA scan diff comparing identical versions, scan skipped.")
        return SCAScanDiffOutput(scanned_files=[], added_vulns=[], removed_vulns=[])

    if previous_ref is None:
        previous_files = []
    else:
        previous_files = sca_files_from_git_repo(
            directory, previous_ref, client, exclusion_regexes
        )

    current_files = sca_files_from_git_repo(
        directory, current_ref, client, exclusion_regexes
    )

    if len(previous_files) == 0 and len(current_files) == 0:
        display_info("No file to scan.")
        return SCAScanDiffOutput(scanned_files=[], added_vulns=[], removed_vulns=[])

    if previous_ref is None:
        previous_tar = get_empty_tar()
    else:
        previous_tar = tar_from_ref_and_filepaths(
            ref=previous_ref, filepaths=previous_files, wd=str(directory)
        )

    current_tar = tar_from_ref_and_filepaths(
        ref=current_ref, filepaths=current_files, wd=str(directory)
    )

    scan_parameters = get_scan_params_from_config(config.user_config.sca)

    response = client.scan_diff(
        reference=previous_tar, current=current_tar, scan_parameters=scan_parameters
    )

    if not isinstance(response, SCAScanDiffOutput):
        if response.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        display_error("Error while scanning diff.")
        display_error(str(response))
        raise UnexpectedError("Unexpected error while scanning diff.")

    return response
