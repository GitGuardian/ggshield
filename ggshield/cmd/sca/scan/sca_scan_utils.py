from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Pattern, Set, Tuple, Type, Union

import click
from pygitguardian.client import GGClient, _create_tar
from pygitguardian.sca_models import (
    ComputeSCAFilesResult,
    SCAIgnoredVulnerability,
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAScanParameters,
)

from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.files import check_directory_not_ignored
from ggshield.core import ui
from ggshield.core.config.user_config import SCAConfig
from ggshield.core.dirs import get_project_root_dir
from ggshield.core.errors import APIKeyCheckError, UnexpectedError
from ggshield.core.scan.scan_context import ScanContext
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.core.tar_utils import INDEX_REF, get_empty_tar, tar_from_ref_and_filepaths
from ggshield.verticals.sca.file_selection import (
    get_all_files_from_sca_paths,
    sca_files_from_git_repo,
)
from ggshield.verticals.sca.output.handler import SCAOutputHandler
from ggshield.verticals.sca.output.json_handler import SCAJsonOutputHandler
from ggshield.verticals.sca.output.text_handler import SCATextOutputHandler


def get_scan_params_from_config(sca_config: SCAConfig) -> SCAScanParameters:
    return SCAScanParameters(
        minimum_severity=sca_config.minimum_severity,
        ignored_vulnerabilities=[
            SCAIgnoredVulnerability(
                identifier=ignored_vuln.identifier, path=ignored_vuln.path
            )
            for ignored_vuln in sca_config.ignored_vulnerabilities
            if ignored_vuln.until is None
            or ignored_vuln.until >= datetime.now(tz=timezone.utc)
        ],
        ignore_fixable=sca_config.ignore_fixable,
        ignore_not_fixable=sca_config.ignore_not_fixable,
    )


def sca_scan_all(
    ctx: click.Context, directory: Path, scan_mode: ScanMode = ScanMode.DIRECTORY
) -> SCAScanAllOutput:
    """
    Scan an entire directory for SCA Vulnerabilities.

    - List SCA related files with a first call to SCA compute files API
    - Create a tar archive with the required files contents
    - Launches the scan with a call to SCA public API
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    client = ctx_obj.client
    exclusion_regexes = ctx_obj.exclusion_regexes

    check_directory_not_ignored(directory, exclusion_regexes)

    sca_filepaths, sca_filter_status_code = get_sca_scan_all_filepaths(
        directory=directory, exclusion_regexes=exclusion_regexes, client=client
    )

    if len(sca_filepaths) == 0:
        ui.display_info("No file to scan.")
        # Not an error, return an empty SCAScanAllOutput
        # with the status code returned by first call
        empty_output = SCAScanAllOutput(scanned_files=[], found_package_vulns=[])
        empty_output.status_code = sca_filter_status_code
        return empty_output

    root = get_project_root_dir(directory)
    relative_paths = [
        str((directory / x).resolve().relative_to(root)) for x in sca_filepaths
    ]

    scan_parameters = get_scan_params_from_config(config.user_config.sca)

    tar = _create_tar(root, relative_paths)

    # Call to full scan API and get results
    scan_result = client.sca_scan_directory(
        tar,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=scan_mode,
            target_path=directory,
        ).get_http_headers(),
    )

    if not isinstance(scan_result, SCAScanAllOutput):
        if scan_result.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        ui.display_error("Error scanning.")
        ui.display_error(str(scan_result))
        raise UnexpectedError("Unexpected error while performing SCA scan all.")

    return scan_result


def get_sca_scan_all_filepaths(
    directory: Path, exclusion_regexes: Set[Pattern[str]], client: GGClient
) -> Tuple[List[str], int]:
    """
    Retrieve SCA related files of a directory.
    First get all filenames that are not in blacklisted directories, then calls SCA compute files
    API to filter SCA related files.
    """
    all_filepaths = get_all_files_from_sca_paths(
        path=directory,
        exclusion_regexes=exclusion_regexes,
        # If the repository is a git repository, ignore untracked files
        ignore_git=True,
    )

    # API Call to filter SCA files
    response = client.compute_sca_files(files=all_filepaths)

    # First check is required by pyright to know that status_code cannot be None
    if response.status_code is None or not isinstance(response, ComputeSCAFilesResult):
        if response.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        ui.display_error("Error while filtering SCA related files.")
        ui.display_error(str(response))
        raise UnexpectedError("Unexpected error while filtering SCA related files.")

    # Only sca_files field is useful in the case of a full_scan,
    # all the potential files already exist in `all_filepaths`
    sca_files = response.sca_files
    if ui.is_verbose():
        ui.display_verbose("> Scanned files:")
        for filename in sca_files:
            ui.display_verbose(f"- {click.format_filename(filename)}")

    return sca_files, response.status_code


def create_output_handler(ctx: click.Context) -> SCAOutputHandler:
    """Read objects defined in ctx.obj and create the appropriate OutputHandler
    instance"""
    ctx_obj = ContextObj.get(ctx)
    output_handler_cls: Type[SCAOutputHandler]
    if ctx_obj.use_json:
        output_handler_cls = SCAJsonOutputHandler
    else:
        output_handler_cls = SCATextOutputHandler
    config = ctx_obj.config
    return output_handler_cls(
        verbose=ui.is_verbose(), exit_zero=config.user_config.exit_zero
    )


def sca_scan_diff(
    ctx: click.Context,
    directory: Path,
    previous_ref: Optional[str],
    scan_mode: Union[ScanMode, str],
    ci_mode: Optional[str] = None,
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
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    client = ctx_obj.client
    exclusion_regexes = ctx_obj.exclusion_regexes

    check_directory_not_ignored(directory, exclusion_regexes)

    if current_ref is None:
        current_ref = INDEX_REF if include_staged else "HEAD"
    if current_ref == previous_ref:
        ui.display_info("SCA scan diff comparing identical versions, scan skipped.")
        return SCAScanDiffOutput(scanned_files=[], added_vulns=[], removed_vulns=[])

    if previous_ref is None:
        previous_files = []
    else:
        previous_files = sca_files_from_git_repo(
            directory, previous_ref, client, exclusion_regexes=exclusion_regexes
        )

    current_files = sca_files_from_git_repo(
        directory, current_ref, client, exclusion_regexes=exclusion_regexes
    )

    if len(previous_files) == 0 and len(current_files) == 0:
        ui.display_info("No file to scan.")
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
        reference=previous_tar,
        current=current_tar,
        scan_parameters=scan_parameters,
        extra_headers=ScanContext(
            command_path=ctx.command_path,
            scan_mode=scan_mode,
            target_path=directory,
            extra_headers={"Ci-Mode": ci_mode} if ci_mode else None,
        ).get_http_headers(),
    )

    if not isinstance(response, SCAScanDiffOutput):
        if response.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        ui.display_error("Error while scanning diff.")
        ui.display_error(str(response))
        raise UnexpectedError("Unexpected error while scanning diff.")

    return response
