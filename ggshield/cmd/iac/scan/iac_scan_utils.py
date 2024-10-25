from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Pattern, Set, Type, Union

import click
from pygitguardian import GGClient
from pygitguardian.iac_models import IaCDiffScanResult, IaCScanResult
from pygitguardian.models import Detail

from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.config.user_config import UserConfig
from ggshield.core.errors import APIKeyCheckError
from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.tar_utils import INDEX_REF, tar_from_ref_and_filepaths
from ggshield.utils.files import is_path_excluded
from ggshield.utils.git_shell import get_filepaths_from_ref, get_staged_filepaths
from ggshield.verticals.iac.collection.iac_scan_collection import IaCResult
from ggshield.verticals.iac.filter import is_iac_file_path
from ggshield.verticals.iac.output import (
    IaCJSONOutputHandler,
    IaCOutputHandler,
    IaCTextOutputHandler,
)


@dataclass
class IaCSkipScanResult:
    id: str = ""


def create_output_handler(ctx: click.Context) -> IaCOutputHandler:
    """Read objects defined in ctx.obj and create the appropriate OutputHandler
    instance"""
    ctx_obj = ContextObj.get(ctx)
    output_handler_cls: Type[IaCOutputHandler]
    if ctx_obj.use_json:
        output_handler_cls = IaCJSONOutputHandler
    else:
        output_handler_cls = IaCTextOutputHandler
    return output_handler_cls(verbose=ui.is_verbose())


def handle_scan_error(client: GGClient, detail: Detail) -> None:
    if detail.status_code == 401:
        raise APIKeyCheckError(client.base_uri, "Invalid API key.")
    ui.display_error("\nError scanning.")
    msg = str(detail)
    ui.display_error(msg)


def get_git_filepaths(directory: Path, ref: str) -> Iterable[Path]:
    return (
        get_staged_filepaths(str(directory))
        if ref == INDEX_REF
        else get_filepaths_from_ref(ref, str(directory))
    )


def _accept_iac_file_on_path(
    path: Path, directory: Path, exclusion_regexes: Optional[Set[Pattern[str]]] = None
) -> bool:
    return is_iac_file_path(path) and (
        exclusion_regexes is None
        or not is_path_excluded(directory / path, exclusion_regexes)
    )


def filter_iac_filepaths(
    directory: Path,
    filepaths: Iterable[Path],
    exclusion_regexes: Optional[Set[Pattern[str]]] = None,
) -> Iterable[Path]:
    # You can filter based on file's content here
    # using read_git_file (result will be cached)
    # You should filter on path first, in order to read
    # the content only if necessary
    return [
        path
        for path in filepaths
        if _accept_iac_file_on_path(
            path, directory, exclusion_regexes=exclusion_regexes
        )
    ]


def get_iac_tar(
    directory: Path, ref: str, exclusion_regexes: Set[Pattern[str]]
) -> bytes:
    filepaths = get_git_filepaths(directory, ref)
    filtered_paths = filter_iac_filepaths(
        directory=directory,
        filepaths=filepaths,
        exclusion_regexes=exclusion_regexes,
    )

    return tar_from_ref_and_filepaths(ref, filtered_paths, wd=str(directory))


def augment_unignored_issues(
    user_config: UserConfig,
    result: Union[IaCResult, IaCSkipScanResult, None],
) -> None:
    """
    GIVEN a list of vulnerabilities from a scan result
    WHEN ignored policies and paths are configured but outdated
    THEN augment the vulnerability with the date it was last ignored
    """
    if isinstance(result, IaCScanResult):
        incidents_list = result.entities_with_incidents
    elif isinstance(result, IaCDiffScanResult):
        incidents_list = [
            *result.entities_with_incidents.new,
            *result.entities_with_incidents.unchanged,
            *result.entities_with_incidents.deleted,
        ]
    else:
        return
    if len(incidents_list) == 0:
        return
    outdated_ignored_paths = user_config.iac.outdated_ignored_paths
    outdated_ignored_policies = user_config.iac.outdated_ignored_policies
    # Early return if there are no outdated configurations
    if len(outdated_ignored_paths) == 0 and len(outdated_ignored_policies) == 0:
        return
    outdated_ignored_paths_dicts = [
        {
            "regex": init_exclusion_regexes({outdated_ignored_path.path}),
            "until": outdated_ignored_path.until,
        }
        for outdated_ignored_path in outdated_ignored_paths
    ]
    outdated_ignored_policies_dict = {
        outdated_policy.policy: outdated_policy.until
        for outdated_policy in outdated_ignored_policies
    }
    # For each file and each vulnerability within
    for file_result in incidents_list:
        # Check if path was ignored
        file_path = file_result.filename
        file_ignored_until = None
        for outdated_ignored_path in outdated_ignored_paths_dicts:
            if is_path_excluded(file_path, outdated_ignored_path["regex"]):
                if (
                    file_ignored_until is None
                    or file_ignored_until < outdated_ignored_path["until"]
                ):
                    file_ignored_until = outdated_ignored_path["until"]
        for vulnerability in file_result.incidents:
            # Check if policy was ignored
            policy_ignored_until = outdated_ignored_policies_dict.get(
                vulnerability.policy_id
            )
            until_dates = (policy_ignored_until, file_ignored_until)
            # Augment vulnerability with the most recent ignored_until date
            vulnerability.ignored_until = max(
                (d for d in until_dates if d is not None), default=None
            )
