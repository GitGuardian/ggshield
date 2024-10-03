from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.sca.scan.sca_scan_utils import (
    create_output_handler,
    sca_scan_all,
    sca_scan_diff,
)
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.common_options import directory_argument
from ggshield.core import ui
from ggshield.core.git_hooks.ci.get_scan_ci_parameters import (
    NotAMergeRequestError,
    get_scan_ci_parameters,
)
from ggshield.core.git_hooks.ci.supported_ci import SupportedCI
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.utils.git_shell import git
from ggshield.verticals.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)


@click.command()
@add_sca_scan_common_options()
@click.pass_context
@directory_argument
@exception_wrapper
def scan_ci_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    ignore_fixable: bool,
    ignore_not_fixable: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Evaluates if a CI event introduces SCA vulnerabilities.

    Scanning a repository with this command will not trigger any incident on your dashboard.

    Only metadata such as call time, request size and scan mode is stored server-side.
    """
    if directory is None:
        directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(
        ctx,
        exit_zero,
        minimum_severity,
        ignore_paths,
        ignore_fixable,
        ignore_not_fixable,
    )

    ci_mode = SupportedCI.from_ci_env()
    output_handler = create_output_handler(ctx)

    try:
        # we will work with branch names and deep commits, so we run a git fetch to ensure the
        # branch names and commit sha are locally available
        git(["fetch"], cwd=directory)
        params = get_scan_ci_parameters(ci_mode, wd=directory)
        if params is None:
            ui.display_info("No commit found in merge request, skipping scan.")
            return 0

        current_commit, reference_commit = params
        scan_mode = f"{ScanMode.CI_DIFF.value}/{ci_mode.value}"
        result = sca_scan_diff(
            ctx=ctx,
            directory=directory,
            previous_ref=reference_commit,
            current_ref=current_commit,
            scan_mode=scan_mode,
            ci_mode=ci_mode.name,
        )
        scan = SCAScanDiffVulnerabilityCollection(id=str(directory), result=result)
        return output_handler.process_scan_diff_result(scan)
    except NotAMergeRequestError:
        ui.display_warning(
            "scan ci expects to be run in a merge-request pipeline.\n"
            "No target branch could be identified, will perform a scan all instead.\n"
            "This is a fallback behaviour, that will be removed in a future version."
        )
        result = sca_scan_all(ctx, directory=directory, scan_mode=ScanMode.CI_ALL)
        scan = SCAScanAllVulnerabilityCollection(id=str(directory), result=result)
        return output_handler.process_scan_all_result(scan)
