import os
from pathlib import Path
from typing import Any, Optional, Sequence

import click
from click import UsageError

from ggshield.cmd.common_options import all_option, directory_argument
from ggshield.cmd.sca.scan.sca_scan_utils import (
    create_output_handler,
    display_sca_beta_warning,
    sca_scan_all,
    sca_scan_diff,
)
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.core.config import Config
from ggshield.core.errors import handle_exception
from ggshield.core.git_hooks.ci import get_current_and_previous_state_from_ci_env
from ggshield.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)


@click.command()
@add_sca_scan_common_options()
@click.pass_context
@directory_argument
@all_option
@display_sca_beta_warning
def scan_ci_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    directory: Optional[Path],
    scan_all: bool,
    **kwargs: Any,
) -> int:
    """
    scan in a CI environment.
    """
    if directory is None:
        directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(ctx, exit_zero, minimum_severity, ignore_paths)

    config: Config = ctx.obj["config"]
    try:
        if not (
            os.getenv("CI") or os.getenv("JENKINS_HOME") or os.getenv("BUILD_BUILDID")
        ):
            raise UsageError("`sca scan ci` should only be used in a CI environment.")

        output_handler = create_output_handler(ctx)
        if scan_all:
            result = sca_scan_all(ctx, directory)
            scan = SCAScanAllVulnerabilityCollection(id=str(directory), result=result)
            return output_handler.process_scan_all_result(scan)

        current_commit, previous_commit = get_current_and_previous_state_from_ci_env(
            config.user_config.verbose
        )

        result = sca_scan_diff(
            ctx=ctx,
            directory=directory,
            previous_ref=previous_commit,
            current_ref=current_commit,
        )
        scan = SCAScanDiffVulnerabilityCollection(id=str(directory), result=result)
        return output_handler.process_scan_diff_result(scan)

    except Exception as error:
        return handle_exception(error, config.user_config.verbose)
