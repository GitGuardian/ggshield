import logging
import os
from pathlib import Path
from typing import Any

import click
from click import UsageError

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.cache import ReadOnlyCache
from ggshield.core.git_hooks.ci import collect_commit_range_from_ci_env
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.core.text_utils import display_info
from ggshield.utils.git_shell import check_git_dir
from ggshield.verticals.secret.repo import scan_commit_range


logger = logging.getLogger(__name__)


@click.command()
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def ci_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """
    Scan the set of pushed commits that triggered the CI pipeline.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    check_git_dir()
    if not (os.getenv("CI") or os.getenv("JENKINS_HOME") or os.getenv("BUILD_BUILDID")):
        raise UsageError("`secret scan ci` should only be used in a CI environment.")

    commit_list, ci_mode = collect_commit_range_from_ci_env(config.user_config.verbose)
    mode_header = f"{ScanMode.CI.value}/{ci_mode.value}"

    if config.user_config.verbose:
        display_info(f"Commits to scan: {len(commit_list)}")
    logger.debug("commit_list=%s", commit_list)

    scan_context = ScanContext(
        scan_mode=mode_header,
        command_path=ctx.command_path,
        target_path=Path.cwd(),
        extra_headers={"Ci-Mode": ci_mode.name},
    )

    return scan_commit_range(
        client=ctx_obj.client,
        cache=ReadOnlyCache(),
        ui=ctx_obj.ui,
        commit_list=commit_list,
        output_handler=create_output_handler(ctx),
        exclusion_regexes=ctx_obj.exclusion_regexes,
        matches_ignore=config.user_config.secret.ignored_matches,
        scan_context=scan_context,
        ignored_detectors=config.user_config.secret.ignored_detectors,
    )
