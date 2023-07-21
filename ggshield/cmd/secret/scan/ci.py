from typing import Any

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.ci import get_ci_commits
from ggshield.core.cache import ReadOnlyCache
from ggshield.core.errors import handle_exception
from ggshield.scan import ScanContext, ScanMode
from ggshield.secret.repo import scan_commit_range


@click.command()
@add_secret_scan_common_options()
@click.pass_context
def ci_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """
    scan in a CI environment.
    """
    config = ctx.obj["config"]
    try:

        commit_list, ci_mode = get_ci_commits(config)

        mode_header = f"{ScanMode.CI.value}/{ci_mode.value}"

        if config.verbose:
            click.echo(f"Commits to scan: {len(commit_list)}", err=True)

        scan_context = ScanContext(
            scan_mode=mode_header,
            command_path=ctx.command_path,
            extra_headers={"Ci-Mode": ci_mode.name},
        )

        return scan_commit_range(
            client=ctx.obj["client"],
            cache=ReadOnlyCache(),
            commit_list=commit_list,
            output_handler=create_output_handler(ctx),
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            matches_ignore=config.secret.ignored_matches,
            scan_context=scan_context,
            ignored_detectors=config.secret.ignored_detectors,
        )
    except Exception as error:
        return handle_exception(error, config.verbose)
