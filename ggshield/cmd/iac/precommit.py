import json
import subprocess as sp
from pathlib import Path
from typing import Any, Union

import click

from ggshield.cmd.iac.scan import iac_scan
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.errors import ExitCode
from ggshield.core.filter import init_exclusion_regexes
from ggshield.iac.iac_scan_collection import IaCScanCollection
from ggshield.iac.output import IaCJSONOutputHandler


@click.command()
@click.argument("precommit_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def precommit_cmd(
    ctx: click.Context, precommit_args: list[str], **kwargs: Any
) -> Union[int, set[tuple[Any, Any]]]:  # modify typing as this is for testing
    """
    iac scan as a pre-commit git hook.
    """
    directory = Path().resolve()
    config: Config = ctx.obj["config"]
    ctx.obj["client"] = create_client_from_config(config)
    ctx.obj["exclusion_regexes"] = init_exclusion_regexes(
        config.user_config.iac.ignored_paths
    )
    post_add_result = iac_scan(ctx, directory)
    post_add_scan = IaCScanCollection(
        id=str(directory), type="path_scan", result=post_add_result
    )
    output_handler_cls = IaCJSONOutputHandler

    post_add_output_handler = output_handler_cls(verbose=config.user_config.verbose)
    post_add_vulns = json.loads(
        post_add_output_handler._process_scan_impl(post_add_scan)
    )

    staged_files_sp = sp.run(
        ["git", "diff", "--name-only", "--cached"],
        capture_output=True,
        encoding="utf-8",
    ).stdout
    staged_files = staged_files_sp.split("\n")[:-1]  # last element is ''

    # restore all staged files
    sp.run(["git", "restore", "--staged"] + staged_files)

    pre_add_result = iac_scan(ctx, directory)
    pre_add_scan = IaCScanCollection(
        id=str(directory), type="path_scan", result=pre_add_result
    )
    pre_add_output_handler = output_handler_cls(verbose=config.user_config.verbose)
    pre_add_vulns = json.loads(pre_add_output_handler._process_scan_impl(pre_add_scan))

    # revert unstaging of modified files
    sp.run(["git", "add"] + staged_files)

    if post_add_vulns["total_incidents"] == pre_add_vulns["total_incidents"]:
        return ExitCode.SUCCESS

    post_add_incidents = set(
        [
            (file["filename"], incident["policy_id"])
            for file in post_add_vulns["entities_with_incidents"]
            for incident in file["incidents"]
        ]
    )
    pre_add_incidents = set(
        [
            (file["filename"], incident["policy_id"])
            for file in pre_add_vulns["entities_with_incidents"]
            for incident in file["incidents"]
        ]
    )

    if post_add_incidents - pre_add_incidents:
        return post_add_incidents - pre_add_incidents
    return ExitCode.SUCCESS
