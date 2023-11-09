from typing import Any

import click

from ggshield.cmd.sca.scan.all import scan_all_cmd
from ggshield.cmd.sca.scan.ci import scan_ci_cmd
from ggshield.cmd.sca.scan.diff import scan_diff_cmd
from ggshield.cmd.sca.scan.precommit import scan_pre_commit_cmd
from ggshield.cmd.sca.scan.prepush import scan_pre_push_cmd
from ggshield.cmd.sca.scan.prereceive import scan_pre_receive_cmd


@click.group(
    commands={
        "pre-commit": scan_pre_commit_cmd,
        "all": scan_all_cmd,
        "ci": scan_ci_cmd,
        "pre-push": scan_pre_push_cmd,
        "diff": scan_diff_cmd,
        "pre-receive": scan_pre_receive_cmd,
    }
)
@click.pass_context
def scan_group(*args: Any, **kwargs: Any) -> None:
    """Perform a SCA scan."""
