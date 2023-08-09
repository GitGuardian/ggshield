from typing import Any, List

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)
from ggshield.core.config import Config
from ggshield.core.errors import handle_exception
from ggshield.core.git_shell import check_git_dir
from ggshield.scan import Commit, ScanContext, ScanMode
from ggshield.secret import SecretScanCollection, SecretScanner
from ggshield.secret.output import SecretTextOutputHandler
from ggshield.secret.output.messages import remediation_message


REMEDIATION_STEPS = """  Since the secret was detected before the commit was made:
  1. replace the secret with its reference (e.g. environment variable).
  2. commit again."""

BYPASS_MESSAGE = """  - if you use the pre-commit framework:

     SKIP=ggshield git commit -m "<your message>"

  - otherwise (warning: the following command bypasses all pre-commit hooks):

     git commit -m "<your message>" --no-verify"""


@click.command()
@click.argument("precommit_args", nargs=-1, type=click.UNPROCESSED)
@add_secret_scan_common_options()
@click.pass_context
def precommit_cmd(
    ctx: click.Context, precommit_args: List[str], **kwargs: Any
) -> int:  # pragma: no cover
    """
    scan as a pre-commit git hook.
    """
    config: Config = ctx.obj["config"]
    output_handler = SecretTextOutputHandler(
        show_secrets=config.user_config.secret.show_secrets,
        verbose=config.user_config.verbose,
        output=None,
        ignore_known_secrets=config.user_config.secret.ignore_known_secrets,
    )
    try:
        check_git_dir()

        scan_context = ScanContext(
            scan_mode=ScanMode.PRE_COMMIT,
            command_path=ctx.command_path,
        )

        commit = Commit(exclusion_regexes=ctx.obj["exclusion_regexes"])
        scanner = SecretScanner(
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            scan_context=scan_context,
            ignored_matches=config.user_config.secret.ignored_matches,
            ignored_detectors=config.user_config.secret.ignored_detectors,
        )
        results = scanner.scan(commit.files)

        return_code = output_handler.process_scan(
            SecretScanCollection(id="cached", type="pre-commit", results=results)
        )
        if return_code:
            click.echo(
                remediation_message(
                    remediation_steps=REMEDIATION_STEPS,
                    bypass_message=BYPASS_MESSAGE,
                    rewrite_git_history=False,
                ),
                err=True,
            )
        return return_code
    except Exception as error:
        return handle_exception(error, config.user_config.verbose)
