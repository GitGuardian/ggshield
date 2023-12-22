from pathlib import Path
from typing import Any, List

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.hooks import check_user_requested_skip
from ggshield.core.scan import Commit, ScanContext, ScanMode
from ggshield.utils.git_shell import check_git_dir
from ggshield.verticals.secret import SecretScanCollection, SecretScanner
from ggshield.verticals.secret.output import SecretTextOutputHandler
from ggshield.verticals.secret.output.messages import remediation_message


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
@exception_wrapper
def precommit_cmd(
    ctx: click.Context, precommit_args: List[str], **kwargs: Any
) -> int:  # pragma: no cover
    """
    Scan as a pre-commit hook all changes that have been staged in a git repository.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    verbose = config.user_config.verbose

    if check_user_requested_skip():
        return 0

    output_handler = SecretTextOutputHandler(
        show_secrets=config.user_config.secret.show_secrets,
        verbose=verbose,
        output=None,
        ignore_known_secrets=config.user_config.secret.ignore_known_secrets,
    )
    check_git_dir()

    scan_context = ScanContext(
        scan_mode=ScanMode.PRE_COMMIT,
        command_path=ctx.command_path,
        target_path=Path.cwd(),
    )

    commit = Commit.from_staged(ctx_obj.exclusion_regexes)
    scanner = SecretScanner(
        client=ctx_obj.client,
        cache=ctx_obj.cache,
        scan_context=scan_context,
        ignored_matches=config.user_config.secret.ignored_matches,
        ignored_detectors=config.user_config.secret.ignored_detectors,
    )
    with ctx_obj.ui.create_scanner_ui(len(commit.urls), verbose=verbose) as scanner_ui:
        results = scanner.scan(commit.get_files(), scanner_ui)

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
