import _thread as thread
import os
import sys
import threading
from typing import Any, List

import click

from ggshield.dev_scan import scan_commit_range
from ggshield.text_utils import display_error
from ggshield.utils import (
    EMPTY_SHA,
    EMPTY_TREE,
    PRERECEIVE_TIMEOUT,
    SupportedScanMode,
    handle_exception,
)

from .git_shell import get_list_commit_SHA


def quit_function() -> None:  # pragma: no cover
    display_error("\nPre-receive hook took too long")
    thread.interrupt_main()  # raises KeyboardInterrupt


class ExitAfter:
    timeout_secs: float
    timer: threading.Timer

    def __init__(self, timeout_secs: float):
        self.timeout_secs = timeout_secs

    def __enter__(self) -> None:
        if self.timeout_secs:
            self.timer = threading.Timer(self.timeout_secs, quit_function)
            self.timer.start()

    def __exit__(self, *args: Any, **kwargs: Any) -> None:
        if self.timeout_secs:
            self.timer.cancel()


def get_prereceive_timeout() -> float:
    try:
        return float(os.getenv("GITGUARDIAN_TIMEOUT", PRERECEIVE_TIMEOUT))
    except BaseException as e:
        display_error(f"Unable to parse GITGUARDIAN_TIMEOUT: {str(e)}")
        return PRERECEIVE_TIMEOUT


def get_breakglass_option() -> bool:
    """Test all options passed to git for `breakglass`"""
    raw_option_count = os.getenv("GIT_PUSH_OPTION_COUNT", None)
    if raw_option_count is not None:
        option_count = int(raw_option_count)
        for option in range(option_count):
            if os.getenv(f"GIT_PUSH_OPTION_{option}", "") == "breakglass":
                return True

    return False


@click.command()
@click.argument("prereceive_args", nargs=-1, type=click.UNPROCESSED)
@click.option(
    "--web",
    is_flag=True,
    default=None,
    help="Scan commits added through the web interface (gitlab only)",
)
@click.pass_context
def prereceive_cmd(ctx: click.Context, web: bool, prereceive_args: List[str]) -> int:
    """
    scan as a pre-receive git hook.
    """
    config = ctx.obj["config"]

    if get_breakglass_option():
        click.echo("SKIP: breakglass detected. Skipping GitGuardian pre-receive hook.")

        return 0

    if not web and os.getenv("GL_PROTOCOL", "") == "web":
        click.echo(
            "GL-HOOK-ERR: SKIP: web push detected. Skipping GitGuardian pre-receive hook."
        )

        return 0

    args = sys.stdin.read().strip().split()
    if len(args) < 3:
        raise click.ClickException(f"Invalid input arguments: {args}")

    before, after, *_ = args
    commit_list = []

    if after == EMPTY_SHA:
        click.echo("Deletion event or nothing to scan.")
        return 0

    if before == EMPTY_SHA:
        before = "HEAD"
        commit_list = get_list_commit_SHA(
            f"--max-count={config.max_commits_for_hook+1} {before}...{after}"
        )

        if not commit_list:
            before = EMPTY_TREE
            click.echo(
                f"New tree event. Scanning last {config.max_commits_for_hook} commits."
            )
            commit_list = get_list_commit_SHA(
                f"--max-count={config.max_commits_for_hook+1} {EMPTY_TREE} {after}"
            )
    else:
        commit_list = get_list_commit_SHA(
            f"--max-count={config.max_commits_for_hook+1} {before}...{after}"
        )

    if not commit_list:
        click.echo(
            "Unable to get commit range.\n"
            f"  before: {before}\n"
            f"  after: {after}\n"
            "Skipping pre-receive hook\n"
        )
        return 0

    if len(commit_list) > config.max_commits_for_hook:
        click.echo(
            f"Too many commits. Scanning last {config.max_commits_for_hook} commits\n"
        )
        commit_list = commit_list[-config.max_commits_for_hook :]

    if config.verbose:
        click.echo(f"Commits to scan: {len(commit_list)}")

    try:
        with ExitAfter(get_prereceive_timeout()):
            return_code = scan_commit_range(
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                commit_list=commit_list,
                output_handler=ctx.obj["output_handler"],
                verbose=config.verbose,
                exclusion_regexes=ctx.obj["exclusion_regexes"],
                matches_ignore=config.matches_ignore,
                all_policies=config.all_policies,
                scan_id=" ".join(commit_list),
                mode_header=SupportedScanMode.PRE_RECEIVE.value,
                banlisted_detectors=config.banlisted_detectors,
            )
            if return_code:
                click.echo(
                    """Rewrite your git history to delete evidence of your secrets.
Use environment variables to use your secrets instead and store them in a file not tracked by git.

If you don't want to go through this painful git history rewrite in the future,
you can set up ggshield in your pre commit:
https://docs.gitguardian.com/internal-repositories-monitoring/integrations/git_hooks/pre_commit

Use it carefully: if those secrets are false positives and you still want your push to pass, run:
'git push -o breakglass'"""
                )
            return return_code

    except Exception as error:
        return handle_exception(error, config.verbose)
