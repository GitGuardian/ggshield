import _thread as thread
import logging
import os
import sys
import threading
from types import TracebackType
from typing import Any, List, Optional, Tuple, Type

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.core.cache import ReadOnlyCache
from ggshield.core.errors import UnexpectedError, handle_exception
from ggshield.core.git_shell import get_list_commit_SHA, git
from ggshield.core.text_utils import display_error
from ggshield.core.utils import EMPTY_SHA, PRERECEIVE_TIMEOUT
from ggshield.output import GitLabWebUIOutputHandler
from ggshield.output.text.message import remediation_message
from ggshield.scan import ScanContext, ScanMode
from ggshield.scan.repo import scan_commit_range


logger = logging.getLogger(__name__)

REMEDIATION_MESSAGE = """  A pre-receive hook set server side prevented you from pushing secrets.
  Since the secret was detected during the push BUT after the commit, you need to:
  1. rewrite the git history making sure to replace the secret with its reference (e.g. environment variable).
  2. push again."""

BYPASS_MESSAGE = """\n     git push -o breakglass"""


def quit_function() -> None:
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

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        if self.timeout_secs:
            self.timer.cancel()
        if exc_type == KeyboardInterrupt:
            # Turn the KeyboardInterrupt raised by quit_function into a more appropriate
            # exception
            raise TimeoutError()


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


def find_branch_start(commit: str) -> Optional[str]:
    """
    Returns the first local-only commit of the branch.
    Returns None if the branch does not contain any new commit.
    """
    # List all ancestors of `commit` which are not in any branches
    output = git(
        ["rev-list", commit, "--topo-order", "--reverse", "--not", "--branches"]
    )
    ancestors = output.splitlines()

    if ancestors:
        return ancestors[0]
    return None


def parse_stdin() -> Optional[Tuple[str, str]]:
    """
    Parse stdin and return the first and last commit to scan,
    or None if there is nothing to do
    """
    prereceive_input = sys.stdin.read().strip()
    if not prereceive_input:
        raise UnexpectedError(f"Invalid input arguments: '{prereceive_input}'")

    # TODO There can be more than one line here, for example when pushing multiple
    # branches. We should support this.
    line = prereceive_input.splitlines()[0]
    logger.debug("stdin: %s", line)
    _old_commit, new_commit, _ = line.split(maxsplit=2)

    if new_commit == EMPTY_SHA:
        # Deletion event, nothing to do
        return None

    # ignore _old_commit because in case of a force-push, it is going to be overwritten
    # and should not be scanned (see #437)
    start_commit = find_branch_start(new_commit)
    if start_commit is None:
        # branch does not contain any new commit
        old_commit = new_commit
    else:
        old_commit = f"{start_commit}~1"

    return (old_commit, new_commit)


@click.command()
@click.argument("prereceive_args", nargs=-1, type=click.UNPROCESSED)
@click.option(
    "--web",
    is_flag=True,
    default=None,
    help="Deprecated",
    hidden=True,
)
@add_secret_scan_common_options()
@click.pass_context
def prereceive_cmd(
    ctx: click.Context, web: bool, prereceive_args: List[str], **kwargs: Any
) -> int:
    """
    scan as a pre-receive git hook.
    """
    config = ctx.obj["config"]
    output_handler = create_output_handler(ctx)

    if os.getenv("GL_PROTOCOL") == "web":
        # We are inside GitLab web UI
        output_handler = GitLabWebUIOutputHandler(
            show_secrets=config.secret.show_secrets
        )

    if get_breakglass_option():
        click.echo(
            "SKIP: breakglass detected. Skipping GitGuardian pre-receive hook.",
            err=True,
        )
        return 0

    before_after = parse_stdin()
    if before_after is None:
        click.echo("Deletion event or nothing to scan.", err=True)
        return 0

    before, after = before_after
    if before == after:
        click.echo(
            "Pushed branch does not contain any new commit.",
            err=True,
        )
        return 0

    assert before != EMPTY_SHA
    assert after != EMPTY_SHA
    commit_list = get_list_commit_SHA(
        f"{before}...{after}", max_count=config.max_commits_for_hook + 1
    )

    assert commit_list, "Commit list should not be empty at this point"

    if len(commit_list) > config.max_commits_for_hook:
        click.echo(
            f"Too many commits. Scanning last {config.max_commits_for_hook} commits\n",
            err=True,
        )
        commit_list = commit_list[-config.max_commits_for_hook :]

    if config.verbose:
        click.echo(f"Commits to scan: {len(commit_list)}", err=True)

    try:
        with ExitAfter(get_prereceive_timeout()):

            scan_context = ScanContext(
                scan_mode=ScanMode.PRE_RECEIVE,
                command_path=ctx.command_path,
            )

            return_code = scan_commit_range(
                client=ctx.obj["client"],
                cache=ReadOnlyCache(),
                commit_list=commit_list,
                output_handler=output_handler,
                exclusion_regexes=ctx.obj["exclusion_regexes"],
                matches_ignore=config.secret.ignored_matches,
                scan_context=scan_context,
                ignored_detectors=config.secret.ignored_detectors,
                ignore_known_secrets=config.ignore_known_secrets,
            )
            if return_code:
                click.echo(
                    remediation_message(
                        remediation_steps=REMEDIATION_MESSAGE,
                        bypass_message=BYPASS_MESSAGE,
                        rewrite_git_history=True,
                    ),
                    err=True,
                )
            return return_code
    except TimeoutError:
        return 0
    except Exception as error:
        return handle_exception(error, config.verbose)
