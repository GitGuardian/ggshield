import os
import tempfile
import traceback
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, List, Set

import click
from pygitguardian import GGClient

from .filter import path_filter_set
from .git_shell import check_git_dir, get_list_all_commits, get_list_commit_SHA, shell
from .message import process_results
from .path import get_files_from_paths
from .scannable import Commit


@contextmanager
def cd(newdir):
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)


@click.command()
@click.argument("repository", nargs=1, type=click.STRING, required=True)
@click.pass_context
def repo_cmd(ctx: click.Context, repository: str) -> int:  # pragma: no cover
    """
    clone and scan a REPOSITORY.

    REPOSITORY is the clone URI of the repository to scan.
    example:
    ggshield scan repo git@github.com:GitGuardian/gg-shield.git
    """
    config = ctx.obj["config"]
    try:
        with tempfile.TemporaryDirectory() as tmpdirname:
            shell(["git", "clone", repository, tmpdirname])
            with cd(tmpdirname):
                return scan_commit_range(
                    client=ctx.obj["client"],
                    commit_list=get_list_all_commits(),
                    verbose=config.verbose,
                    filter_set=path_filter_set(Path(os.getcwd()), []),
                    matches_ignore=config.matches_ignore,
                    all_policies=config.all_policies,
                    show_secrets=config.show_secrets,
                )
    except click.exceptions.Abort:
        return 0
    except Exception as error:
        if config.verbose:
            traceback.print_exc()
        raise click.ClickException(str(error))


@click.command()
@click.argument("commit_range", nargs=1, type=click.STRING)
@click.pass_context
def range_cmd(ctx: click.Context, commit_range: str) -> int:  # pragma: no cover
    """
    scan a defined COMMIT_RANGE in git.

    git rev-list COMMIT_RANGE to list several commits to scan.
    example: ggshield scan commit-range HEAD~1...
    """
    config = ctx.obj["config"]
    try:
        commit_list = get_list_commit_SHA(commit_range)
        if not commit_list:
            raise click.ClickException("invalid commit range")
        if config.verbose:
            click.echo(f"Commits to scan: {len(commit_list)}")

        return scan_commit_range(
            client=ctx.obj["client"],
            commit_list=commit_list,
            verbose=config.verbose,
            filter_set=ctx.obj["filter_set"],
            matches_ignore=config.matches_ignore,
            all_policies=config.all_policies,
            show_secrets=config.show_secrets,
        )
    except click.exceptions.Abort:
        return 0
    except Exception as error:
        if config.verbose:
            traceback.print_exc()
        raise click.ClickException(str(error))


@click.command()
@click.argument("precommit_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def precommit_cmd(
    ctx: click.Context, precommit_args: List[str]
) -> int:  # pragma: no cover
    """
    scan as a pre-commit git hook.
    """
    config = ctx.obj["config"]
    try:
        check_git_dir()

        return process_results(
            results=Commit(filter_set=ctx.obj["filter_set"]).scan(
                client=ctx.obj["client"],
                matches_ignore=config.matches_ignore,
                all_policies=config.all_policies,
                verbose=config.verbose,
            ),
            verbose=config.verbose,
            show_secrets=config.show_secrets,
        )
    except click.exceptions.Abort:
        return 0
    except Exception as error:
        if config.verbose:
            traceback.print_exc()
        raise click.ClickException(str(error))


@click.command()
@click.argument(
    "paths", nargs=-1, type=click.Path(exists=True, resolve_path=True), required=True
)
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively")
@click.option("--yes", "-y", is_flag=True, help="Confirm recursive scan")
@click.pass_context
def path_cmd(
    ctx: click.Context, paths: List[str], recursive: bool, yes: bool
) -> int:  # pragma: no cover
    """
    scan files and directories.
    """
    config = ctx.obj["config"]
    try:
        files = get_files_from_paths(
            paths=paths,
            paths_ignore=config.paths_ignore,
            recursive=recursive,
            yes=yes,
            verbose=config.verbose,
        )
        return process_results(
            results=files.scan(
                client=ctx.obj["client"],
                matches_ignore=config.matches_ignore,
                all_policies=config.all_policies,
                verbose=config.verbose,
            ),
            show_secrets=config.show_secrets,
            verbose=config.verbose,
        )
    except click.exceptions.Abort:
        return 0
    except Exception as error:
        if config.verbose:
            traceback.print_exc()
        raise click.ClickException(str(error))


def scan_commit_range(
    client: GGClient,
    commit_list: List[str],
    verbose: bool,
    filter_set: Set[str],
    matches_ignore: Iterable[str],
    all_policies: bool,
    show_secrets: bool,
) -> int:  # pragma: no cover
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_range: Range of commits to scan (A...B)
    :param verbose: Display successfull scan's message
    """
    return_code = 0

    for sha in commit_list:
        commit = Commit(sha, filter_set)
        results = commit.scan(
            client=client,
            matches_ignore=matches_ignore,
            all_policies=all_policies,
            verbose=verbose,
        )

        if results or verbose:
            click.echo("\nCommit {}:".format(sha))

        return_code = max(
            return_code,
            process_results(
                results=results, verbose=verbose, show_secrets=show_secrets,
            ),
        )

    return return_code
