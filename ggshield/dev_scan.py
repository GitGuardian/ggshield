import concurrent.futures
import os
import re
import tempfile
from contextlib import contextmanager
from typing import Iterable, Iterator, List, Optional, Set

import click
from pygitguardian import GGClient

from ggshield.output import OutputHandler
from ggshield.scan import Commit, ScanCollection
from ggshield.text_utils import STYLE, format_text

from .config import CPU_COUNT, Cache, Config
from .git_shell import GIT_PATH, get_list_commit_SHA, is_git_dir, shell
from .path import get_files_from_paths
from .utils import REGEX_GIT_URL, SupportedScanMode, handle_exception


@contextmanager
def cd(newdir: str) -> Iterator[None]:
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)


def scan_repo_path(
    client: GGClient,
    cache: Cache,
    output_handler: OutputHandler,
    config: Config,
    repo_path: str,
    scan_id: str,
) -> int:  # pragma: no cover
    try:
        with cd(repo_path):
            if not is_git_dir():
                raise click.ClickException(f"{repo_path} is not a git repository")

            return scan_commit_range(
                client=client,
                cache=cache,
                commit_list=get_list_commit_SHA("--all"),
                output_handler=output_handler,
                verbose=config.verbose,
                exclusion_regexes=set(),
                matches_ignore=config.matches_ignore,
                all_policies=config.all_policies,
                scan_id=scan_id,
                mode_header=SupportedScanMode.REPO.value,
                banlisted_detectors=config.banlisted_detectors,
            )
    except Exception as error:
        return handle_exception(error, config.verbose)


@click.command()
@click.argument("repository", nargs=1, type=click.STRING, required=True)
@click.pass_context
def repo_cmd(ctx: click.Context, repository: str) -> int:  # pragma: no cover
    """
    scan a REPOSITORY's commits at a given URL or path.

    REPOSITORY is the clone URI or the path of the repository to scan.
    Examples:

    ggshield scan repo git@github.com:GitGuardian/ggshield.git

    ggshield scan repo /repositories/ggshield
    """
    config: Config = ctx.obj["config"]
    cache: Cache = ctx.obj["cache"]
    client: GGClient = ctx.obj["client"]
    if os.path.isdir(repository):
        return scan_repo_path(
            client=client,
            cache=cache,
            output_handler=ctx.obj["output_handler"],
            config=config,
            repo_path=repository,
            scan_id=repository,
        )

    if REGEX_GIT_URL.match(repository):
        with tempfile.TemporaryDirectory() as tmpdirname:
            shell([GIT_PATH, "clone", repository, tmpdirname])
            return scan_repo_path(
                client=client,
                cache=cache,
                output_handler=ctx.obj["output_handler"],
                config=config,
                repo_path=tmpdirname,
                scan_id=repository,
            )

    if any(host in repository for host in ("gitlab.com", "github.com")):
        raise click.ClickException(
            f"{repository} doesn't seem to be a valid git URL.\n"
            f"Did you mean {repository}.git?"
        )
    raise click.ClickException(f"{repository} is neither a valid path nor a git URL")


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
            cache=ctx.obj["cache"],
            commit_list=commit_list,
            output_handler=ctx.obj["output_handler"],
            verbose=config.verbose,
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            matches_ignore=config.matches_ignore,
            all_policies=config.all_policies,
            scan_id=commit_range,
            mode_header=SupportedScanMode.COMMIT_RANGE.value,
            banlisted_detectors=config.banlisted_detectors,
        )
    except Exception as error:
        return handle_exception(error, config.verbose)


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
    output_handler: OutputHandler = ctx.obj["output_handler"]
    try:
        files = get_files_from_paths(
            paths=paths,
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            recursive=recursive,
            yes=yes,
            verbose=config.verbose,
            # when scanning a path explicitly we should not care if it is a git repository or not
            ignore_git=True,
        )
        results = files.scan(
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            matches_ignore=config.matches_ignore,
            banlisted_detectors=config.banlisted_detectors,
            all_policies=config.all_policies,
            verbose=config.verbose,
            mode_header=SupportedScanMode.PATH.value,
        )
        scan = ScanCollection(id=" ".join(paths), type="path_scan", results=results)

        return output_handler.process_scan(scan)[1]
    except Exception as error:
        return handle_exception(error, config.verbose)


def scan_commit(
    commit: Commit,
    client: GGClient,
    cache: Cache,
    verbose: bool,
    matches_ignore: Iterable[str],
    all_policies: bool,
    mode_header: str,
    banlisted_detectors: Optional[Set[str]] = None,
) -> ScanCollection:  # pragma: no cover
    results = commit.scan(
        client=client,
        cache=cache,
        matches_ignore=matches_ignore,
        banlisted_detectors=banlisted_detectors,
        all_policies=all_policies,
        verbose=verbose,
        mode_header=mode_header,
    )

    return ScanCollection(
        commit.sha or "unknown",
        type="commit",
        results=results,
        optional_header=commit.optional_header,
        extra_info=commit.info._asdict(),
    )


def scan_commit_range(
    client: GGClient,
    cache: Cache,
    commit_list: List[str],
    output_handler: OutputHandler,
    verbose: bool,
    exclusion_regexes: Set[re.Pattern],
    matches_ignore: Iterable[str],
    all_policies: bool,
    scan_id: str,
    mode_header: str,
    banlisted_detectors: Optional[Set[str]] = None,
) -> int:  # pragma: no cover
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_list: List of commits sha to scan
    :param verbose: Display successfull scan's message
    """
    return_code = 0
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(CPU_COUNT, 4)
    ) as executor:
        future_to_process = [
            executor.submit(
                scan_commit,
                Commit(sha, exclusion_regexes),
                client,
                cache,
                verbose,
                matches_ignore,
                all_policies,
                mode_header,
                banlisted_detectors,
            )
            for sha in commit_list
        ]

        scans: List[ScanCollection] = []
        with click.progressbar(
            iterable=concurrent.futures.as_completed(future_to_process),
            length=len(future_to_process),
            label=format_text("Scanning Commits", STYLE["progress"]),
        ) as completed_futures:
            for future in completed_futures:
                scans.append(future.result())

        return_code = output_handler.process_scan(
            ScanCollection(id=scan_id, type="commit-range", scans=scans)
        )[1]
    return return_code
