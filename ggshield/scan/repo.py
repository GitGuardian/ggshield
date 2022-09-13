import concurrent.futures
import os
import re
import sys
from contextlib import contextmanager
from typing import Iterable, Iterator, List, Optional, Set

import click
from pygitguardian import GGClient

from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.constants import MAX_WORKERS
from ggshield.core.git_shell import get_list_commit_SHA, is_git_dir
from ggshield.core.text_utils import STYLE, display_error, format_text
from ggshield.core.types import IgnoredMatch
from ggshield.core.utils import ScanContext, handle_exception
from ggshield.output import OutputHandler
from ggshield.scan import Commit, Results, ScanCollection


# We add a maximal value to avoid silently consuming all threads on powerful machines
SCAN_THREADS = 4


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
    scan_context: ScanContext,
    repo_path: str,
) -> int:  # pragma: no cover
    try:
        if not is_git_dir(repo_path):
            raise click.ClickException(f"{repo_path} is not a git repository")

        with cd(repo_path):
            return scan_commit_range(
                client=client,
                cache=cache,
                commit_list=get_list_commit_SHA("--all"),
                output_handler=output_handler,
                exclusion_regexes=set(),
                matches_ignore=config.secret.ignored_matches,
                scan_context=scan_context,
                ignored_detectors=config.secret.ignored_detectors,
            )
    except Exception as error:
        return handle_exception(error, config.verbose)


def scan_commit(
    commit: Commit,
    client: GGClient,
    cache: Cache,
    matches_ignore: Iterable[IgnoredMatch],
    scan_context: ScanContext,
    ignored_detectors: Optional[Set[str]] = None,
) -> ScanCollection:  # pragma: no cover
    try:
        results = commit.scan(
            client=client,
            cache=cache,
            matches_ignore=matches_ignore,
            scan_context=scan_context,
            ignored_detectors=ignored_detectors,
            scan_threads=SCAN_THREADS,
        )
    except Exception as exc:
        results = Results.from_exception(exc)

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
    exclusion_regexes: Set[re.Pattern],
    matches_ignore: Iterable[IgnoredMatch],
    scan_context: ScanContext,
    ignored_detectors: Optional[Set[str]] = None,
) -> int:  # pragma: no cover
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_list: List of commits sha to scan
    :param verbose: Display successful scan's message
    """

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        future_to_process = [
            executor.submit(
                scan_commit,
                Commit(sha, exclusion_regexes),
                client,
                cache,
                matches_ignore,
                scan_context,
                ignored_detectors,
            )
            for sha in commit_list
        ]

        scans: List[ScanCollection] = []
        with click.progressbar(
            iterable=concurrent.futures.as_completed(future_to_process),
            length=len(future_to_process),
            label=format_text("Scanning Commits", STYLE["progress"]),
            file=sys.stderr,
        ) as completed_futures:
            for future in completed_futures:
                scan_collection = future.result()
                if scan_collection.results and scan_collection.results.errors:
                    for error in scan_collection.results.errors:
                        # Prefix with `\n` since we are in the middle of a progress bar
                        display_error(f"\n{error.description}")
                scans.append(scan_collection)

        return_code = output_handler.process_scan(
            ScanCollection(id=scan_context.command_id, type="commit-range", scans=scans)
        )
    return return_code
