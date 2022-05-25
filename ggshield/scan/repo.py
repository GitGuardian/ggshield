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
from ggshield.core.constants import CPU_COUNT
from ggshield.core.git_shell import get_list_commit_SHA, is_git_dir
from ggshield.core.text_utils import STYLE, format_text
from ggshield.core.types import IgnoredMatch
from ggshield.core.utils import SupportedScanMode, handle_exception
from ggshield.output import OutputHandler
from ggshield.scan import Commit, ScanCollection


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
                matches_ignore=config.secret.ignored_matches,
                scan_id=scan_id,
                ignored_detectors=config.secret.ignored_detectors,
            )
    except Exception as error:
        return handle_exception(error, config.verbose)


def scan_commit(
    commit: Commit,
    client: GGClient,
    cache: Cache,
    verbose: bool,
    matches_ignore: Iterable[IgnoredMatch],
    ignored_detectors: Optional[Set[str]] = None,
) -> ScanCollection:  # pragma: no cover
    results = commit.scan(
        client=client,
        cache=cache,
        matches_ignore=matches_ignore,
        mode_header=SupportedScanMode.REPO.value,
        ignored_detectors=ignored_detectors,
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
    matches_ignore: Iterable[IgnoredMatch],
    scan_id: str,
    ignored_detectors: Optional[Set[str]] = None,
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
                scans.append(future.result())

        return_code = output_handler.process_scan(
            ScanCollection(id=scan_id, type="commit-range", scans=scans)
        )
    return return_code
