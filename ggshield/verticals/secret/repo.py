import itertools
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Iterable, Iterator, List, Optional, Set

from click import UsageError
from pygitguardian import GGClient

from ggshield.core.cache import Cache
from ggshield.core.client import check_client_api_key
from ggshield.core.config import Config
from ggshield.core.constants import MAX_WORKERS
from ggshield.core.errors import ExitCode, QuotaLimitReachedError, handle_exception
from ggshield.core.scan import Commit, ScanContext
from ggshield.core.types import IgnoredMatch
from ggshield.core.ui.ggshield_ui import GGShieldUI
from ggshield.utils.git_shell import get_list_commit_SHA, is_git_dir
from ggshield.utils.os import cd

from .output import SecretOutputHandler
from .secret_scan_collection import Results, SecretScanCollection
from .secret_scanner import SecretScanner


# We add a maximal value to avoid silently consuming all threads on powerful machines
SCAN_THREADS = 4


def scan_repo_path(
    client: GGClient,
    cache: Cache,
    ui: GGShieldUI,
    output_handler: SecretOutputHandler,
    config: Config,
    scan_context: ScanContext,
    repo_path: Path,
) -> int:  # pragma: no cover
    try:
        if not is_git_dir(repo_path):
            raise UsageError(f"{repo_path} is not a git repository")

        with cd(repo_path):
            return scan_commit_range(
                client=client,
                cache=cache,
                ui=ui,
                commit_list=get_list_commit_SHA("--all"),
                output_handler=output_handler,
                exclusion_regexes=set(),
                matches_ignore=config.user_config.secret.ignored_matches,
                scan_context=scan_context,
                ignored_detectors=config.user_config.secret.ignored_detectors,
                verbose=config.user_config.verbose,
            )
    except Exception as error:
        return handle_exception(error, config.user_config.verbose)


def scan_commits_content(
    commits: List[Commit],
    client: GGClient,
    cache: Cache,
    ui: GGShieldUI,
    matches_ignore: Iterable[IgnoredMatch],
    scan_context: ScanContext,
    progress_callback: Callable[[int], None],
    commit_scanned_callback: Callable[[Commit], None],
    ignored_detectors: Optional[Set[str]] = None,
) -> SecretScanCollection:  # pragma: no cover
    try:
        commit_files = itertools.chain.from_iterable(c.get_files() for c in commits)

        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=scan_context,
            ignored_matches=matches_ignore,
            ignored_detectors=ignored_detectors,
            check_api_key=False,  # Key has been checked in `scan_commit_range()`
        )
        with ui.create_message_only_scanner_ui() as scanner_ui:
            results = scanner.scan(
                commit_files, scan_threads=SCAN_THREADS, scanner_ui=scanner_ui
            )
    except QuotaLimitReachedError:
        raise
    except Exception as exc:
        results = Results.from_exception(exc)
    finally:
        progress_callback(len(commits))
        for commit in commits:
            commit_scanned_callback(commit)

    result_for_urls = {result.file.url: result for result in results.results}
    scans = []
    for commit in commits:
        results_for_commit_files = [
            result_for_urls[u] for u in commit.urls if u in result_for_urls
        ]
        scans.append(
            SecretScanCollection(
                commit.sha or "unknown",
                type="commit",
                results=Results(
                    results=results_for_commit_files,
                    errors=results.errors,
                ),
                optional_header=commit.optional_header,
                extra_info={
                    "author": commit.info.author,
                    "email": commit.info.email,
                    "date": commit.info.date,
                },
            )
        )

    return SecretScanCollection(
        id=scan_context.command_id, type="commit-ranges", scans=scans
    )


def get_commits_by_batch(
    commits: Iterable[Commit],
    batch_max_size: int,
) -> Iterator[List[Commit]]:
    """
    Given a list of commit shas yield the commit files
    by biggest batches possible of length at most `batch_max_size`
    """
    current_count = 0
    batch = []
    for commit in commits:
        num_files = len(commit.urls)
        if current_count + num_files < batch_max_size:
            batch.append(commit)
            current_count += num_files
        else:
            # The first batch can remain empty if it has too many files
            if batch:
                yield batch
            current_count = num_files
            batch = [commit]
    # Send the last batch that remains
    yield batch


def scan_commit_range(
    client: GGClient,
    cache: Cache,
    ui: GGShieldUI,
    commit_list: List[str],
    output_handler: SecretOutputHandler,
    exclusion_regexes: Set[re.Pattern],
    matches_ignore: Iterable[IgnoredMatch],
    scan_context: ScanContext,
    ignored_detectors: Optional[Set[str]] = None,
    verbose: bool = False,
) -> ExitCode:
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_list: List of commits sha to scan
    :param verbose: Display successful scan's message
    """
    check_client_api_key(client)
    max_documents = client.secret_scan_preferences.maximum_documents_per_scan

    with ui.create_progress(len(commit_list)) as progress:
        commits_batch = get_commits_by_batch(
            commits=(
                Commit.from_sha(sha, exclusion_regexes=exclusion_regexes)
                for sha in commit_list
            ),
            batch_max_size=max_documents,
        )
        scans: List[SecretScanCollection] = []

        def commit_scanned_callback(commit: Commit):
            if verbose:
                progress.ui.display_info(f"Scanned {commit.sha}")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for commits in commits_batch:
                futures.append(
                    executor.submit(
                        scan_commits_content,
                        commits,
                        client,
                        cache,
                        ui,
                        matches_ignore,
                        scan_context,
                        progress.advance,
                        commit_scanned_callback,
                        ignored_detectors,
                    )
                )
                # Stop now if an exception has been raised by a future
                for future in futures:
                    exception = future.exception()
                    if exception is not None:
                        raise exception

            for future in as_completed(futures):
                scan_collection = future.result()
                for scan in scan_collection.scans_with_results:
                    if scan.results and scan.results.errors:
                        for error in scan.results.errors:
                            progress.ui.display_error(error.description)
                    scans.append(scan)

    return_code = output_handler.process_scan(
        SecretScanCollection(
            id=scan_context.command_id, type="commit-range", scans=scans
        )
    )
    return return_code
