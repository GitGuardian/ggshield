import concurrent.futures
import logging
from ast import literal_eval
from concurrent.futures import Future
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

import click
from pygitguardian import GGClient
from pygitguardian.config import MULTI_DOCUMENT_LIMIT
from pygitguardian.models import Detail, ScanResult

from ggshield.core.cache import Cache
from ggshield.core.extra_headers import get_headers
from ggshield.core.filter import (
    remove_ignored_from_result,
    remove_results_from_ignore_detectors,
)
from ggshield.core.text_utils import STYLE, display_error, format_text, pluralize
from ggshield.core.types import IgnoredMatch
from ggshield.core.utils import Filemode, ScanContext
from ggshield.iac.models import IaCScanResult
from ggshield.scan import File


logger = logging.getLogger(__name__)

# GitGuardian API does not accept paths longer than this
_API_PATH_MAX_LENGTH = 256


class Result(NamedTuple):
    """
    Return model for a scan which zips the information
    between the Scan result and its input content.
    """

    content: str  # Text content scanned
    filemode: Filemode  # Filemode (useful for commits)
    filename: str  # Filename of content scanned
    scan: ScanResult  # Result of content scan


class Error(NamedTuple):
    files: List[Tuple[str, Filemode]]
    description: str  # Description of the error


@dataclass(frozen=True)
class Results:
    """
    Return model for a scan with the results and errors of the scan

    Not a NamedTuple like the others because it causes mypy 0.961 to crash on the
    `from_exception()` method (!)

    Similar crash: https://github.com/python/mypy/issues/12629
    """

    results: List[Result]
    errors: List[Error]

    @staticmethod
    def from_exception(exc: Exception) -> "Results":
        """Create a Results representing a failure"""
        error = Error(files=[], description=str(exc))
        return Results(results=[], errors=[error])


class ScanCollection(NamedTuple):
    id: str
    type: str
    results: Optional[Results] = None
    scans: Optional[List["ScanCollection"]] = None  # type: ignore[misc]
    iac_result: Optional[IaCScanResult] = None
    optional_header: Optional[str] = None  # To be printed in Text Output
    extra_info: Optional[Dict[str, str]] = None  # To be included in JSON Output

    @property
    def scans_with_results(self) -> List["ScanCollection"]:
        if self.scans:
            return [scan for scan in self.scans if scan.results]
        return []

    @property
    def has_iac_result(self) -> bool:
        return bool(self.iac_result and self.iac_result.entities_with_incidents)

    @property
    def has_results(self) -> bool:
        return bool(self.results and self.results.results)

    def get_all_results(self) -> Iterable[Result]:
        """Returns an iterable on all results and sub-scan results"""
        if self.results:
            yield from self.results.results
        if self.scans:
            for scan in self.scans:
                yield from scan.results.results


class Scanner:
    def __init__(
        self,
        client: GGClient,
        cache: Cache,
        scan_context: ScanContext,
        ignored_matches: Optional[Iterable[IgnoredMatch]] = None,
        ignored_detectors: Optional[Set[str]] = None,
    ):
        self.client = client
        self.cache = cache
        self.ignored_matches = ignored_matches or []
        self.ignored_detectors = ignored_detectors
        self.headers = get_headers(scan_context)
        self.command_id = scan_context.command_id

    def _scan_chunk(
        self, executor: concurrent.futures.ThreadPoolExecutor, chunk: List[File]
    ) -> Future:
        """
        Sends a chunk of files to scan to the API
        """
        # `documents` is a version of `chunk` suitable for `GGClient.multi_content_scan()`
        documents = [
            {"document": x.document, "filename": x.filename[-_API_PATH_MAX_LENGTH:]}
            for x in chunk
        ]
        return executor.submit(
            self.client.multi_content_scan,
            documents,
            self.headers,
        )

    def _start_scans(
        self,
        executor: concurrent.futures.ThreadPoolExecutor,
        files: Iterable[File],
        progress_callback: Callable[..., None],
    ) -> Dict[Future, List[File]]:
        """
        Start all scans, return a tuple containing:
        - a mapping of future to the list of files it is scanning
        - a list of files which we did not send to scan because we could not decode them

        on_file
        """
        chunks_for_futures = {}
        skipped_chunk = []

        chunk: List[File] = []
        for file in files:
            if file.document:
                chunk.append(file)
                if len(chunk) == MULTI_DOCUMENT_LIMIT:
                    future = self._scan_chunk(executor, chunk)
                    progress_callback(advance=len(chunk))
                    chunks_for_futures[future] = chunk
                    chunk = []
            else:
                skipped_chunk.append(file)
        if chunk:
            future = self._scan_chunk(executor, chunk)
            progress_callback(advance=len(chunk))
            chunks_for_futures[future] = chunk
        progress_callback(advance=len(skipped_chunk))
        return chunks_for_futures

    def _collect_results(
        self,
        chunks_for_futures: Dict[Future, List[File]],
    ) -> Results:
        """
        Receive scans as they complete, report progress and collect them and return
        a Results.
        """
        self.cache.purge()

        results = []
        errors = []
        for future in concurrent.futures.as_completed(chunks_for_futures):
            chunk = chunks_for_futures[future]

            exception = future.exception()
            if exception is None:
                scan = future.result()
            else:
                scan = Detail(detail=str(exception))
                errors.append(
                    Error(
                        files=[(file.filename, file.filemode) for file in chunk],
                        description=scan.detail,
                    )
                )

            if not scan.success:
                handle_scan_chunk_error(scan, chunk)
                continue

            for file, scanned in zip(chunk, scan.scan_results):
                remove_ignored_from_result(scanned, self.ignored_matches)
                remove_results_from_ignore_detectors(scanned, self.ignored_detectors)
                if scanned.has_policy_breaks:
                    for policy_break in scanned.policy_breaks:
                        self.cache.add_found_policy_break(policy_break, file.filename)
                    results.append(
                        Result(
                            content=file.document,
                            scan=scanned,
                            filemode=file.filemode,
                            filename=file.filename,
                        )
                    )

        self.cache.save()
        return Results(results=results, errors=errors)

    def scan(
        self,
        files: Iterable[File],
        progress_callback: Callable[..., None] = lambda advance: None,
        scan_threads: int = 4,
    ) -> Results:
        logger.debug("files=%s command_id=%s", self, self.command_id)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=scan_threads, thread_name_prefix="content_scan"
        ) as executor:
            chunks_for_futures = self._start_scans(
                executor,
                files,
                progress_callback,
            )

            return self._collect_results(chunks_for_futures)


def handle_scan_chunk_error(detail: Detail, chunk: List[File]) -> None:
    # Use %s for status_code because it can be None. Logger is OK with an int being
    # passed for a %s placeholder.
    logger.error("status_code=%s detail=%s", detail.status_code, detail.detail)
    if detail.status_code == 401:
        raise click.UsageError(detail.detail)
    if detail.status_code is None:
        raise click.ClickException(f"Error scanning: {detail.detail}")

    details = None

    display_error("\nError scanning. Results may be incomplete.")
    try:
        # try to load as list of dicts to get per file details
        details = literal_eval(detail.detail)
    except Exception:
        pass

    if isinstance(details, list) and details:
        # if the details had per file details
        display_error(
            f"Add the following {pluralize('file', len(details))}"
            " to your paths-ignore:"
        )
        for i, inner_detail in enumerate(details):
            if inner_detail:
                click.echo(
                    f"- {format_text(chunk[i].filename, STYLE['filename'])}:"
                    f" {str(inner_detail)}",
                    err=True,
                )
        return
    else:
        # if the details had a request error
        filenames = ", ".join([file.filename for file in chunk])
        display_error(
            "The following chunk is affected:\n"
            f"{format_text(filenames, STYLE['filename'])}"
        )

        display_error(str(detail))
