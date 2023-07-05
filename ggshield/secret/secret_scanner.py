import concurrent.futures
import logging
import sys
from abc import ABC, abstractmethod
from ast import literal_eval
from concurrent.futures import Future
from typing import Dict, Iterable, List, Optional, Sequence, Set

import click
from pygitguardian import GGClient
from pygitguardian.models import Detail, MultiScanResult

from ggshield.core.cache import Cache
from ggshield.core.client import check_client_api_key
from ggshield.core.constants import MAX_WORKERS
from ggshield.core.errors import QuotaLimitReachedError, UnexpectedError
from ggshield.core.filter import (
    remove_ignored_from_result,
    remove_results_from_ignore_detectors,
)
from ggshield.core.text_utils import STYLE, display_error, format_text, pluralize
from ggshield.core.types import IgnoredMatch
from ggshield.scan import DecodeError, ScanContext, Scannable

from .secret_scan_collection import Error, Result, Results


# GitGuardian API does not accept paths longer than this
_API_PATH_MAX_LENGTH = 256


logger = logging.getLogger(__name__)


class SecretScannerUI(ABC):
    """
    An abstract class used by SecretScanner to notify callers about progress or events
    during a scan
    """

    @abstractmethod
    def on_scanned(self, scannables: Sequence[Scannable]) -> None:
        raise NotImplementedError

    @abstractmethod
    def on_skipped(self, scannable: Scannable, reason: str) -> None:
        """
        Called when a scannable was skipped, `reason` explains why. If `reason` is empty
        then the user should not be notified of the skipped scannable (this happens for
        example when skipping empty files)
        """
        raise NotImplementedError


class DefaultSecretScannerUI(SecretScannerUI):
    """
    Default implementation of SecretScannerUI. Does not show progress.
    """

    def on_scanned(self, scannables: Sequence[Scannable]) -> None:
        pass

    def on_skipped(self, scannable: Scannable, reason: str) -> None:
        if reason:
            print(f"Skipped {scannable.url}: {reason}", file=sys.stderr)


class SecretScanner:
    """
    A SecretScanner scans a list of Scannable, using multiple threads
    """

    def __init__(
        self,
        client: GGClient,
        cache: Cache,
        scan_context: ScanContext,
        ignored_matches: Optional[Iterable[IgnoredMatch]] = None,
        ignored_detectors: Optional[Set[str]] = None,
        check_api_key: Optional[bool] = True,
    ):
        if check_api_key:
            check_client_api_key(client)

        self.client = client
        self.cache = cache
        self.ignored_matches = ignored_matches or []
        self.ignored_detectors = ignored_detectors
        self.headers = scan_context.get_http_headers()
        self.command_id = scan_context.command_id

    def scan(
        self,
        files: Iterable[Scannable],
        scanner_ui: SecretScannerUI = DefaultSecretScannerUI(),
        scan_threads: Optional[int] = None,
    ) -> Results:
        """
        Starts the scan, using at most `scan_threads`. If `scan_threads` is not set,
        defaults to MAX_WORKERS.
        Reports progress through `scanner_ui`.
        Returns a Results instance.
        """
        if scan_threads is None:
            scan_threads = MAX_WORKERS
        logger.debug("command_id=%s scan_threads=%d", self.command_id, scan_threads)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=scan_threads, thread_name_prefix="content_scan"
        ) as executor:
            chunks_for_futures = self._start_scans(
                executor,
                files,
                scanner_ui,
            )

            return self._collect_results(scanner_ui, chunks_for_futures)

    def _scan_chunk(
        self, executor: concurrent.futures.ThreadPoolExecutor, chunk: List[Scannable]
    ) -> Future:
        """
        Sends a chunk of files to scan to the API
        """
        # `documents` is a version of `chunk` suitable for `GGClient.multi_content_scan()`
        documents = [
            {"document": x.content, "filename": x.filename[-_API_PATH_MAX_LENGTH:]}
            for x in chunk
        ]

        return executor.submit(
            self.client.multi_content_scan,
            documents,
            self.headers,
            ignore_known_secrets=True,
        )

    def _start_scans(
        self,
        executor: concurrent.futures.ThreadPoolExecutor,
        scannables: Iterable[Scannable],
        scanner_ui: SecretScannerUI,
    ) -> Dict[Future, List[Scannable]]:
        """
        Start all scans, return a tuple containing:
        - a mapping of future to the list of files it is scanning
        - a list of files which we did not send to scan because we could not decode them
        """
        chunks_for_futures = {}

        chunk: List[Scannable] = []
        maximum_chunk_size = self.client.secret_scan_preferences.maximum_document_size
        maximum_documents_per_scan = (
            self.client.secret_scan_preferences.maximum_documents_per_scan
        )
        for scannable in scannables:
            try:
                if scannable.is_longer_than(maximum_chunk_size):
                    max_size_mb = maximum_chunk_size // 1024 // 1024
                    scanner_ui.on_skipped(
                        scannable, f"content is over {max_size_mb} MB"
                    )
                    continue
                content = scannable.content
            except DecodeError:
                scanner_ui.on_skipped(scannable, "can't detect encoding")
                continue

            if content:
                chunk.append(scannable)
                if len(chunk) == maximum_documents_per_scan:
                    future = self._scan_chunk(executor, chunk)
                    chunks_for_futures[future] = chunk
                    chunk = []
            else:
                scanner_ui.on_skipped(scannable, "")
        if chunk:
            future = self._scan_chunk(executor, chunk)
            chunks_for_futures[future] = chunk
        return chunks_for_futures

    def _collect_results(
        self,
        scanner_ui: SecretScannerUI,
        chunks_for_futures: Dict[Future, List[Scannable]],
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
            scanner_ui.on_scanned(chunk)

            exception = future.exception()
            if exception is None:
                scan = future.result()
            else:
                scan = Detail(detail=str(exception))
                errors.append(
                    Error(
                        files=[(x.filename, x.filemode) for x in chunk],
                        description=scan.detail,
                    )
                )

            if not scan.success:
                handle_scan_chunk_error(scan, chunk)
                continue

            assert isinstance(scan, MultiScanResult)
            for file, scanned in zip(chunk, scan.scan_results):
                remove_ignored_from_result(scanned, self.ignored_matches)
                remove_results_from_ignore_detectors(scanned, self.ignored_detectors)
                if scanned.has_policy_breaks:
                    for policy_break in scanned.policy_breaks:
                        self.cache.add_found_policy_break(policy_break, file.filename)
                    results.append(
                        Result(
                            file=file,
                            scan=scanned,
                        )
                    )

        self.cache.save()
        return Results(results=results, errors=errors)


def handle_scan_chunk_error(detail: Detail, chunk: List[Scannable]) -> None:
    # Use %s for status_code because it can be None. Logger is OK with an int being
    # passed for a %s placeholder.
    logger.error("status_code=%s detail=%s", detail.status_code, detail.detail)
    if detail.status_code == 401:
        raise click.UsageError(detail.detail)
    if detail.status_code is None:
        raise UnexpectedError(f"Scanning failed: {detail.detail}")
    if detail.status_code == 403 and detail.detail == "Quota limit reached.":
        raise QuotaLimitReachedError()

    details = None

    display_error("\nScanning failed. Results may be incomplete.")
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
