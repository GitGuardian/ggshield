import concurrent.futures
import logging
import os
import sys
from ast import literal_eval
from concurrent.futures import Future
from typing import Dict, Iterable, List, Optional, Union

from pygitguardian import GGClient
from pygitguardian.models import Detail, MultiScanResult, TokenScope

from ggshield.core import ui
from ggshield.core.cache import Cache
from ggshield.core.client import check_client_api_key
from ggshield.core.config.user_config import SecretConfig
from ggshield.core.constants import MAX_WORKERS
from ggshield.core.errors import handle_api_error
from ggshield.core.scan import DecodeError, ScanContext, Scannable
from ggshield.core.scan.scannable import NonSeekableFileError
from ggshield.core.scanner_ui.scanner_ui import ScannerUI
from ggshield.core.text_utils import pluralize

from .secret_scan_collection import Error, Result, Results


# GitGuardian API does not accept paths longer than this
_API_PATH_MAX_LENGTH = 256
_SIZE_METADATA_OVERHEAD = 10240  # 10 KB


logger = logging.getLogger(__name__)


if sys.version_info >= (3, 10):
    ScanFuture = Future[Union[Detail, MultiScanResult]]
else:
    ScanFuture = Future


class SecretScanner:
    """
    A SecretScanner scans a list of Scannable, using multiple threads
    """

    def __init__(
        self,
        client: GGClient,
        cache: Cache,
        scan_context: ScanContext,
        secret_config: SecretConfig,
        check_api_key: Optional[bool] = True,
    ):
        if check_api_key:
            scopes = get_required_token_scopes_from_config(secret_config)
            check_client_api_key(client, scopes)

        self.client = client
        self.cache = cache
        self.secret_config = secret_config
        self.headers = scan_context.get_http_headers()
        self.headers.update({"scan_options": secret_config.dump_for_monitoring()})

        self.command_id = scan_context.command_id

    def scan(
        self,
        files: Iterable[Scannable],
        scanner_ui: ScannerUI,
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
    ) -> ScanFuture:
        """
        Sends a chunk of files to scan to the API
        """
        # `documents` is a version of `chunk` suitable for `GGClient.multi_content_scan()`
        documents = [
            {"document": x.content, "filename": x.filename[-_API_PATH_MAX_LENGTH:]}
            for x in chunk
        ]

        # Use scan_and_create_incidents if source_uuid is provided, otherwise use multi_content_scan
        if self.secret_config.source_uuid:
            return executor.submit(
                self.client.scan_and_create_incidents,
                documents,
                self.secret_config.source_uuid,
                extra_headers=self.headers,
            )
        else:
            return executor.submit(
                self.client.multi_content_scan,
                documents,
                self.headers,
                all_secrets=True,
            )

    def _start_scans(
        self,
        executor: concurrent.futures.ThreadPoolExecutor,
        scannables: Iterable[Scannable],
        scanner_ui: ScannerUI,
    ) -> Dict[ScanFuture, List[Scannable]]:
        """
        Start all scans, return a tuple containing:
        - a mapping of future to the list of files it is scanning
        - a list of files which we did not send to scan because we could not decode them
        """
        chunks_for_futures = {}

        chunk: List[Scannable] = []
        max_payload_size = self.client.maximum_payload_size - _SIZE_METADATA_OVERHEAD
        utf8_encoded_chunk_size = 0
        maximum_document_size = int(
            os.getenv(
                "GG_MAX_DOC_SIZE",
                self.client.secret_scan_preferences.maximum_document_size,
            )
        )
        maximum_documents_per_scan = int(
            os.getenv(
                "GG_MAX_DOCS",
                self.client.secret_scan_preferences.maximum_documents_per_scan,
            )
        )
        logging.debug("max_doc_size=%d", maximum_document_size)
        logging.debug("max_docs=%d", maximum_documents_per_scan)
        for scannable in scannables:
            try:
                if scannable.is_longer_than(maximum_document_size):
                    scanner_ui.on_skipped(
                        scannable, f"content is over {maximum_document_size:,} bytes"
                    )
                    continue
                content = scannable.content
            except DecodeError:
                scanner_ui.on_skipped(scannable, "can't detect encoding")
                continue
            except NonSeekableFileError:
                scanner_ui.on_skipped(scannable, "file cannot be seeked")
                continue

            if content:
                if (
                    len(chunk) == maximum_documents_per_scan
                    or utf8_encoded_chunk_size + scannable.utf8_encoded_size
                    > max_payload_size
                ):
                    future = self._scan_chunk(executor, chunk)
                    chunks_for_futures[future] = chunk
                    chunk = []
                    utf8_encoded_chunk_size = 0
                chunk.append(scannable)
                utf8_encoded_chunk_size += scannable.utf8_encoded_size
            else:
                scanner_ui.on_skipped(scannable, "")
        if chunk:
            future = self._scan_chunk(executor, chunk)
            chunks_for_futures[future] = chunk
        return chunks_for_futures

    def _collect_results(
        self,
        scanner_ui: ScannerUI,
        chunks_for_futures: Dict[ScanFuture, List[Scannable]],
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
                assert isinstance(scan, Detail)
                handle_scan_chunk_error(scan, chunk)
                continue

            assert isinstance(scan, MultiScanResult)
            for file, scan_result in zip(chunk, scan.scan_results):
                result = Result.from_scan_result(file, scan_result, self.secret_config)
                for secret in result.secrets:
                    self.cache.add_found_policy_break(
                        secret.detector_display_name,
                        secret.get_ignore_sha(),
                        file.filename,
                    )
                results.append(result)

        self.cache.save()
        return Results(results=results, errors=errors)


def handle_scan_chunk_error(detail: Detail, chunk: List[Scannable]) -> None:
    handle_api_error(detail)
    details = None

    # Handle source_uuid not found error specifically
    if "Source" in detail.detail and "not found" in detail.detail:
        ui.display_error("The provided source was not found in GitGuardian.")
        return

    ui.display_error("Scanning failed. Results may be incomplete.")
    try:
        # try to load as list of dicts to get per file details
        details = literal_eval(detail.detail)
    except Exception:
        pass

    if isinstance(details, list) and details:
        # if the details had per file details
        ui.display_error(
            f"Add the following {pluralize('file', len(details))}"
            " to your ignored_paths:"
        )
        for i, inner_detail in enumerate(details):
            if inner_detail:
                ui.display_error(f"- {chunk[i].filename}: {str(inner_detail)}")
        return
    else:
        # if the details had a request error
        filenames = "\n".join(f"- {file.filename}" for file in chunk)
        ui.display_error(f"The following chunk is affected:\n{filenames}")
        ui.display_error(str(detail))


def get_required_token_scopes_from_config(
    secret_config: SecretConfig,
) -> set[TokenScope]:
    """
    Get the required token scopes based on the secret configuration.

    Args:
        secret_config: The secret configuration to analyze

    Returns:
        A set of TokenScope values required for the given configuration
    """
    scopes = {TokenScope.SCAN}
    if secret_config.with_incident_details:
        scopes.add(TokenScope.INCIDENTS_READ)
    if secret_config.source_uuid:
        scopes.add(TokenScope.SCAN_CREATE_INCIDENTS)
    return scopes
