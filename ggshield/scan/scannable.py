import concurrent.futures
import logging
import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

import click
from pygitguardian import GGClient
from pygitguardian.config import MULTI_DOCUMENT_LIMIT
from pygitguardian.models import Detail, ScanResult

from ggshield import __version__
from ggshield.core.cache import Cache
from ggshield.core.constants import CPU_COUNT, MAX_FILE_SIZE
from ggshield.core.filter import (
    is_filepath_excluded,
    remove_ignored_from_result,
    remove_results_from_ignore_detectors,
)
from ggshield.core.git_shell import GIT_PATH, shell
from ggshield.core.text_utils import STYLE, format_text
from ggshield.core.types import IgnoredMatch
from ggshield.core.utils import REGEX_HEADER_INFO, Filemode

from ..core.extra_headers import get_extra_headers
from ..iac.models import IaCScanResult
from .scannable_errors import handle_scan_chunk_error


logger = logging.getLogger(__name__)


_MATCH_FILENAME_RX = re.compile(r"^a/(.*) b/\1$")


class PatchParseError(Exception):
    """
    Raised by Commit.get_files() if it fails to parse its patch.
    """

    pass


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


class Results(NamedTuple):
    """
    Return model for a scan with the results and errors of the scan
    """

    results: List[Result]
    errors: List[Error]


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
    def has_results(self) -> bool:
        return bool(self.results and self.results.results)

    def get_all_results(self) -> Iterable[Result]:
        """Returns an iterable on all results and sub-scan results"""
        if self.results:
            yield from self.results.results
        if self.scans:
            for scan in self.scans:
                yield from scan.results.results


class File:
    """Class representing a simple file."""

    def __init__(self, document: str, filename: str):
        self.document = document
        self.filename = filename
        self.filemode = Filemode.FILE

    def relative_to(self, root_path: Path) -> "File":
        return File(self.document, str(Path(self.filename).relative_to(root_path)))

    @staticmethod
    def from_bytes(raw_document: bytes, filename: str) -> "File":
        document = raw_document.decode(errors="replace")
        return File(document, filename)

    @property
    def scan_dict(self) -> Dict[str, Any]:
        """Return a payload compatible with the scanning API."""
        return {
            "filename": self.filename
            if len(self.filename) <= 256
            else self.filename[-255:],
            "document": self.document,
            "filemode": self.filemode,
        }

    def __repr__(self) -> str:
        return f"<File filename={self.filename} filemode={self.filemode}>"

    def has_extensions(self, extensions: Set[str]) -> bool:
        """Returns True iff the file has one of the given extensions."""
        file_extensions = Path(self.filename).suffixes
        return any(ext in extensions for ext in file_extensions)


class CommitFile(File):
    """Class representing a commit file."""

    def __init__(self, document: str, filename: str, filemode: Filemode):
        super().__init__(document, filename)
        self.filemode = filemode


class Files:
    """
    Files is a list of files. Useful for directory scanning.
    """

    def __init__(self, files: List[File]):
        self._files = {entry.filename: entry for entry in files}

    @property
    def files(self) -> Dict[str, File]:
        return self._files

    @property
    def scannable_list(self) -> List[Dict[str, Any]]:
        return [entry.scan_dict for entry in self.files.values()]

    @property
    def extra_headers(self) -> Dict[str, str]:
        # get_current_context returns None if outside a click command.
        # It happens in the tests and if gg-shield is used as a library.
        context = click.get_current_context(silent=True)
        extra_headers = get_extra_headers(context)

        command_path = context.command_path if context is not None else "external"

        return {
            "GGShield-Version": __version__,
            "GGShield-Command-Path": command_path,
            **extra_headers,
        }

    def __repr__(self) -> str:
        files = list(self.files.values())
        return f"<Files files={files}>"

    def apply_filter(self, filter_func: Callable[[File], bool]) -> "Files":
        return Files([file for file in self.files.values() if filter_func(file)])

    def relative_to(self, root_path: Path) -> "Files":
        return Files([file.relative_to(root_path) for file in self.files.values()])

    def scan(
        self,
        client: GGClient,
        cache: Cache,
        matches_ignore: Iterable[IgnoredMatch],
        mode_header: str,
        ignored_detectors: Optional[Set[str]] = None,
        on_file_chunk_scanned: Callable[
            [List[Dict[str, Any]]], None
        ] = lambda chunk: None,
    ) -> Results:
        logger.debug("self=%s", self)
        cache.purge()
        scannable_list = self.scannable_list
        results = []
        errors = []
        chunks = []
        for i in range(0, len(scannable_list), MULTI_DOCUMENT_LIMIT):
            chunks.append(scannable_list[i : i + MULTI_DOCUMENT_LIMIT])

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(CPU_COUNT, 4), thread_name_prefix="content_scan"
        ) as executor:
            future_to_scan = {
                executor.submit(
                    client.multi_content_scan,
                    chunk,
                    {"mode": mode_header, **self.extra_headers},
                ): chunk
                for chunk in chunks
            }

            for future in concurrent.futures.as_completed(future_to_scan):
                chunk = future_to_scan[future]
                on_file_chunk_scanned(chunk)

                exception = future.exception()
                if exception is None:
                    scan = future.result()
                else:
                    scan = Detail(detail=str(exception))
                    errors.append(
                        Error(
                            files=[
                                (file["filename"], file["filemode"]) for file in chunk
                            ],
                            description=scan.detail,
                        )
                    )

                if not scan.success:
                    handle_scan_chunk_error(scan, chunk)
                    continue

                for index, scanned in enumerate(scan.scan_results):
                    remove_ignored_from_result(scanned, matches_ignore)
                    remove_results_from_ignore_detectors(scanned, ignored_detectors)
                    if scanned.has_policy_breaks:
                        for policy_break in scanned.policy_breaks:
                            cache.add_found_policy_break(
                                policy_break, chunk[index]["filename"]
                            )
                        results.append(
                            Result(
                                content=chunk[index]["document"],
                                scan=scanned,
                                filemode=chunk[index]["filemode"],
                                filename=chunk[index]["filename"],
                            )
                        )
        cache.save()
        return Results(results=results, errors=errors)


class CommitInformation(NamedTuple):
    author: str
    email: str
    date: str


class Commit(Files):
    """
    Commit represents a commit which is a list of commit files.
    """

    def __init__(
        self, sha: Optional[str] = None, exclusion_regexes: Set[re.Pattern] = set()
    ):
        self.sha = sha
        self._patch: Optional[str] = None
        self._files = {}
        self.exclusion_regexes = exclusion_regexes
        self._info: Optional[CommitInformation] = None

    @property
    def info(self) -> CommitInformation:
        if self._info is None:
            m = REGEX_HEADER_INFO.search(self.patch)

            if m is None:
                self._info = CommitInformation("unknown", "", "")
            else:
                self._info = CommitInformation(**m.groupdict())

        return self._info

    @property
    def optional_header(self) -> str:
        """Return the formatted patch."""
        return (
            format_text(f"\ncommit {self.sha}\n", STYLE["commit_info"])
            + f"Author: {self.info.author} <{self.info.email}>\n"
            + f"Date: {self.info.date}\n"
        )

    @property
    def patch(self) -> str:
        """Get the change patch for the commit."""
        if self._patch is None:
            if self.sha:
                self._patch = shell([GIT_PATH, "show", self.sha])
            else:
                self._patch = shell([GIT_PATH, "diff", "--cached"])

        return self._patch

    @property
    def files(self) -> Dict[str, File]:
        if not self._files:
            self._files = {entry.filename: entry for entry in list(self.get_files())}

        return self._files

    @staticmethod
    def _get_filemode(line: str) -> Filemode:
        """
        Get the file mode from the line patch (new, modified or deleted)

        :raise: Exception if filemode is not detected
        """
        if line.startswith("index"):
            return Filemode.MODIFY
        if line.startswith("similarity"):
            return Filemode.RENAME
        if line.startswith("new"):
            return Filemode.NEW
        if line.startswith("deleted"):
            return Filemode.DELETE
        if line.startswith("old"):
            return Filemode.PERMISSION_CHANGE

        raise PatchParseError("Filemode is not detected")

    @staticmethod
    def _parse_diff_header_lines(lines: List[str]) -> Tuple[str, Filemode]:
        """
        Parses the part of the patch after a "diff --git " string to extract the
        filename and filemode.
        """

        # This code is tricky because the first line of a diff looks like this:
        #
        #     diff --git a/path/to/filename b/path/to/filename
        #
        # But spaces are not escaped, so if a filename contains a space the line looks
        # like this:
        #
        #     diff --git a/path/to/file name b/path/to/file name
        #
        # For all cases but RENAMEs, the old and the new file are the same. We take
        # advantage of this in the _MATCH_FILENAME_RX regular expression.
        #
        # For RENAMEs we look at the next lines. A rename header looks like this:
        #
        #     diff --git a/old_name b/new_name
        #     similarity index 90%
        #     rename from old_name
        #     rename to new_name
        #
        # We look for the "rename to " and get the new file name from it.
        #
        # Note: we can't use the "--- old", "+++ new" header lines because
        # PERMISSION_CHANGE and RENAME without changes do not have these lines.
        filemode = Commit._get_filemode(lines[1])
        if filemode == Filemode.RENAME:
            prefix = "rename to "
            for line in lines[2:]:
                if line.startswith(prefix):
                    filename = line[len(prefix) :]
                    break
            else:
                raise PatchParseError("Could not extract filename, no rename prefix")
        else:
            match = _MATCH_FILENAME_RX.match(lines[0])
            if not match:
                raise PatchParseError("Could not extract filename")
            filename = match.group(1)
        return filename, filemode

    def get_files(self) -> Iterable[CommitFile]:
        """
        Format the diff into files and extract the patch for each one of them.

        Example :
            diff --git a/test.txt b/test.txt\n
            new file mode 100644\n
            index 0000000..b80e3df\n
            --- /dev/null\n
            +++ b/test\n
            @@ -0,0 +1,28 @@\n
            +this is a test patch\n
        """
        list_diff = re.split(r"^diff --git ", self.patch, flags=re.MULTILINE)[1:]

        for diff in list_diff:
            lines = diff.split("\n")

            try:
                filename, filemode = self._parse_diff_header_lines(lines)
            except PatchParseError as e:
                if self.sha:
                    raise click.ClickException(f"Error parsing commit {self.sha}: {e}")
                else:
                    raise click.ClickException(f"Error parsing diff: {e}")

            if is_filepath_excluded(filename, self.exclusion_regexes):
                continue
            document = "\n".join(lines[filemode.start :])
            file_size = len(document.encode("utf-8"))
            if file_size > MAX_FILE_SIZE * 0.90:
                continue

            if document:
                yield CommitFile(document, filename, filemode)

    def __repr__(self) -> str:
        files = list(self.files.values())
        return f"<Commit sha={self.sha} files={files}>"
