import concurrent.futures
import re
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Set

import click
from pygitguardian import GGClient
from pygitguardian.config import MULTI_DOCUMENT_LIMIT
from pygitguardian.models import ScanResult

from ggshield.config import CPU_COUNT, MAX_FILE_SIZE, Cache
from ggshield.filter import (
    is_filepath_excluded,
    remove_ignored_from_result,
    remove_results_from_banlisted_detectors,
)
from ggshield.git_shell import GIT_PATH, shell
from ggshield.text_utils import STYLE, format_text
from ggshield.utils import REGEX_HEADER_INFO, Filemode

from .scannable_errors import handle_scan_error


class Result(NamedTuple):
    """
    Return model for a scan which zips the information
    between the Scan result and its input content.
    """

    content: str  # Text content scanned
    filemode: Filemode  # Filemode (useful for commits)
    filename: str  # Filename of content scanned
    scan: ScanResult  # Result of content scan


class ScanCollection(NamedTuple):
    id: str
    type: str
    results: Optional[List[Result]] = None
    scans: Optional[List["ScanCollection"]] = None  # type: ignore[misc]
    optional_header: Optional[str] = None  # To be printed in Text Output
    extra_info: Optional[Dict[str, str]] = None  # To be included in JSON Output

    @property
    def scans_with_results(self) -> List["ScanCollection"]:
        if self.scans:
            return [scan for scan in self.scans if scan.results]
        return []

    def get_all_results(self) -> Iterable[Result]:
        """Returns an iterable on all results and sub-scan results"""
        if self.results:
            yield from self.results
        if self.scans:
            for scan in self.scans:
                yield from scan.results


class File:
    """Class representing a simple file."""

    def __init__(self, document: str, filename: str, filesize: Optional[int] = None):
        self.document = document
        self.filename = filename
        self.filemode = Filemode.FILE
        self.filesize = filesize if filesize else len(self.document.encode("utf-8"))

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


class CommitFile(File):
    """Class representing a commit file."""

    def __init__(
        self,
        document: str,
        filename: str,
        filemode: Filemode,
        filesize: Optional[int] = None,
    ):
        super().__init__(document, filename, filesize)
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

    def scan(
        self,
        client: GGClient,
        cache: Cache,
        matches_ignore: Iterable[str],
        all_policies: bool,
        verbose: bool,
        mode_header: str,
        banlisted_detectors: Optional[Set[str]] = None,
        on_file_chunk_scanned: Callable[
            [List[Dict[str, Any]]], None
        ] = lambda chunk: None,
    ) -> List[Result]:
        cache.purge()
        scannable_list = self.scannable_list
        results = []
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
                    {"mode": mode_header},
                ): chunk
                for chunk in chunks
            }

            for future in concurrent.futures.as_completed(future_to_scan):
                chunk = future_to_scan[future]
                on_file_chunk_scanned(chunk)

                scan = future.result()
                if not scan.success:
                    handle_scan_error(scan, chunk)
                    continue
                for index, scanned in enumerate(scan.scan_results):
                    remove_ignored_from_result(scanned, all_policies, matches_ignore)
                    remove_results_from_banlisted_detectors(
                        scanned, banlisted_detectors
                    )
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
        return results


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
    def get_filename(line: str) -> str:
        """
        Get the file path from the line patch

        Example: line = "a/filename.txt b/filename.txt"
        """
        return line.split(" ")[1][2:]

    @staticmethod
    def get_filemode(line: str) -> Filemode:
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

        raise click.ClickException(f"Filemode is not detected:{line}")

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

            filename = self.get_filename(lines[0])
            if is_filepath_excluded(filename, self.exclusion_regexes):
                continue

            filemode = self.get_filemode(lines[1])
            document = "\n".join(lines[filemode.start :])
            file_size = len(document.encode("utf-8"))
            if file_size > MAX_FILE_SIZE * 0.90:
                continue

            if document:
                yield CommitFile(document, filename, filemode, file_size)
