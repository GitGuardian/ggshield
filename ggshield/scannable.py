import os
import re
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Set

import click
from pygitguardian import GGClient
from pygitguardian.config import MULTI_DOCUMENT_LIMIT
from pygitguardian.models import ScanResult

from .filter import remove_ignored_from_result
from .git_shell import shell
from .scannable_errors import handle_scan_error
from .utils import MAX_FILE_SIZE, Filemode


class Result(NamedTuple):
    """
    Return model for a scan which zips the information
    betwen the Scan result and its input content.
    """

    content: str  # Text content scanned
    filemode: Filemode  # Filemode (useful for commits)
    filename: str  # Filename of content scanned
    scan: ScanResult  # Result of content scan


class File:
    """ Class representing a simple file. """

    def __init__(self, document: str, filename: str, filesize: Optional[int] = None):
        self.document = document
        self.filename = filename
        self.filemode = Filemode.FILE
        self.filesize = filesize if filesize else len(self.document.encode("utf-8"))

    @property
    def scan_dict(self) -> Dict[str, Any]:
        """ Return a payload compatible with the scanning API. """
        return {
            "filename": self.filename
            if len(self.filename) <= 256
            else self.filename[-255:],
            "document": self.document,
            "filemode": self.filemode,
        }


class CommitFile(File):
    """ Class representing a commit file. """

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
        matches_ignore: Iterable[str],
        all_policies: bool,
        verbose: bool,
    ) -> List[Result]:
        scannable_list = self.scannable_list
        results = []
        for i in range(0, len(scannable_list), MULTI_DOCUMENT_LIMIT):
            chunk = scannable_list[i : i + MULTI_DOCUMENT_LIMIT]
            scan = client.multi_content_scan(chunk)
            if not scan.success:
                handle_scan_error(scan, chunk)
                continue
            for index, scanned in enumerate(scan.scan_results):
                remove_ignored_from_result(scanned, all_policies, matches_ignore)
                if scanned.has_policy_breaks:
                    results.append(
                        Result(
                            content=chunk[index]["document"],
                            scan=scanned,
                            filemode=chunk[index]["filemode"],
                            filename=chunk[index]["filename"],
                        )
                    )

        return results


class Commit(Files):
    """
    Commit represents a commit which is a list of commit files.
    """

    def __init__(self, sha: Optional[str] = None, filter_set: Set[str] = set()):
        self.sha = sha
        self._patch = None
        self._files = {}
        self.filter_set = filter_set

    @property
    def patch(self):
        """ Get the change patch for the commit. """
        if not self._patch:
            if self.sha:
                self._patch = "\n".join(shell(["git", "show", self.sha]))
            else:
                self._patch = "\n".join(shell(["git", "diff", "--cached"]))

        return self._patch

    @property
    def files(self):
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
        work_dir = os.getcwd()

        for diff in list_diff:
            lines = diff.split("\n")

            filename = self.get_filename(lines[0])
            if os.path.join(work_dir, filename) in self.filter_set:
                continue

            filemode = self.get_filemode(lines[1])
            document = "\n".join(lines[filemode.start :])
            file_size = len(document.encode("utf-8"))
            if file_size > MAX_FILE_SIZE:
                continue

            if document:
                yield CommitFile(document, filename, filemode, file_size)
