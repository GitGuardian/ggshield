import os
import re
from typing import Any, Dict, Iterable, List, Optional, Set

import click

from .filter import remove_ignored_from_result
from .git_shell import shell
from .pygitguardian import GGClient, ScanResult
from .utils import MAX_FILE_SIZE, Filemode


class Scannable:
    """ Class representing a scannable content. """

    def __init__(self, document: str):
        self.document = document
        self.result = None

    def scan(self, client: GGClient) -> Dict[str, Any]:
        """ Call Scanning API via the client method. """
        try:
            self.result.update({"document": self.document})
            scan = client.scan_file(self.document)
            self.result.update({"scan": scan})
        except Exception as error:
            self.result.update({"error": str(error)})
        finally:
            return self.result


class File(Scannable):
    """ Class representing a simple file. """

    def __init__(self, document: str, filename: str, filesize: Optional[int] = None):
        super().__init__(document)
        self.filename = filename
        self.filemode = Filemode.FILE
        self.filesize = filesize if filesize else len(self.document.encode("utf-8"))

    def get_scan_dict(self) -> Dict[str, str]:
        """ Return a payload compatible with the scanning API. """
        return {"filename": self.filename, "document": self.document}

    def process_result(self, scan_result: ScanResult) -> Dict[str, Any]:
        """ Format publicAPI response into leak list for display. """
        return {
            "filename": self.filename,
            "filemode": self.filemode,
            "document": self.document,
            "scan": scan_result,
            "has_leak": scan_result.has_secrets,
        }

    def scan(self, client: GGClient) -> Dict[str, Any]:
        self.result = {}
        self.result = super().scan(client)
        self.result["filename"] = self.filename
        self.result["filemode"] = self.filemode
        self.result["has_leak"] = (
            self.result.get("scan", {}).get("metadata", {}).get("leak_count", 0) > 0
        )
        return self.result


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

    # API only scans 20 files at a time maximum
    SCANNABLE_CHUNK = 20

    def __init__(self, files: List[File]):
        self._files = {entry.filename: entry for entry in files}
        self.result = []

    @property
    def files(self) -> Dict[str, File]:
        return self._files

    @property
    def scannable_list(self) -> List[Dict[str, str]]:
        return [
            {"filename": entry.filename, "document": entry.document}
            for entry in self.files.values()
        ]

    def process_result(
        self, scan_results: List[ScanResult], matches_ignore: Iterable[str],
    ) -> Iterable[Dict[str, Any]]:
        for i, input_file in enumerate(self.files.values()):
            remove_ignored_from_result(scan_results[i], matches_ignore)
            yield {
                "content": input_file.document,
                "scan": scan_results[i],
                "has_leak": scan_results[i].has_secrets,
                "filemode": input_file.filemode.mode,
                "filename": input_file.filename,
            }

    def scan(
        self, client: GGClient, matches_ignore: Iterable[str]
    ) -> List[Dict[str, Any]]:
        scannable_list = self.scannable_list
        to_process = []
        for i in range(0, len(scannable_list), 20):
            scan, status_code = client.multi_content_scan(scannable_list[i : i + 20])
            if status_code != 200:
                click.echo(str(scan))
                continue
            to_process.extend(scan)

        return list(self.process_result(to_process, matches_ignore))


class Commit(Files):
    """
    Commit represents a commit which is a list of commit files.
    """

    def __init__(
        self, sha: Optional[str] = None, filter_set: Optional[Set[str]] = set()
    ):
        self.sha = sha
        self._patch = None
        self._files = None
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

    @classmethod
    def get_filename(cls, line: str) -> str:
        """
        Get the file path from the line patch

        Example: line = "a/filename.txt b/filename.txt"
        """
        return line.split(" ")[1][2:]

    @classmethod
    def get_filemode(cls, line: str) -> str:
        """
        Get the file mode from the line patch (new, modified or deleted)

        :raise: Exception if filemode is not detected
        """
        if line.startswith("index"):
            return Filemode.MODIFY
        elif line.startswith("similarity"):
            return Filemode.RENAME
        elif line.startswith("new"):
            return Filemode.NEW
        elif line.startswith("deleted"):
            return Filemode.DELETE
        elif line.startswith("old"):
            return Filemode.PERMISSION_CHANGE
        else:
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
