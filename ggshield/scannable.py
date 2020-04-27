import re
from typing import Any, Dict, List, Set, Union

import click

from .pygitguardian import GGClient, ScanResult
from .utils import Filemode, remove_ignored, shell


class Scannable:
    """ Class representing a scannable content. """

    def __init__(self, content: str):
        self.content = content
        self.result = None

    def scan(self, client: GGClient):
        """ Call Scanning API via the client method. """
        try:
            self.result.update({"content": self.content})
            scan = client.scan_file(self.content)
            self.result.update({"scan": scan})
        except Exception as error:
            self.result.update({"error": str(error)})
        finally:
            return self.result


class File(Scannable):
    """ Class representing a simple file. """

    def __init__(self, content: str, filename: str):
        super().__init__(content)
        self.filename = filename
        self.filemode = Filemode.FILE

    def get_dict(self):
        """ Return a payload compatible with the scanning API. """
        return {"filename": self.filename, "document": self.content}

    def process_result(self, scan_result: ScanResult) -> Dict[str, Any]:
        """ Format publicAPI response into leak list for display. """
        return {
            "filename": self.filename,
            "filemode": self.filemode,
            "content": self.content,
            "scan": scan_result,
            "has_leak": scan_result.has_secrets,
        }

    def scan(self, client: GGClient):
        self.result = {}
        self.result = super().scan(client)
        self.result["filename"] = self.filename
        self.result["filemode"] = self.filemode
        self.result["has_leak"] = (
            self.result.get("scan", {}).get("metadata", {}).get("leak_count", 0) > 0
        )
        return self.result


class Files:
    def __init__(self, files: List[File]):
        self.files = {file.filename: file for file in files}
        self.result = []

    def scan(self, client: GGClient, ignored_matches: Set[str]) -> List[Dict[str, Any]]:
        for file in self.files.values():
            scan = client.content_scan(**file.get_dict())
            assert scan.success is True
            remove_ignored(scan, ignored_matches)
            self.result.append(file.process_result(scan))

        return self.result


class CommitFile(File):
    """ Class representing a commit file. """

    def __init__(self, content: str, filename: str, filemode: Filemode):
        super().__init__(content, filename)
        self.filemode = filemode

    def scan(self, client: GGClient):
        self.result = {}
        self.result = super().scan(client)
        self.result["filemode"] = self.filemode
        return self.result


class Commit:
    def __init__(self, sha: Union[str, None] = None):
        self.sha = sha
        self.patch_ = None
        self.files_ = None

    @property
    def patch(self):
        """ Get the change patch for the commit. """
        if not self.patch_:
            if self.sha:
                self.patch_ = "\n".join(shell("git show {}".format(self.sha)))
            else:
                self.patch_ = "\n".join(shell("git diff --cached"))

        return self.patch_

    @property
    def commit_files(self):
        if not self.files_:
            self.files_ = {file["filename"]: file for file in list(self.get_files())}

        return self.files_

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

    def get_files(self):
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
            filemode = self.get_filemode(lines[1])
            content = "\n".join(lines[filemode.start :])

            if content:
                yield {
                    "filename": filename,
                    "filemode": filemode.mode,
                    "content": content,
                }

    def process_result(self, scan_result: Dict):
        """ Format scanning_api response into leak list for display. """
        for file_result in scan_result["files"]:
            file = self.commit_files[file_result["filename"]]
            yield {
                "filename": file["filename"],
                "filemode": file["filemode"],
                "content": file["content"],
                "scan": file_result,
                "has_leak": len(file_result.get("secrets", [])) > 0,
            }

    def scan(self, client: GGClient, ignored_matches: Set[str]) -> Dict[str, Any]:
        """ Scan the patch for all files in the commit and save it in result. """
        result = []
        for file in self.get_files():
            commit_file = CommitFile(**file)
            scan = client.content_scan(**commit_file.get_dict())
            assert scan.success is True
            remove_ignored(scan, ignored_matches)
            result.append(commit_file.process_result(scan))

        return result
