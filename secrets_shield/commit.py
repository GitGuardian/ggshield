import os
import subprocess
import re
import asyncio

from secrets_shield.client import ScanningApiClient


class Commit:
    def __init__(self, SHA: str = None) -> None:
        self.SHA = SHA
        self.patch_ = None
        self.result = []

    @property
    def patch(self):
        """
        Gets the change patch for the commit
        """
        if not self.patch_:
            self.patch_ = subprocess.check_output(["git", "diff", "--cached"]).decode(
                "utf-8"
            )

        return self.patch_

    @classmethod
    def get_filename(self, line: str):
        """
        Gets the file path from the line patch
        """
        assert line.split(" ")[0][2:] == line.split(" ")[1][2:]
        return line.split(" ")[0][2:]

    @classmethod
    def get_filemode(self, line: str):
        """
        Gets the file mode from the line patch (new, modified or deleted)
        """
        if line.startswith("index"):
            return "modified file"

        return line.split(" mode ")[0]

    def get_diffs(self):
        """
        Splits the patches into files and extract content for each one of them
        """
        list_diff = re.split(r"^diff --git ", self.patch, flags=re.MULTILINE)[1:]

        for diff in list_diff:
            lines = diff.split("\n")
            assert len(lines) > 5

            filename = self.get_filename(lines[0])
            filemode = self.get_filemode(lines[1])
            content = ""

            if filemode == "modified file":
                content = "\n".join(lines[5:])
            else:
                content = "\n".join(lines[6:])

            yield {"filename": filename, "filemode": filemode, "content": content}

    async def scan(self):
        """
        Scan the patch for all file (async) in the commit and save it in result
        """
        client = ScanningApiClient(os.getenv("GG_SCANNING_API_TOKEN"))
        await asyncio.gather(
            *(self._scan_file(client, diff) for diff in self.get_diffs())
        )

    async def _scan_file(self, client, diff):
        scan = await client.scan_file(diff["content"], diff["filename"])
        error = "msg" in scan or "message" in scan

        self.result.append(
            {
                "content": diff["content"],
                "filename": diff["filename"],
                "filemode": diff["filemode"],
                "scan": scan,
                "has_leak": (not error and scan["metadata"]["leak_count"] > 0),
                "error": error,
            }
        )
