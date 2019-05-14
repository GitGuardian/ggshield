import os
import subprocess
import re
import asyncio

from secrets_shield.client import ScanningApiClient
from typing import Dict


class Commit:
    def __init__(self, SHA: str = None) -> None:
        self.SHA = SHA
        self.patch_ = None
        self.client = ScanningApiClient(os.getenv("GG_SCANNING_API_TOKEN"))

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
    def get_filename(self, line: str) -> str:
        """
        Gets the file path from the line patch

        Example: line = "a/filename.txt b/filename.txt"
        """
        assert line.split(" ")[0][2:] == line.split(" ")[1][2:]
        return line.split(" ")[0][2:]

    @classmethod
    def get_filemode(self, line: str) -> str:
        """
        Gets the file mode from the line patch (new, modified or deleted)
        """
        if line.startswith("index"):
            return "modified file"

        return line.split(" mode ")[0]

    def get_diffs(self):
        """
        Format the diff into files and extract the patch for each one of them

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
            content = " "

            if len(lines) > 5:
                if filemode == "modified file":
                    content = "\n".join(lines[5:])
                else:
                    content = "\n".join(lines[6:])

            yield {"filename": filename, "filemode": filemode, "content": content}

    async def scan(self):
        """
        Scan the patch for all file (async) in the commit and save it in result
        """
        return await asyncio.gather(
            *(self._scan_file(diff) for diff in self.get_diffs())
        )

    async def _scan_file(self, diff: Dict):
        scan = await self.client.scan_file(diff["content"], diff["filename"])
        error = "msg" in scan or "message" in scan

        return {
            "content": diff["content"],
            "filename": diff["filename"],
            "filemode": diff["filemode"],
            "scan": scan,
            "has_leak": (not error and scan["metadata"]["leak_count"] > 0),
            "error": error,
        }
