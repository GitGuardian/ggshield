import re
import asyncio
import click

from secrets_shield.utils import shell, Filemode


class Scannable:
    """ Class representing a scannable content. """

    def __init__(self, content: str):
        self.content = content
        self.result = None

    async def scan(self, client: object):
        """ Call Scanning API via the client method. """
        try:
            self.result.update({"content": self.content})
            scan = await client.scan_file(self.content)
            self.result.update({"scan": scan})
        except asyncio.TimeoutError:
            self.result.update({"error": "timeout"})
        except Exception as error:
            self.result.update({"error": str(error)})
        finally:
            return self.result


class File(Scannable):
    """ Class representing a simple file. """

    def __init__(self, content, filename):
        super().__init__(content)
        self.filename = filename

    async def scan(self, client):
        self.result = {}
        self.result = await super().scan(client)
        self.result["filename"] = self.filename
        self.result["filemode"] = Filemode.FILE
        self.result["has_leak"] = (
            self.result.get("scan", {}).get("metadata", {}).get("leak_count", 0) > 0
        )

        return self.result


class CommitFile(File):
    """ Class representing a commit file. """

    def __init__(self, content: str, filename: str, filemode: Filemode):
        super().__init__(content, filename)
        self.filemode = filemode

    async def scan(self, client):
        self.result = {}
        self.result = await super().scan(client)
        self.result["filemode"] = self.filemode

        return self.result


class Commit:
    def __init__(self, SHA: str = None):
        self.SHA = SHA
        self.patch_ = None
        self.files_ = None

    @property
    def patch(self):
        """ Get the change patch for the commit. """
        if not self.patch_:
            if self.SHA:
                self.patch_ = "\n".join(shell("git show {}".format(self.SHA)))
            else:
                self.patch_ = "\n".join(shell("git diff --cached"))

        return self.patch_

    @property
    def commit_files(self):
        if not self.files_:
            self.files_ = self.get_files()

        return self.files_

    @classmethod
    def get_filename(self, line: str) -> str:
        """
        Get the file path from the line patch

        Example: line = "a/filename.txt b/filename.txt"
        """
        return line.split(" ")[1][2:]

    @classmethod
    def get_filemode(self, line: str) -> str:
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

        else:
            raise click.ClickException("Filemode is not detected.")

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
                yield CommitFile(content, filename, filemode)

    async def scan(self, client: object):
        """ Scan the patch for all file (async) in the commit and save it in result. """
        return await asyncio.gather(*(cf.scan(client) for cf in self.commit_files))


class GitHubRepo:
    """ Class representing a GitHub repository. """

    def __init__(self, user: str, repo: str):
        self.user = user
        self.repo = repo

    def scan(client: object):
        pass
