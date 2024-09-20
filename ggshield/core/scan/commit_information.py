import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ggshield.utils.git_shell import git

from .commit_utils import DIFF_EMPTY_COMMIT_INFO_BLOCK, HEADER_COMMON_ARGS, PatchHeader


_INFO_HEADER_REGEX = re.compile(
    r"Author:\s(?P<author>.*?) <(?P<email>.*?)>\nDate:\s+(?P<date>.+)"
)


@dataclass
class CommitInformation:
    author: str
    email: str
    date: str
    paths: List[Path]
    renames: Dict[Path, Path] = field(default_factory=dict)

    @staticmethod
    def from_patch_header(header_str: str) -> "CommitInformation":
        """
        Parse a patch header generated with `git show` or `git diff` using
        HEADER_COMMON_ARGS.

        Output format looks like this:

        ```
        commit $SHA
        Author: $NAME <$EMAIL>
        Date: $DATE

             $SUBJECT

             $BODY
        $RAW_FILE_LINES
        ```

        If the commit is empty the last line is absent and the header ends with `\n`.
        """
        header = PatchHeader.from_string(header_str)
        match = _INFO_HEADER_REGEX.search(header.info)
        assert match is not None, f"Failed to extract commit info from `{header.info}`"

        if header.files:
            # Usual commit, with files in it
            paths: List[Path] = []
            renames: Dict[Path, Path] = {}
            for file_info in header.files:
                paths.append(file_info.path)
                if file_info.old_path is not None:
                    renames[file_info.path] = file_info.old_path
        else:
            # Empty commit
            paths = []
            renames = {}

        return CommitInformation(**match.groupdict(), paths=paths, renames=renames)

    @staticmethod
    def from_staged(cwd: Optional[Path] = None) -> "CommitInformation":
        output = git(["diff", "--staged"] + HEADER_COMMON_ARGS, cwd=cwd)
        if not output:
            # This happens when there are no changes
            return CommitInformation("", "", "", [])

        return CommitInformation.from_patch_header(
            DIFF_EMPTY_COMMIT_INFO_BLOCK + output
        )

    @staticmethod
    def from_sha(sha: str, cwd: Optional[Path] = None) -> "CommitInformation":
        header = git(["show", sha] + HEADER_COMMON_ARGS, cwd=cwd)
        return CommitInformation.from_patch_header(header)
