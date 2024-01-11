import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Set

from ggshield.utils.files import is_filepath_excluded
from ggshield.utils.git_shell import Filemode

from .scannable import Scannable


# Used instead of the SHA in commit URLs for staged changes
STAGED_PREFIX = "staged"

# Used instead of the SHA in commit URLs for commit files created from a patch
PATCH_PREFIX = "patch"

# Command line arguments passed to `git show` and `git diff` to get parsable headers
HEADER_COMMON_ARGS = [
    "--raw",  # shows a header with the files touched by the commit
    "-z",  # separate file names in the raw header with \0
    "-m",  # split multi-parent (aka merge) commits into several one-parent commits
]

# Command line arguments passed to `git show` and `git diff` to get parsable patches
PATCH_COMMON_ARGS = [
    *HEADER_COMMON_ARGS,
    "--patch",  # force output of the diff (--raw disables it)
]

# This block is inserted before the patch by commands generating patches from the staging
# area, where there is no commit info yet
DIFF_EMPTY_COMMIT_INFO_BLOCK = """Author:   <>\nDate:  \n:"""

_RX_HEADER_FILE_LINE_SEPARATOR = re.compile("[\n\0]:", re.MULTILINE)


class PatchParseError(Exception):
    """
    Raised by parse_patch() if it fails to parse its patch.
    """

    pass


class CommitScannable(Scannable):
    """Represents a file inside a commit. The URL of a CommitScannable looks like
    this:

        commit://<sha>/<path>

    For staged commits and commits from patches, `<sha>` is replaced with STAGED_PREFIX
    and PATCH_PREFIX respectively.
    """

    def __init__(
        self,
        sha: Optional[str],
        path: Path,
        content: str,
        filemode: Filemode = Filemode.MODIFY,
    ) -> None:
        super().__init__(filemode)
        self._sha = sha
        self._path = path
        self._content = content
        self._utf8_encoded_size = None

    def _read_content(self) -> None:
        if self._content is not None and self._utf8_encoded_size is None:
            self._utf8_encoded_size = len(self._content.encode(errors="replace"))

    @property
    def url(self) -> str:
        return CommitScannable.create_url(self._sha, self.path)

    @property
    def filename(self) -> str:
        return self.url

    @property
    def path(self) -> Path:
        return self._path

    def is_longer_than(self, max_utf8_encoded_size: int) -> bool:
        self._read_content()
        assert self._utf8_encoded_size is not None
        return self._utf8_encoded_size > max_utf8_encoded_size

    @staticmethod
    def create_url(sha: Optional[str], path: Path) -> str:
        """Creates a Commit URL based on the sha and Path. It is exposed as a static
        method so that code working with not-yet-parsed commits can return an URL for
        them."""
        prefix = sha if sha else STAGED_PREFIX
        return f"commit://{prefix}/{path.as_posix()}"


@dataclass
class PatchFileInfo:
    """
    Stores information about a file modified by a patch
    """

    # old_path is None unless filemode is RENAME or COPY
    old_path: Optional[Path]
    path: Path
    mode: Filemode

    @staticmethod
    def from_string(line: str) -> "PatchFileInfo":
        """
        Parse a file line in the raw patch header, returns a PatchFileInfo

        See https://github.com/git/git/blob/master/Documentation/diff-format.txt for
        details on the format.
        """

        prefix, path, *rest = line.rstrip("\0").split("\0")

        if rest:
            # If the line has a new path, it's a rename
            old_path = Path(path)
            new_path = Path(rest[0])
        else:
            old_path = None
            new_path = Path(path)

        # for a non-merge commit, prefix is
        # :old_perm new_perm old_sha new_sha status_and_score
        #
        # for a 2 parent commit, prefix is
        # ::old_perm1 old_perm2 new_perm old_sha1 old_sha2 new_sha status_and_score
        #
        # We can ignore most of it, because we only care about the status.
        #
        # status_and_score is one or more status letters, followed by an optional
        # numerical score. We can ignore the score, but we need to check the status
        # letters.
        status = prefix.rsplit(" ", 1)[-1].rstrip("0123456789")

        # There is one status letter per commit parent. In the case of a non-merge
        # commit the situation is simple: there is only one letter.
        # In the case of a merge commit we must look at all letters: if one parent is
        # marked as D(eleted) and the other as M(odified) then we use MODIFY as filemode
        # because the end result contains modifications. To ensure this, the order of
        # the `if` below matters.

        if "M" in status:  # modify
            mode = Filemode.MODIFY
        elif "C" in status:  # copy
            mode = Filemode.NEW
        elif "A" in status:  # add
            mode = Filemode.NEW
        elif "T" in status:  # type change
            mode = Filemode.NEW
        elif "R" in status:  # rename
            mode = Filemode.RENAME
        elif "D" in status:  # delete
            mode = Filemode.DELETE
        else:
            raise ValueError(f"Can't parse header line {line}: unknown status {status}")

        return PatchFileInfo(old_path, new_path, mode)


@dataclass
class PatchHeader:
    """
    Semi-parsed information about a patch. `info` is not parsed because some functions
    do not need the details in it.
    """

    # Meta information: commit author, date, message
    info: str

    # Files added/modified/removed by the commit
    files: List[PatchFileInfo] = field(default_factory=list)

    @staticmethod
    def from_string(header: str) -> "PatchHeader":
        # First item returned by split() contains commit info and message, skip it
        info, *lines = _RX_HEADER_FILE_LINE_SEPARATOR.split(header)
        return PatchHeader(
            info,
            [PatchFileInfo.from_string(x) for x in lines],
        )


def parse_patch(
    sha: Optional[str], patch: str, exclusion_regexes: Optional[Set[re.Pattern]]
) -> Iterable[Scannable]:
    """
    Parse a patch generated with `git show` or `git diff` using PATCH_COMMON_ARGS.

    If the patch represents a merge commit, then `patch` actually contains multiple
    commits, one per parent, because we call `git show` with the `-m` option to force it
    to generate one single-parent commit per parent. This makes later code simpler and
    ensures we see *all* the changes.
    """
    if exclusion_regexes is None:
        exclusion_regexes = set()

    for commit in patch.split("\0commit "):
        tokens = commit.split("\0diff ", 1)
        if len(tokens) == 1:
            # No diff, carry on to next commit
            continue
        header_str, rest = tokens

        try:
            header = PatchHeader.from_string(header_str)

            diffs = re.split(r"^diff ", rest, flags=re.MULTILINE)
            for file_info, diff in zip(header.files, diffs):
                if is_filepath_excluded(file_info.path, exclusion_regexes):
                    continue

                # extract document from diff: we must skip diff extended headers
                # (lines like "old mode 100644", "--- a/foo", "+++ b/foo"...)
                try:
                    end_of_headers = diff.index("\n@@")
                except ValueError:
                    # No content
                    continue
                # +1 because we searched for the '\n'
                content = diff[end_of_headers + 1 :]

                yield CommitScannable(
                    sha, file_info.path, content, filemode=file_info.mode
                )
        except Exception as exc:
            if sha:
                msg = f"Could not parse patch (sha: {sha}): {exc}"
            else:
                msg = f"Could not parse patch: {exc}"
            raise PatchParseError(msg)
