import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Pattern, Set, Tuple

from ggshield.utils.files import is_path_excluded
from ggshield.utils.git_shell import Filemode, git
from ggshield.utils.itertools import batched

from .scannable import Scannable


# Used instead of the SHA in commit URLs for staged changes
STAGED_PREFIX = "staged"

# Used instead of the SHA in commit URLs for commit files created from a patch
PATCH_PREFIX = "patch"

# Command line arguments passed to `git show` and `git diff` to get parsable headers
HEADER_COMMON_ARGS = [
    "--raw",  # shows a header with the files touched by the commit
    "-z",  # separate file names in the raw header with \0
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

# Match the path in a "---a/file_path" or a "+++ b/file_path".
# Note that for some reason, git sometimes append an \t at the end (happens with the
# "I'm unusual!" file in the test suite). We ignore it.
OLD_NAME_RX = re.compile(r"^--- a/(.*?)\t?$", flags=re.MULTILINE)
NEW_NAME_RX = re.compile(r"^\+\+\+ b/(.*?)\t?$", flags=re.MULTILINE)

MULTI_PARENT_HUNK_HEADER_RX = re.compile(
    r"^(?P<at>@@+) (?P<from>-\d+(?:,\d+)?) .* (?P<to>\+\d+(?:,\d+)?) @@+(?P<trailing_content>.+)?"
)

MAX_FILES_PER_GIT_COMMAND = 100


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
    sha: Optional[str], patch: str, exclusion_regexes: Optional[Set[Pattern[str]]]
) -> Iterable[Scannable]:
    """
    Parse a patch generated with `git show` or `git diff` using PATCH_COMMON_ARGS.
    Returns a list of Scannable.

    A patch looks like this:

    ```
    commit $SHA
    Author: $NAME <$EMAIL>
    Date:   $DATE

        $SUBJECT

        $BODY1
        $BODY2
        ...

    $AFFECTED_FILE_LINE\0$DIFF1
    $DIFF2
    ...
    ```

    For a non-merge commit, $DIFFn looks like this:

    ```
    diff --git $A_NAME $B_NAME
    $META_INFO
    $META_INFO
    ...
    --- $A_NAME
    +++ $A_NAME
    @@ $FROM $TO @@
    $ACTUAL_CHANGES
    @@ $FROM $TO @@
    $MORE_CHANGES
    ```

    $A_NAME and $B_NAME may be /dev/null in case of creation or removal. When they are
    not, they start with "a/" and "b/" respectively.

    For a 2-parent merge commit with resolved conflicts, $DIFFn looks like this:

    ```
    diff --cc $NAME
    $META_INFO
    $META_INFO
    ...
    --- $A_NAME
    +++ $B_NAME
    @@@ $FROM1 $FROM2 $TO @@@
    $ACTUAL_CHANGES
    ```

    Note that:
    - The diff line only contains one name, without any "a/" or "b/" prefixes.
    - The hunk starts with 3 "@" instead of 2. For a commit with N parents, there are
      actually N+1 "@" characters.
    """
    if exclusion_regexes is None:
        exclusion_regexes = set()

    tokens = patch.split("\0diff ", 1)
    if len(tokens) == 1:
        # No diff, we are done
        return
    header_str, rest = tokens

    try:
        header = PatchHeader.from_string(header_str)

        diffs = re.split(r"^diff ", rest, flags=re.MULTILINE)
        for diff in diffs:
            # Split diff into header and content
            try:
                # + 1 because we match the "\n" in "\n@@"
                content_start = diff.index("\n@@") + 1
            except ValueError:
                # No content
                continue
            diff_header = diff[:content_start]
            content = diff[content_start:]

            # Find diff path in diff header
            match = NEW_NAME_RX.search(diff_header)
            if not match:
                # Must have been deleted. find the old path in this case
                match = OLD_NAME_RX.search(diff_header)
                if not match:
                    raise PatchParseError(
                        f"Could not find old path in {repr(diff_header)}"
                    )
            path = Path(match.group(1))
            if is_path_excluded(path, exclusion_regexes):
                continue

            file_info = next(x for x in header.files if x.path == path)

            if content.startswith("@@@"):
                content = convert_multi_parent_diff(content)

            yield CommitScannable(sha, file_info.path, content, filemode=file_info.mode)
    except Exception as exc:
        if sha:
            msg = f"Could not parse patch (sha: {sha}): {exc}"
        else:
            msg = f"Could not parse patch: {exc}"
        raise PatchParseError(msg)


def convert_multi_parent_diff(content: str) -> str:
    """
    ggshield output handlers currently do not work with multi-parent diffs, so convert
    them into single-parent diffs
    """
    lines = content.splitlines()

    # Process header
    hunk_header, parent_count = process_multi_parent_hunk_header(lines.pop(0))
    out_lines = [hunk_header]

    # Process content
    for line in lines:
        columns = line[:parent_count]
        text = line[parent_count:]
        if columns.startswith("-"):
            # Removed from first parent, keep it
            text = f"-{text}"
        elif columns.startswith("+"):
            # Added by first parent, keep it
            text = f"+{text}"
        elif "+" in columns:
            # Added by another parent, keep it but consider it unchanged
            text = f" {text}"
        elif "-" in columns:
            # Removed from another parent, skip it
            continue
        else:
            # Unchanged
            text = f" {text}"
        out_lines.append(text)

    return "\n".join(out_lines)


def process_multi_parent_hunk_header(header: str) -> Tuple[str, int]:
    match = MULTI_PARENT_HUNK_HEADER_RX.match(header)
    if not match:
        raise PatchParseError(  # pragma: no cover
            f"Failed to parse multi-parent hunk header '{header}'"
        )

    from_ = match.group("from")
    to = match.group("to")
    new_hunk_header = f"@@ {from_} {to} @@"
    if match.group("trailing_content"):
        new_hunk_header += f"{match.group('trailing_content')}"

    # Parent count is the number of '@' at the beginning of the header, minus 1
    parent_count = len(match.group("at")) - 1

    return new_hunk_header, parent_count


def get_file_sha_in_ref(
    ref: str,
    files: List[str],
    cwd: Optional[Path] = None,
) -> Iterable[Tuple[str, str]]:
    """
    Helper function to get the shas of files in the git reference.
    """
    for files in batched(files, MAX_FILES_PER_GIT_COMMAND):
        output = git(["ls-tree", "-z", ref] + files, cwd=cwd)
        for line in output.split("\0")[:-1]:
            _, _, sha, path = line.split(maxsplit=3)
            yield (path, sha)


def get_file_sha_stage(
    files: List[str], cwd: Optional[Path] = None
) -> Iterable[Tuple[str, str]]:
    """
    Helper function to get the shas currently staged of files.
    """
    for files in batched(files, MAX_FILES_PER_GIT_COMMAND):
        output = git(["ls-files", "--stage", "-z"] + files, cwd=cwd)
        for line in output.split("\0")[:-1]:
            _, sha, _, path = line.split(maxsplit=3)
            yield (path, sha)


def get_diff_files(cwd: Optional[Path] = None) -> List[str]:
    """
    Helper function to get the files modified and staged.
    """
    output = git(["diff", "--name-only", "--staged", "-z"], cwd=cwd)
    return output.split("\0")[:-1]  # remove the trailing \0
