from pathlib import Path
from typing import Callable, Iterable, Optional, Pattern, Sequence, Set

from ggshield.utils.git_shell import git
from ggshield.utils.itertools import batched
from ggshield.utils.os import getenv_int

from .commit_information import CommitInformation
from .commit_utils import (
    DIFF_EMPTY_COMMIT_INFO_BLOCK,
    MAX_FILES_PER_GIT_COMMAND,
    PATCH_COMMON_ARGS,
    PATCH_PREFIX,
    STAGED_PREFIX,
    CommitScannable,
    get_diff_files,
    get_file_sha_in_ref,
    get_file_sha_stage,
    parse_patch,
)
from .scannable import Scannable


# get files in commit by batch of _MAX_DOCS_PER_COMMIT
_MAX_DOCS_PER_COMMIT = getenv_int("GG_MAX_DOCS_PER_COMMIT", 20)

# Internal: type for a function to produce scannables from a commit
PatchParserFunction = Callable[["Commit"], Iterable[Scannable]]


class Commit:
    """
    Commit represents a commit which is a list of commit files.
    """

    def __init__(
        self,
        sha: Optional[str],
        patch_parser: PatchParserFunction,
        info: CommitInformation,
    ):
        """
        Internal constructor. Used by the `from_*` static methods and by some tests.
        Real code should use the `from_*` methods.
        """
        self.sha = sha
        self._patch_parser = patch_parser
        self.info = info

    @property
    def urls(self) -> Sequence[str]:
        return [CommitScannable.create_url(self.sha, x) for x in self.info.paths]

    @staticmethod
    def from_sha(
        sha: str,
        exclusion_regexes: Optional[Set[Pattern[str]]] = None,
        cwd: Optional[Path] = None,
    ) -> "Commit":
        info = CommitInformation.from_sha(sha, cwd=cwd)

        def parser(commit: "Commit") -> Iterable[Scannable]:
            for paths in batched(commit.info.paths, _MAX_DOCS_PER_COMMIT):
                cmd = ["show", sha, *PATCH_COMMON_ARGS, "--"]

                # Append paths to the command-line. If the file has been renamed, append
                # both old and new paths. If we only append the new path then `git
                # show` returns the new path as an added file.
                for path in paths:
                    if old_path := commit.info.renames.get(path):
                        cmd.append(str(old_path))
                    cmd.append(str(path))

                patch = git(cmd, cwd=cwd)
                yield from parse_patch(sha, patch, exclusion_regexes)

        return Commit(sha, parser, info)

    @staticmethod
    def from_merge(
        exclusion_regexes: Optional[Set[Pattern[str]]] = None,
        merge_branch: str = "MERGE_HEAD",
        cwd: Optional[Path] = None,
    ) -> "Commit":

        diff_files = get_diff_files(cwd=cwd)

        shas_in_merge_branch = dict(
            get_file_sha_in_ref(merge_branch, diff_files, cwd=cwd)
        )
        shas_in_head = dict(get_file_sha_in_ref("HEAD", diff_files, cwd=cwd))

        files_to_scan = set()
        for path, sha in get_file_sha_stage(diff_files, cwd=cwd):
            # The file is either new or different from both HEAD and MERGE_HEAD
            if sha not in {shas_in_head.get(path), shas_in_merge_branch.get(path)}:
                files_to_scan.add(path)

        def parser_merge(commit: "Commit") -> Iterable[Scannable]:
            for files in batched(files_to_scan, MAX_FILES_PER_GIT_COMMAND):
                patch = git(["diff", "--staged", *PATCH_COMMON_ARGS, *files], cwd=cwd)
                yield from parse_patch(
                    STAGED_PREFIX,
                    DIFF_EMPTY_COMMIT_INFO_BLOCK + patch,
                    exclusion_regexes,
                )

        info = CommitInformation.from_staged(cwd)
        return Commit(sha=None, patch_parser=parser_merge, info=info)

    @staticmethod
    def from_staged(
        exclusion_regexes: Optional[Set[Pattern[str]]] = None,
        cwd: Optional[Path] = None,
    ) -> "Commit":
        def parser(commit: "Commit") -> Iterable[Scannable]:
            patch = git(["diff", "--staged"] + PATCH_COMMON_ARGS, cwd=cwd)
            yield from parse_patch(
                STAGED_PREFIX,
                DIFF_EMPTY_COMMIT_INFO_BLOCK + patch,
                exclusion_regexes,
            )

        info = CommitInformation.from_staged(cwd)

        return Commit(sha=None, patch_parser=parser, info=info)

    @staticmethod
    def from_patch(
        patch: str,
        exclusion_regexes: Optional[Set[Pattern[str]]] = None,
        sha: str = PATCH_PREFIX,
    ) -> "Commit":
        """This one is for tests"""
        info = CommitInformation.from_patch_header(patch)

        def parser(commit: "Commit") -> Iterable[Scannable]:
            yield from parse_patch(sha, patch, exclusion_regexes)

        return Commit(sha=None, patch_parser=parser, info=info)

    def get_files(self) -> Iterable[Scannable]:
        """
        Parse the patch into files and extract the changes for each one of them.
        """
        yield from self._patch_parser(self)

    def __repr__(self) -> str:
        return f"<Commit sha={self.sha}>"
