import re
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence, Set

from ggshield.core.text_utils import STYLE, format_text
from ggshield.utils.git_shell import git
from ggshield.utils.itertools import batched
from ggshield.utils.os import getenv_int

from .commit_information import CommitInformation
from .commit_utils import (
    PATCH_COMMON_ARGS,
    PATCH_PREFIX,
    STAGED_PREFIX,
    CommitScannable,
    parse_patch,
)
from .scannable import Scannable


# get files in commit by batch of _MAX_DOCS_PER_COMMIT
_MAX_DOCS_PER_COMMIT = getenv_int("GG_MAX_DOCS_PER_COMMIT", 20)


class PatchParseError(Exception):
    """
    Raised by Commit.get_files() if it fails to parse its patch.
    """

    pass


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
        exclusion_regexes: Optional[Set[re.Pattern]] = None,
        cwd: Optional[Path] = None,
    ) -> "Commit":
        info = CommitInformation.from_sha(sha, cwd=cwd)

        def parser(commit: "Commit") -> Iterable[Scannable]:
            for paths in batched(commit.info.paths, _MAX_DOCS_PER_COMMIT):
                patch = git(
                    ["show", sha]
                    + PATCH_COMMON_ARGS
                    + ["--"]
                    + [str(x) for x in paths],
                    cwd=cwd,
                )
                try:
                    yield from parse_patch(sha, patch, exclusion_regexes)
                except Exception as exc:
                    raise PatchParseError(f"Could not parse patch (sha: {sha}): {exc}")

        return Commit(sha, parser, info)

    @staticmethod
    def from_staged(
        exclusion_regexes: Optional[Set[re.Pattern]] = None, cwd: Optional[Path] = None
    ) -> "Commit":
        def parser(commit: "Commit") -> Iterable[Scannable]:
            patch = git(["diff", "--cached"] + PATCH_COMMON_ARGS, cwd=cwd)
            try:
                yield from parse_patch(STAGED_PREFIX, patch, exclusion_regexes)
            except Exception as exc:
                raise PatchParseError(f"Could not parse patch: {exc}")

        info = CommitInformation.from_staged(cwd)

        return Commit(sha=None, patch_parser=parser, info=info)

    @staticmethod
    def from_patch(
        patch: str,
        exclusion_regexes: Optional[Set[re.Pattern]] = None,
    ) -> "Commit":
        """This one is for tests"""
        info = CommitInformation.from_patch_header(patch)

        def parser(commit: "Commit") -> Iterable[Scannable]:
            try:
                yield from parse_patch(PATCH_PREFIX, patch, exclusion_regexes)
            except Exception as exc:
                raise PatchParseError(f"Could not parse patch: {exc}")

        return Commit(sha=None, patch_parser=parser, info=info)

    @property
    def optional_header(self) -> str:
        """Return the formatted patch."""
        return (
            format_text(f"\ncommit {self.sha}\n", STYLE["commit_info"])
            + f"Author: {self.info.author} <{self.info.email}>\n"
            + f"Date: {self.info.date}\n"
        )

    def get_files(self) -> Iterable[Scannable]:
        """
        Parse the patch into files and extract the changes for each one of them.
        """
        yield from self._patch_parser(self)

    def __repr__(self) -> str:
        return f"<Commit sha={self.sha}>"
