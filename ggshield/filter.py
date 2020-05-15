import hashlib
import operator
import os
from pathlib import Path
from typing import Iterable, Set

from .git_shell import is_git_dir, shell
from .pygitguardian import PolicyBreak, ScanResult


def remove_ignored_from_result(scan_result: ScanResult, matches_ignore: Iterable[str]):
    """
    remove_ignored removes policy breaks from a Scan Result based on a sha
    made from its matches.

    :param scan_result: ScanResult to filter
    :param matches_ignore: match SHAS to filter out
    """

    scan_result.policy_breaks = [
        policy_break
        for policy_break in scan_result.policy_breaks
        if get_ignore_sha(policy_break) not in matches_ignore
    ]
    scan_result.policy_break_count = len(scan_result.policy_breaks)


def get_ignore_sha(policy_break: PolicyBreak):
    hashable = "".join(
        [
            f"{match.match},{match.match_type}"
            for match in sorted(
                policy_break.matches, key=operator.attrgetter("match_type")
            )
        ]
    )

    return hashlib.sha256(hashable.encode("UTF-8")).hexdigest()


def path_filter_set(top_dir: Path, paths_ignore: Iterable[str]) -> Set[str]:
    """
    filter_set creates a set of paths of the ignored
    entries from 3 sources:
    .gitguardian.yaml
    files in .git
    files ignore in .gitignore
    """
    filters = set()
    for ignored in paths_ignore:
        filters.update({str(target) for target in top_dir.glob(ignored)})

    if is_git_dir():
        filters.update({str(target) for target in top_dir.glob(r".git/**/*")})
        filters.update(
            {
                os.path.join(top_dir, filename)
                for filename in shell(
                    ["git", "ls-files", "-o", "-i", "--exclude-standard"]
                )
            }
        )
    return filters
