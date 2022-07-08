import hashlib
import math
import operator
import re
from collections import OrderedDict
from typing import Dict, Iterable, List, Optional, Set

import click
from pygitguardian.models import Match, PolicyBreak, ScanResult

from ggshield.core.types import IgnoredMatch


REGEX_MATCH_HIDE = re.compile(r"[^+\-\s]")
REGEX_SPECIAL_CHARS = set(".^$+*?{}()[]\\|")
INVALID_PATTERNS_REGEX = re.compile(
    r"(\*\*\*)"  # the "***" sequence is not valid
    r"|(\*\*[^/])"  # a "**" sequence must be immediately followed by a "/"
    r"|([^/]\*\*)"  # a "**" sequence must be either at the start of the string or
    # immediately preceded by a "/"
)

MAXIMUM_CENSOR_LENGTH = 60


def is_ignored(
    policy_break: PolicyBreak,
    matches_ignore: Iterable[IgnoredMatch],
) -> bool:
    """
    is_ignored checks if a occurrence is ignored.
    There are 2 ways of ignoring a occurrence:
    - matching the occurrence sha
    - matching one of the match.match values

    :param policy_break: Policy Break occurrence to judge
    :param matches_ignore: Iterable of match ignores
    :return: True if ignored
    """

    matches = [match.match for match in matches_ignore]
    if policy_break.policy.lower() != "secrets detection":
        return True
    if get_ignore_sha(policy_break) in matches or any(
        match.match in matches for match in policy_break.matches
    ):
        return True
    return False


def remove_ignored_from_result(
    scan_result: ScanResult, matches_ignore: Iterable[IgnoredMatch]
) -> None:
    """
    remove_ignored removes occurrences from a Scan Result based on a sha
    made from its matches.

    :param scan_result: ScanResult to filter
    :param matches_ignore: match SHAs or plaintext matches to filter out
    """

    scan_result.policy_breaks = [
        policy_break
        for policy_break in scan_result.policy_breaks
        if not is_ignored(policy_break, matches_ignore)
    ]

    scan_result.policy_break_count = len(scan_result.policy_breaks)


def remove_results_from_ignore_detectors(
    scan_result: ScanResult,
    ignored_detectors: Optional[Set[str]] = None,
) -> None:
    if not ignored_detectors:
        return

    scan_result.policy_breaks = [
        policy_break
        for policy_break in scan_result.policy_breaks
        if policy_break.break_type not in ignored_detectors
    ]

    scan_result.policy_break_count = len(scan_result.policy_breaks)


def get_ignore_sha(policy_break: PolicyBreak) -> str:
    hashable = "".join(
        [
            f"{match.match},{match.match_type}"
            for match in sorted(
                policy_break.matches, key=operator.attrgetter("match_type")
            )
        ]
    )

    return hashlib.sha256(hashable.encode("UTF-8")).hexdigest()


def leak_dictionary_by_ignore_sha(
    policy_breaks: List[PolicyBreak],
) -> Dict[str, List[PolicyBreak]]:
    """
    leak_dictionary_by_ignore_sha sorts matches and incidents by
    first appearance in file.

    sort incidents by first appearance on file,
    file wide matches have no index
    so give it -1 so they get bumped to the top

    :return: Dictionary with line number as index and a list of
    matches that start on said line.
    """
    policy_breaks.sort(
        key=lambda x: min(  # type: ignore
            (match.index_start if match.index_start else -1 for match in x.matches)
        )
    )
    sha_dict: Dict[str, List[PolicyBreak]] = OrderedDict()
    for policy_break in policy_breaks:
        policy_break.matches.sort(key=lambda x: x.index_start if x.index_start else -1)
        ignore_sha = get_ignore_sha(policy_break)
        sha_dict.setdefault(ignore_sha, []).append(policy_break)

    return sha_dict


def translate_user_pattern(pattern: str) -> str:
    """
    Translate the user pattern into a regex. This function assumes that the given
    pattern is valid and has been normalized beforehand.
    """

    # Escape each special character
    pattern = "".join(
        f"\\{char}" if char in REGEX_SPECIAL_CHARS else char for char in pattern
    )

    # Handle start/end of pattern
    if pattern[-1] != "/":
        pattern += "$"
    if pattern[0] == "/":
        pattern = "^" + pattern[1:]
    else:
        pattern = "(^|/)" + pattern

    # Replace * and ** sequences
    pattern = re.sub(r"\\\*\\\*/", "([^/]+/)*", pattern)
    pattern = re.sub(r"\\\*", "([^/]+)", pattern)

    return pattern


def is_pattern_valid(pattern: str) -> bool:
    return bool(pattern) and not INVALID_PATTERNS_REGEX.search(pattern)


def init_exclusion_regexes(paths_ignore: Iterable[str]) -> Set[re.Pattern]:
    """
    filter_set creates a set of paths of the ignored
    entries from 3 sources:
    .gitguardian.yaml
    files in .git
    files ignore in .gitignore
    """
    res = set()
    for path in paths_ignore:
        if not is_pattern_valid(path):
            raise click.ClickException(f"{path} is not a valid exclude pattern.")
        res.add(re.compile(translate_user_pattern(path)))
    return res


def is_filepath_excluded(filepath: str, exclusion_regexes: Set[re.Pattern]) -> bool:
    return any(r.search(filepath) for r in exclusion_regexes)


def censor_match(match: Match) -> str:
    """
    censored_match censors a match value revealing only the first and last
    1/6th of the match up to a maximum of MAXIMUM_CENSOR_LENGTH.

    :return: match value censored
    """
    len_match = len(match.match)
    start_privy_len = min(math.ceil(len_match / 6), MAXIMUM_CENSOR_LENGTH)
    end_privy_len = len_match - min(math.ceil(len_match / 6), MAXIMUM_CENSOR_LENGTH)

    censored = REGEX_MATCH_HIDE.sub("*", match.match)

    return str(
        match.match[:start_privy_len]
        + censored[start_privy_len:end_privy_len]
        + match.match[end_privy_len:]
    )


def censor_content(content: str, policy_breaks: List[PolicyBreak]) -> str:
    for policy_break in policy_breaks:
        for match in policy_break.matches:
            if match.index_start is None:
                continue

            match.match = censor_match(match)

            content = "".join(
                (
                    content[: match.index_start],
                    match.match,
                    content[len(match.match) + match.index_start :],
                )
            )
    return content
