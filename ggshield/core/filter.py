import hashlib
import math
import operator
import re
from typing import Iterable, Pattern, Set

from click import UsageError
from pygitguardian.models import Match, PolicyBreak

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


def is_in_ignored_matches(
    policy_break: PolicyBreak,
    matches_ignore: Iterable[IgnoredMatch],
) -> bool:
    """
    is_in_ignored_matches checks if a occurrence is ignored.
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


def init_exclusion_regexes(paths_ignore: Iterable[str]) -> Set[Pattern[str]]:
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
            raise UsageError(f"{path} is not a valid exclude pattern.")
        res.add(re.compile(translate_user_pattern(path)))
    return res


def censor_string(text: str) -> str:
    """
    Censor a string (usually a secret), revealing only the first and last
    1/6th of the match up to a maximum of MAXIMUM_CENSOR_LENGTH.

    :return: the text censored
    """
    len_match = len(text)

    # Special cases for short lengths
    if len_match <= 2:
        return "*" * len_match
    if len_match == 3:
        return f"**{text[2]}"

    censor_start = min(math.ceil(len_match / 6), MAXIMUM_CENSOR_LENGTH)
    censor_end = len_match - censor_start

    censored = REGEX_MATCH_HIDE.sub("*", text)

    return text[:censor_start] + censored[censor_start:censor_end] + text[censor_end:]


def censor_match(match: Match) -> str:
    return censor_string(match.match)
