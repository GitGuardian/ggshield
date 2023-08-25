from typing import List, NamedTuple

from pygitguardian.models import Match

from ggshield.core.lines import Line


class MatchIndices(NamedTuple):
    line_index_start: int
    line_index_end: int
    index_start: int
    index_end: int


def find_match_indices(match: Match, lines: List[Line], is_patch: bool) -> MatchIndices:
    """Utility function.

    Returns a MatchIndices instance where
     - line_index_{start,end} are the indices in the lines of the line objects
       containing the start and end of the match
     - index_{start,end} are the indices of the match in the line_{start,end} objects

    :param match: a Match where index_{start,end} are not None
    :param lines: List of content lines with indices (post_index and pre_index)
    :param is_patch: True if is patch from git, False if file

    :return: MatchIndices
    """
    index = 0
    line_index = 0
    len_line = len(lines[line_index].content) + 1 + int(is_patch)
    # Update line_index until we find the secret start
    assert match.index_start is not None
    while match.index_start >= index + len_line:
        index += len_line
        line_index += 1
        len_line = len(lines[line_index].content) + 1 + int(is_patch)

    line_index_start = line_index
    index_start = match.index_start - index - int(is_patch)

    # Update line_index until we find the secret end
    assert match.index_end is not None
    while match.index_end > index + len_line:
        index += len_line
        line_index += 1
        len_line = len(lines[line_index].content) + 1 + int(is_patch)

    line_index_end = line_index
    index_end = match.index_end - index - int(is_patch) + 1
    return MatchIndices(
        line_index_start,
        line_index_end,
        index_start,
        index_end,
    )
