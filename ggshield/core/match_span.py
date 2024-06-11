from typing import List, NamedTuple

from pygitguardian.models import Match

from ggshield.core.lines import Line


class MatchSpan(NamedTuple):
    """Represents the start and end of a match in a text.

    line_index_start and line_index_end are line numbers.
    column_index_start and column_index_end are positions within the line.

    All indices are 0-based.

    Contrary to Match, column_index_end points to the character *after* the last
    character of the match.
    """

    line_index_start: int
    line_index_end: int
    column_index_start: int
    column_index_end: int

    @staticmethod
    def from_match(match: Match, lines: List[Line]) -> "MatchSpan":
        """
        Create a MatchSpan from a Match and a list of lines.

        :param match: a Match where index_{start,end} are not None
        :param lines: List of lines with indices (post_index and pre_index)
        """
        index = 0
        line_index = 0
        len_line = len(lines[line_index].content) + 1
        # Update line_index until we find the secret start
        assert match.index_start is not None
        while match.index_start >= index + len_line:
            index += len_line
            line_index += 1
            len_line = len(lines[line_index].content) + 1

        line_index_start = line_index
        column_index_start = match.index_start - index

        # Update line_index until we find the secret end
        assert match.index_end is not None
        while match.index_end > index + len_line:
            index += len_line
            line_index += 1
            len_line = len(lines[line_index].content) + 1

        line_index_end = line_index
        column_index_end = match.index_end - index + 1
        return MatchSpan(
            line_index_start,
            line_index_end,
            column_index_start,
            column_index_end,
        )
