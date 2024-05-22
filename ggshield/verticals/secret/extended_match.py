from typing import Any, Dict, List, Optional

from marshmallow import fields, post_dump
from pygitguardian.models import Match, MatchSchema

from ggshield.core.filter import censor_string
from ggshield.core.lines import Line
from ggshield.core.match_span import MatchSpan


class ExtendedMatchSchema(MatchSchema):
    pre_line_start = fields.Int(required=False, allow_none=True)
    pre_line_end = fields.Int(required=False, allow_none=True)
    post_line_start = fields.Int(required=False, allow_none=True)
    post_line_end = fields.Int(required=False, allow_none=True)

    @post_dump
    def remove_none_extra(
        self, data: Dict[str, Optional[int]], many: bool
    ) -> Dict[str, Optional[int]]:
        OPTIONAL_OUTPUT_FIELDS = (
            "pre_line_start",
            "pre_line_end",
            "post_line_start",
            "post_line_end",
        )

        return {
            key: value
            for key, value in data.items()
            if key not in OPTIONAL_OUTPUT_FIELDS or value is not None
        }


class ExtendedMatch(Match):
    """Match extended with information about pre and post commit
    line indices"""

    SCHEMA = ExtendedMatchSchema()
    context_lines: List[Line]

    def __init__(
        self,
        pre_line_start: Optional[int] = None,
        pre_line_end: Optional[int] = None,
        post_line_start: Optional[int] = None,
        post_line_end: Optional[int] = None,
        **kwargs: Any,
    ):
        self.pre_line_start = pre_line_start
        self.pre_line_end = pre_line_end
        self.post_line_start = post_line_start
        self.post_line_end = post_line_end
        super().__init__(**kwargs)

    def censor(self) -> None:
        len_match = len(self.match)
        self.match = censor_string(self.match)
        assert len(self.match) == len_match
        match_split_lines = self.match.split("\n")
        for line in self.context_lines:
            assert self.line_start is not None and self.line_end is not None
            if line.number < self.line_start or line.number > self.line_end:
                continue  # the lines does not contain this extended match
            censor_start = 0
            censor_end = len(line.content)
            if line.number == self.line_start:
                censor_start = self.index_start
            if line.number == self.line_end:
                censor_end = self.index_end
            assert censor_start is not None and censor_end is not None
            line.content = (
                line.content[:censor_start]
                + match_split_lines[line.number - self.line_start]
                + line.content[censor_end:]
            )

    @classmethod
    def from_match(
        cls, match: Match, lines: List[Line], is_patch: bool
    ) -> "ExtendedMatch":
        span = MatchSpan.from_match(match, lines, is_patch)
        line_start = lines[span.line_index_start]
        line_end = lines[span.line_index_end]
        line_index_start = line_start.number
        line_index_end = line_end.number
        assert line_index_start is not None and line_index_end is not None
        index_context_lines = range(
            max(line_index_start - NB_CONTEXT_LINES, 0),
            min(line_index_end - 1 + NB_CONTEXT_LINES, len(lines)),
        )
        stripped_match = "\n".join(
            [
                match_line[int(is_patch) if index_line > 0 else 0 :]
                for index_line, match_line in enumerate(match.match.split("\n"))
            ]
        )
        ext_match = cls(
            match=stripped_match,
            match_type=match.match_type,
            index_start=span.column_index_start,
            index_end=span.column_index_end
            - int(is_patch),  # not sure why I need this :(
            line_start=line_index_start,
            line_end=line_index_end,
            pre_line_start=line_start.pre_index,
            post_line_start=line_start.post_index,
            pre_line_end=line_end.pre_index,
            post_line_end=line_end.post_index,
        )
        ext_match.context_lines = [
            lines[line_index] for line_index in index_context_lines
        ]
        return ext_match


# The number of lines to display before and after a secret in the patch
NB_CONTEXT_LINES = 3
