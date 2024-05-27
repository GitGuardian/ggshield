from typing import Any, Dict, List, Optional

from marshmallow import fields, post_dump
from pygitguardian.models import Match, MatchSchema

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

    @classmethod
    def from_match(
        cls, match: Match, lines: List[Line], is_patch: bool
    ) -> "ExtendedMatch":
        span = MatchSpan.from_match(match, lines, is_patch)
        line_start = lines[span.line_index_start]
        line_end = lines[span.line_index_end]
        line_index_start = line_start.pre_index or line_start.post_index
        line_index_end = line_end.pre_index or line_end.post_index
        assert line_index_start is not None and line_index_end is not None
        line_index_start += int(is_patch) - 1  # convert to 0-based
        line_index_end += int(is_patch) - 1
        return cls(
            match=match.match,
            match_type=match.match_type,
            index_start=span.column_index_start,
            index_end=span.column_index_end,
            line_start=line_index_start,
            line_end=line_index_end,
            pre_line_start=line_start.pre_index,
            post_line_start=line_start.post_index,
            pre_line_end=line_end.pre_index,
            post_line_end=line_end.post_index,
        )

    def __repr__(self) -> str:
        return ", ".join(
            [
                super().__repr__(),
                f"pre_line_start:{self.pre_line_start}",
                f"pre_line_end:{self.pre_line_end}",
                f"post_line_start:{self.post_line_start}",
                f"post_line_end:{self.post_line_end}",
            ]
        )
