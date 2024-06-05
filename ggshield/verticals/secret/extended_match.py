from typing import Any, Dict, List, Optional

from marshmallow import fields, post_dump
from pygitguardian.models import Match, MatchSchema

from ggshield.core.filter import censor_string
from ggshield.core.lines import Line, LineCategory
from ggshield.core.match_span import MatchSpan


# The number of lines to display before and after a secret in the patch
NB_CONTEXT_LINES = 3


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
        span: MatchSpan,
        lines_before_secret: List[Line],
        lines_with_secret: List[Line],
        lines_after_secret: List[Line],
        pre_line_start: Optional[int] = None,
        pre_line_end: Optional[int] = None,
        post_line_start: Optional[int] = None,
        post_line_end: Optional[int] = None,
        **kwargs: Any,
    ):
        self.span = span
        self.lines_before_secret = lines_before_secret
        self.lines_with_secret = lines_with_secret
        self.lines_after_secret = lines_after_secret
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

        start_line = lines[span.line_index_start]
        end_line = lines[span.line_index_end]
        line_index_start = start_line.pre_index or start_line.post_index
        line_index_end = end_line.pre_index or end_line.post_index
        assert line_index_start is not None and line_index_end is not None
        line_index_start += int(is_patch) - 1  # convert to 0-based
        line_index_end += int(is_patch) - 1

        lines_with_secret = lines[span.line_index_start : span.line_index_end + 1]

        match_split_lines = match.match.splitlines()
        assert len(match_split_lines) == len(lines_with_secret)
        if is_patch and len(lines_with_secret) > 1:
            # The secret is multi-line and in patch, we can have the first character to remove
            stripped_match = "\n".join(
                (
                    str_line_match[1:]
                    if index > 0 and line.category != LineCategory.DATA
                    else str_line_match
                )
                for index, (str_line_match, line) in enumerate(
                    zip(match_split_lines, lines_with_secret)
                )
            )
        else:
            stripped_match = match.match
        return cls(
            span=span,
            match=stripped_match,
            lines_before_secret=lines[
                max(
                    span.line_index_start - NB_CONTEXT_LINES + 1, 0
                ) : span.line_index_start
            ],
            lines_with_secret=lines_with_secret,
            lines_after_secret=lines[
                span.line_index_end
                + 1 : min(span.line_index_end + NB_CONTEXT_LINES, len(lines))
            ],
            match_type=match.match_type,
            index_start=span.column_index_start,
            index_end=span.column_index_end,
            line_start=line_index_start,
            line_end=line_index_end,
            pre_line_start=start_line.pre_index,
            post_line_start=start_line.post_index,
            pre_line_end=end_line.pre_index,
            post_line_end=end_line.post_index,
        )

    def censor(self) -> None:
        """
        Censor the match and all the lines containing the secret.
        Lines are modified in place, so the secret does not appear in the context of other secrets.
        """
        len_match = len(self.match)
        self.match = censor_string(self.match)  # Censor the match
        assert len(self.match) == len_match
        match_split_lines = self.match.splitlines()
        assert len(self.lines_with_secret) == len(match_split_lines)
        # Censor the lines containing the secret by replacing the secret by its censored version.
        for index_line, (line, match_split_line) in enumerate(
            zip(self.lines_with_secret, match_split_lines)
        ):
            censor_start = self.span.column_index_start if index_line == 0 else 0
            censor_end = (
                self.span.column_index_end
                if index_line == len(match_split_lines) - 1
                else len(line.content)
            )
            line.content = (  # Modify the line to censor the match
                line.content[:censor_start]
                + match_split_line
                + line.content[censor_end:]
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
