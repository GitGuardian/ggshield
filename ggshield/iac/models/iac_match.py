from typing import Any, Dict, Optional

from marshmallow import fields, post_load
from pygitguardian.models import Match, MatchSchema


class IaCMatchSchema(MatchSchema):
    filename = fields.String(required=True)

    @post_load
    def make_match(self, data: Dict[str, Any], **kwargs: Any) -> "IaCMatch":
        return IaCMatch(**data)


class IaCMatch(Match):
    SCHEMA = IaCMatchSchema()

    def __init__(
        self,
        filename: str,
        match: str,
        match_type: str,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
        index_start: Optional[int] = None,
        index_end: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            match, match_type, line_start, line_end, index_start, index_end, **kwargs
        )
        self.filename = filename

    def __repr__(self) -> str:
        return f"filename:{self.filename}, {super().__repr__()}"
