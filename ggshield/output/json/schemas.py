from typing import Any, Dict, Optional

from marshmallow import fields, post_dump
from pygitguardian.models import BaseSchema, Match, MatchSchema

from ggshield.iac.models import IaCFileResultSchema, IaCScanResultSchema


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
        cls,
        match: Match,
        pre_line_start: Optional[int] = None,
        pre_line_end: Optional[int] = None,
        post_line_start: Optional[int] = None,
        post_line_end: Optional[int] = None,
    ) -> "ExtendedMatch":
        match_dict = match.to_dict()
        match_dict["match_type"] = match_dict["type"]
        return cls(
            pre_line_start=pre_line_start,
            pre_line_end=pre_line_end,
            post_line_start=post_line_start,
            post_line_end=post_line_end,
            **match_dict,
        )


class FlattenedPolicyBreak(BaseSchema):
    policy = fields.String(required=True)
    occurrences = fields.List(fields.Nested(ExtendedMatchSchema), required=True)
    break_type = fields.String(data_key="type", required=True)
    validity = fields.String(required=False, allow_none=True)
    ignore_sha = fields.String(required=True)
    total_occurrences = fields.Integer(required=True)


class JSONResultSchema(BaseSchema):
    mode = fields.String(required=True)
    filename = fields.String(required=True)
    incidents = fields.List(fields.Nested(FlattenedPolicyBreak), required=True)
    total_incidents = fields.Integer(required=True)
    total_occurrences = fields.Integer(required=True)


class JSONErrorSchema(BaseSchema):
    class JSONErrorFileSchema(BaseSchema):
        mode = fields.String(required=True)
        filename = fields.String(required=True)

    files = fields.List(fields.Nested(JSONErrorFileSchema))
    description = fields.String(required=True)


class JSONScanCollectionSchema(BaseSchema):
    id = fields.String()
    type = fields.String()
    results = fields.List(
        fields.Nested(JSONResultSchema), data_key="entities_with_incidents"
    )
    errors = fields.List(fields.Nested(JSONErrorSchema))
    scans = fields.List(fields.Nested(lambda: JSONScanCollectionSchema()))
    extra_info = fields.Dict(keys=fields.Str(), values=fields.Str())
    total_incidents = fields.Integer(required=True)
    total_occurrences = fields.Integer(required=True)
    secrets_engine_version = fields.String(required=False)


class IaCJSONFileResultSchema(IaCFileResultSchema):  # type: ignore
    total_incidents = fields.Integer(default=0)


class IaCJSONScanResultSchema(IaCScanResultSchema):  # type: ignore
    entities_with_incidents = fields.List(fields.Nested(IaCJSONFileResultSchema))
    total_incidents = fields.Integer(default=0)
