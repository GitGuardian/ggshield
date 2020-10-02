from marshmallow import fields
from marshmallow.schema import Schema
from pygitguardian.models import MatchSchema


class FlattenedPolicyBreak(Schema):
    policy = fields.String(required=True)
    occurrences = fields.List(fields.Nested(MatchSchema), required=True)
    break_type = fields.String(data_key="type", required=True)
    ignore_sha = fields.String(required=True)
    total_occurrences = fields.Integer(required=True)

    class Meta:
        ordered = True


class JSONResultSchema(Schema):
    mode = fields.String(required=True)
    filename = fields.String(required=True)
    incidents = fields.List(fields.Nested(FlattenedPolicyBreak), required=True)
    total_incidents = fields.Integer(required=True)
    total_occurrences = fields.Integer(required=True)

    class Meta:
        ordered = True


class JSONScanCollectionSchema(Schema):
    id = fields.String()
    type = fields.String()
    results = fields.List(
        fields.Nested(JSONResultSchema), data_key="entities_with_incidents"
    )
    scans = fields.List(fields.Nested(lambda: JSONScanCollectionSchema()))
    extra_info = fields.Dict(keys=fields.Str(), values=fields.Str())
    total_incidents = fields.Integer(required=True)
    total_occurrences = fields.Integer(required=True)

    class Meta:
        ordered = True
