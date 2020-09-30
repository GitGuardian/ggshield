from marshmallow import fields
from marshmallow.schema import Schema
from pygitguardian.models import MatchSchema


class FlattenedPolicyBreak(Schema):
    break_type = fields.String(data_key="break_type", required=True)
    policy = fields.String(required=True)
    matches = fields.List(fields.Nested(MatchSchema), required=True)
    ignore_sha = fields.String(required=True)
    occurences = fields.Integer(required=True)


class JSONResultSchema(Schema):
    mode = fields.String(required=True)
    filename = fields.String(required=True)
    issues = fields.List(fields.Nested(FlattenedPolicyBreak), required=True)
    total_issues = fields.Integer(required=True)


class ScanCollectionSchema(Schema):
    id = fields.String()
    results = fields.List(fields.Nested(JSONResultSchema))
    scans = fields.List(fields.Nested(lambda: ScanCollectionSchema()))
