from marshmallow import fields
from pygitguardian.iac_models import IaCFileResultSchema, IaCScanResultSchema


class IaCJSONFileResultSchema(IaCFileResultSchema):
    total_incidents = fields.Integer(dump_default=0)


class IaCJSONScanResultSchema(IaCScanResultSchema):
    entities_with_incidents = fields.List(fields.Nested(IaCJSONFileResultSchema))
    total_incidents = fields.Integer(dump_default=0)


class IaCJSONScanDiffResultSchema(IaCFileResultSchema):
    added_vulns = fields.List(fields.Nested(IaCJSONFileResultSchema))
    persisting_vulns = fields.List(fields.Nested(IaCJSONFileResultSchema))
    removed_vulns = fields.List(fields.Nested(IaCJSONFileResultSchema))
