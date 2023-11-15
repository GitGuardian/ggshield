from marshmallow import fields
from pygitguardian.iac_models import (
    IaCDiffScanResultSchema,
    IaCFileResultSchema,
    IaCScanResultSchema,
)
from pygitguardian.models import BaseSchema, FromDictMixin


class IaCJSONFileResultSchema(IaCFileResultSchema):
    total_incidents = fields.Integer(dump_default=0)


class IaCJSONScanResultSchema(IaCScanResultSchema):
    entities_with_incidents = fields.List(fields.Nested(IaCJSONFileResultSchema))
    total_incidents = fields.Integer(dump_default=0)


class IaCJSONScanDiffEntitiesSchema(BaseSchema, FromDictMixin):
    unchanged = fields.List(fields.Nested(IaCJSONFileResultSchema))
    new = fields.List(fields.Nested(IaCJSONFileResultSchema))
    deleted = fields.List(fields.Nested(IaCJSONFileResultSchema))


class IaCJSONScanDiffResultSchema(IaCDiffScanResultSchema):
    entities_with_incidents = fields.Nested(IaCJSONScanDiffEntitiesSchema)
