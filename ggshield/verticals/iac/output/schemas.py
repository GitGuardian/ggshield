from marshmallow import fields
from pygitguardian.iac_models import (
    IaCDiffScanResultSchema,
    IaCFileResultSchema,
    IaCScanResultSchema,
    IaCVulnerabilitySchema,
)
from pygitguardian.models import BaseSchema, FromDictMixin


class IaCJSONVulnerabilitySchema(IaCVulnerabilitySchema):
    class Meta:
        exclude = ("url", "status", "ignored_until", "ignore_reason", "ignore_comment")


class IaCJSONFileResultSchema(IaCFileResultSchema):
    incidents = fields.List(fields.Nested(IaCJSONVulnerabilitySchema))
    total_incidents = fields.Integer(dump_default=0)


class IaCJSONScanResultSchema(IaCScanResultSchema):
    entities_with_incidents = fields.List(fields.Nested(IaCJSONFileResultSchema))
    total_incidents = fields.Integer(dump_default=0)

    class Meta:
        exclude = ("source_found",)


class IaCJSONScanDiffEntitiesSchema(BaseSchema, FromDictMixin):
    unchanged = fields.List(fields.Nested(IaCJSONFileResultSchema))
    new = fields.List(fields.Nested(IaCJSONFileResultSchema))
    deleted = fields.List(fields.Nested(IaCJSONFileResultSchema))


class IaCJSONScanDiffResultSchema(IaCDiffScanResultSchema):
    entities_with_incidents = fields.Nested(IaCJSONScanDiffEntitiesSchema)

    class Meta:
        exclude = ("source_found",)
