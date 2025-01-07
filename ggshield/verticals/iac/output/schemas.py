from marshmallow import fields
from pygitguardian.iac_models import (
    IaCDiffScanResultSchema,
    IaCFileResultSchema,
    IaCScanResultSchema,
    IaCVulnerabilitySchema,
)
from pygitguardian.models_utils import BaseSchema


class IaCJSONVulnerabilitySchema(IaCVulnerabilitySchema):
    class Meta(IaCVulnerabilitySchema.Meta):
        exclude = ("url", "status", "ignored_until", "ignore_reason", "ignore_comment")


class IaCJSONFileResultSchema(IaCFileResultSchema):
    incidents = fields.List(fields.Nested(IaCJSONVulnerabilitySchema))
    total_incidents = fields.Integer(dump_default=0)


class IaCJSONScanResultSchema(IaCScanResultSchema):
    entities_with_incidents = fields.List(fields.Nested(IaCJSONFileResultSchema))
    total_incidents = fields.Integer(dump_default=0)

    class Meta(IaCScanResultSchema.Meta):
        exclude = ("source_found",)


class IaCJSONScanDiffEntitiesSchema(BaseSchema):
    unchanged = fields.List(fields.Nested(IaCJSONFileResultSchema))
    new = fields.List(fields.Nested(IaCJSONFileResultSchema))
    deleted = fields.List(fields.Nested(IaCJSONFileResultSchema))


class IaCJSONScanDiffResultSchema(IaCDiffScanResultSchema):
    entities_with_incidents = fields.Nested(IaCJSONScanDiffEntitiesSchema)

    class Meta(IaCDiffScanResultSchema.Meta):
        exclude = ("source_found",)
