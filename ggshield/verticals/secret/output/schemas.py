from marshmallow import fields
from pygitguardian.models import BaseSchema, SecretIncidentSchema

from ggshield.verticals.secret.extended_match import ExtendedMatchSchema


class IgnoreReasonSchema(BaseSchema):
    kind = fields.String(required=True)
    detail = fields.String()


class FlattenedPolicyBreak(BaseSchema):
    policy = fields.String(required=True)
    occurrences = fields.List(fields.Nested(ExtendedMatchSchema), required=True)
    break_type = fields.String(data_key="type", required=True)
    validity = fields.String(required=False, allow_none=True)
    ignore_sha = fields.String(required=True)
    total_occurrences = fields.Integer(required=True)
    incident_url = fields.String(required=True, dump_default="")
    incident_details = fields.Nested(SecretIncidentSchema)
    known_secret = fields.Bool(required=True, dump_default=False)
    ignore_reason = fields.Nested(IgnoreReasonSchema)


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
