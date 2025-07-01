from marshmallow import fields
from pygitguardian.models import SecretIncidentSchema
from pygitguardian.models_utils import BaseSchema

from ggshield.verticals.secret.extended_match import ExtendedMatchSchema


class IgnoreReasonSchema(BaseSchema):
    kind = fields.String(required=True)
    detail = fields.String()


class FlattenedPolicyBreak(BaseSchema):
    policy = fields.String(required=True)
    occurrences = fields.List(fields.Nested(ExtendedMatchSchema), required=True)
    detector = fields.String(data_key="type", required=True)
    detector_documentation = fields.String(required=False, allow_none=True)
    validity = fields.String(required=False, allow_none=True)
    ignore_sha = fields.String(required=True)
    total_occurrences = fields.Integer(required=True)
    incident_url = fields.String(required=True, dump_default="")
    incident_details = fields.Nested(SecretIncidentSchema)
    known_secret = fields.Bool(required=True, dump_default=False)
    ignore_reason = fields.Nested(IgnoreReasonSchema, dump_default=None)
    secret_vaulted = fields.Bool(required=True, dump_default=False)
    vault_type = fields.String(required=False, allow_none=True)
    vault_name = fields.String(required=False, allow_none=True)
    vault_path = fields.String(required=False, allow_none=True)
    vault_path_count = fields.Integer(required=False, allow_none=True)


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
